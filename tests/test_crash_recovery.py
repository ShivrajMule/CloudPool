"""
Automated Test Suite for CloudPool Crash Recovery and Orphaned Remote Object Prevention (TASK 04)
Tests persistent upload journal, lifecycle states (preparing -> uploading -> uploading_parity ->
verifying -> committing -> completed -> rolling_back -> failed), crash recovery at startup,
orphaned object prevention, retry of failed cleanup, quota reconciliation, and conservative recovery.
All tests use temporary SQLite databases and mocked cloud remotes. Never touches real cloud data.
"""

import os
import sys
import uuid
import sqlite3
import tempfile
import unittest
import subprocess
from unittest.mock import patch, MagicMock

# Ensure CloudPool_Project is in path
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from core_engine import DatabaseEngine
from network_engine import NetworkEngine


class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        """Create an isolated temporary SQLite database and network engine for each test."""
        self.rclone_patcher = patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
        self.rclone_patcher.start()

        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db_path = self.temp_db_file.name

        self.db = DatabaseEngine(db_path=self.db_path)
        self.net = NetworkEngine()
        self.net.db = self.db

        # Track mock Rclone delete calls
        self.deleted_remote_objects = []

    def tearDown(self):
        """Clean up SQLite connection and temporary database file."""
        self.rclone_patcher.stop()
        try:
            self.db.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def _create_mock_proc(self, returncode=0, stdout_bytes=b"", stderr_bytes=b""):
        """Creates a mock subprocess with specified returncode and output."""
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.returncode = returncode
        mock_proc.communicate.return_value = (stdout_bytes, stderr_bytes)
        mock_proc.poll.return_value = returncode
        mock_proc.stdin = MagicMock()
        return mock_proc

    def _record_rclone_call(self, cmd, *args, **kwargs):
        """Intercepts subprocess.Popen to monitor and record deletefile calls."""
        if isinstance(cmd, list) and len(cmd) >= 3 and cmd[1] == "deletefile":
            self.deleted_remote_objects.append(cmd[2])
            return self._create_mock_proc(returncode=0)
        return self._create_mock_proc(returncode=0)

    # --------------------------------------------------------------------------
    # 1. Crash after Journal Creation (preparing)
    # --------------------------------------------------------------------------
    def test_crash_after_journal_creation(self):
        """Crash in 'preparing' state before any chunk is uploaded. Recovery must safely clean up with 0 remote calls."""
        acc = "Remote_Prep"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_prep_001"
        file_id = str(uuid.uuid4())
        self.db.create_upload_journal_entry(
            op_id=op_id,
            file_id=file_id,
            file_name="unstarted.dat",
            total_size_bytes=1000,
            total_expected_chunks=1,
            data_chunks_count=1
        )
        # Register in virtual_files with 'uploading' status
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'unstarted.dat', 1000, datetime('now'), 'uploading')", (file_id,))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        # Operation is rolled back
        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "rolled_back")
        # 0 remote chunks existed, so 0 delete calls needed
        self.assertEqual(len(self.deleted_remote_objects), 0)
        # virtual_files record removed
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())

    # --------------------------------------------------------------------------
    # 2. Crash after First Data Chunk
    # --------------------------------------------------------------------------
    def test_crash_after_first_data_chunk(self):
        """Crash after Chunk 1 is uploaded. Startup recovery must wipe Chunk 1 from remote and reset quotas."""
        acc = "Remote_C1"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_c1_002"
        file_id = str(uuid.uuid4())
        chunk1_id = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="multi.bin",
            total_size_bytes=40000000, total_expected_chunks=2, data_chunks_count=2
        )
        self.db.update_upload_journal_status(op_id, "uploading")
        self.db.record_journal_chunk(op_id, chunk1_id, acc, 1, 20000000, is_parity=0, status="uploaded")

        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'multi.bin', 40000000, datetime('now'), 'uploading')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 20000000, 0)", (chunk1_id, file_id, acc))
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 20000000 WHERE account_name = ?", (acc,))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        # Chunk 1 was wiped from cloud remote
        expected_target = f"{acc}:CloudPool_Vault/{chunk1_id}.enc"
        self.assertIn(expected_target, self.deleted_remote_objects)

        # Quota reconciled to 0
        cur = self.db.conn.cursor()
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)

        # Journal rolled back
        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "rolled_back")

    # --------------------------------------------------------------------------
    # 3. Crash after Multiple Data Chunks
    # --------------------------------------------------------------------------
    def test_crash_after_multiple_data_chunks(self):
        """Crash after Chunk 1 (Remote_A) and Chunk 2 (Remote_B). Recovery wipes both remotes."""
        acc_a = "Remote_Multi_A"
        acc_b = "Remote_Multi_B"
        self.db.register_account(acc_a, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc_b, "GoogleDrive", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_multi_003"
        file_id = str(uuid.uuid4())
        c1 = f"{file_id[:8]}_part0001"
        c2 = f"{file_id[:8]}_part0002"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="bigfile.iso",
            total_size_bytes=60000000, total_expected_chunks=3, data_chunks_count=3
        )
        self.db.update_upload_journal_status(op_id, "uploading")
        self.db.record_journal_chunk(op_id, c1, acc_a, 1, 20000000, is_parity=0, status="uploaded")
        self.db.record_journal_chunk(op_id, c2, acc_b, 2, 20000000, is_parity=0, status="uploaded")

        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'bigfile.iso', 60000000, datetime('now'), 'uploading')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 20000000, 0)", (c1, file_id, acc_a))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 2, 20000000, 0)", (c2, file_id, acc_b))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        # Both remote objects wiped
        self.assertIn(f"{acc_a}:CloudPool_Vault/{c1}.enc", self.deleted_remote_objects)
        self.assertIn(f"{acc_b}:CloudPool_Vault/{c2}.enc", self.deleted_remote_objects)

        # Quotas reconciled
        cur = self.db.conn.cursor()
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc_a,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc_b,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)

    # --------------------------------------------------------------------------
    # 4. Crash after Parity Upload
    # --------------------------------------------------------------------------
    def test_crash_after_parity_upload(self):
        """Crash after data chunk and parity chunk uploaded. Recovery wipes both data and parity chunks."""
        acc_data = "Remote_Parity_Data"
        acc_par = "Remote_Parity_Par"
        self.db.register_account(acc_data, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc_par, "OneDrive", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_parity_004"
        file_id = str(uuid.uuid4())
        c_data = f"{file_id[:8]}_part0001"
        c_par = f"{file_id[:8]}_parity"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="secure.dat",
            total_size_bytes=1000, enable_parity=1, total_expected_chunks=2, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "uploading_parity")
        self.db.record_journal_chunk(op_id, c_data, acc_data, 1, 1000, is_parity=0, status="uploaded")
        self.db.record_journal_chunk(op_id, c_par, acc_par, 9999, 1000, is_parity=1, status="uploaded")

        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'secure.dat', 1000, datetime('now'), 'uploading')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 1000, 0)", (c_data, file_id, acc_data))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 9999, 1000, 1)", (c_par, file_id, acc_par))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        # Both data chunk AND parity chunk wiped
        self.assertIn(f"{acc_data}:CloudPool_Vault/{c_data}.enc", self.deleted_remote_objects)
        self.assertIn(f"{acc_par}:CloudPool_Vault/{c_par}.enc", self.deleted_remote_objects)

    # --------------------------------------------------------------------------
    # 5. Crash after Remote Upload Completion (verifying)
    # --------------------------------------------------------------------------
    def test_crash_after_remote_upload_completion(self):
        """Crash while in 'verifying' state. Recovery safely cleans up incomplete upload."""
        acc = "Remote_Verify"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_ver_005"
        file_id = str(uuid.uuid4())
        cid = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="verify_crash.bin",
            total_size_bytes=1000, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "verifying")
        self.db.record_journal_chunk(op_id, cid, acc, 1, 1000, is_parity=0, status="uploaded")

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        self.assertIn(f"{acc}:CloudPool_Vault/{cid}.enc", self.deleted_remote_objects)
        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "rolled_back")

    # --------------------------------------------------------------------------
    # 6. Crash after Metadata Insertion (committing with full chunks)
    # --------------------------------------------------------------------------
    def test_crash_after_metadata_insertion(self):
        """Crash in 'committing' state when all chunks and metadata are present. Recovery finalizes and commits the upload."""
        acc = "Remote_Commit"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_com_006"
        file_id = str(uuid.uuid4())
        cid = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="committed_file.zip",
            total_size_bytes=5000, enable_parity=0, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "committing")
        self.db.record_journal_chunk(op_id, cid, acc, 1, 5000, is_parity=0, status="uploaded")

        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'committed_file.zip', 5000, datetime('now'), 'uploading')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 5000, 0)", (cid, file_id, acc))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        # Recovery recognizes completed payload and finalizes it instead of deleting!
        self.assertEqual(len(self.deleted_remote_objects), 0)
        self.assertEqual(summary["jobs_committed"], 1)

        # virtual_files is completed
        cur = self.db.conn.cursor()
        cur.execute("SELECT upload_status FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertEqual(cur.fetchone()["upload_status"], "completed")

        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "completed")

    # --------------------------------------------------------------------------
    # 7. Final Commit State (completed - Never delete valid objects)
    # --------------------------------------------------------------------------
    def test_crash_after_final_commit(self):
        """A completed upload must NEVER be touched, deleted, or rolled back by recovery."""
        acc = "Remote_Finished"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_fin_007"
        file_id = str(uuid.uuid4())
        cid = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="final.pdf",
            total_size_bytes=10000, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "completed")
        self.db.record_journal_chunk(op_id, cid, acc, 1, 10000, is_parity=0, status="committed")

        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'final.pdf', 10000, datetime('now'), 'completed')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 10000, 0)", (cid, file_id, acc))

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            summary = self.db.cleanup_incomplete_uploads()

        self.assertEqual(len(self.deleted_remote_objects), 0)
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertIsNotNone(cur.fetchone())

    # --------------------------------------------------------------------------
    # 8. Remote Offline During Recovery Rollback (Record for Retry)
    # --------------------------------------------------------------------------
    def test_remote_offline_during_recovery(self):
        """When an account is offline or Rclone fails during recovery, job is kept in 'failed' state for retry."""
        acc = "Remote_Offline"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_off_008"
        file_id = str(uuid.uuid4())
        cid = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="offline.dat",
            total_size_bytes=5000, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "uploading")
        self.db.record_journal_chunk(op_id, cid, acc, 1, 5000, is_parity=0, status="uploaded")

        # Mock Rclone failure (network unreachable)
        def mock_failing_rclone(cmd, *args, **kwargs):
            return self._create_mock_proc(returncode=1, stderr_bytes=b"Network is unreachable")

        with patch("subprocess.Popen", side_effect=mock_failing_rclone):
            summary = self.db.cleanup_incomplete_uploads()

        self.assertEqual(summary["cleanup_failures"], 1)

        # Job is marked failed, preserving chunk for future retry
        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "failed")
        self.assertIn("could not be wiped", journal["error_message"])

        # Chunk remains marked failed in journal chunks table
        chunks = self.db.get_upload_journal_chunks(op_id)
        self.assertEqual(chunks[0]["status"], "failed")

    # --------------------------------------------------------------------------
    # 9. Repeated Restarts Idempotence
    # --------------------------------------------------------------------------
    def test_repeated_restarts_idempotence(self):
        """Subsequent restarts after successful recovery must be idempotent with 0 side effects."""
        acc = "Remote_Idem"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        op_id = "op_idem_009"
        file_id = str(uuid.uuid4())
        cid = f"{file_id[:8]}_part0001"

        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=file_id, file_name="idem.bin",
            total_size_bytes=1000, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "uploading")
        self.db.record_journal_chunk(op_id, cid, acc, 1, 1000, is_parity=0, status="uploaded")

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            # Restart 1: Recover
            s1 = self.db.cleanup_incomplete_uploads()
            self.assertEqual(len(self.deleted_remote_objects), 1)

            # Restart 2: Idempotent run
            s2 = self.db.cleanup_incomplete_uploads()
            self.assertEqual(s2["incomplete_jobs_found"], 0)
            self.assertEqual(len(self.deleted_remote_objects), 1)

            # Restart 3: Another idempotent run
            s3 = self.db.cleanup_incomplete_uploads()
            self.assertEqual(s3["incomplete_jobs_found"], 0)
            self.assertEqual(len(self.deleted_remote_objects), 1)

    # --------------------------------------------------------------------------
    # 10. Storage Counter Reconciliation
    # --------------------------------------------------------------------------
    def test_storage_counter_reconciliation(self):
        """Reconciliation synchronizes used_bytes strictly to the sum of active file_chunks."""
        acc = "Remote_Reconcile"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        # Create valid committed chunk
        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'valid.bin', 1500, datetime('now'), 'completed')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c_valid', ?, ?, 1, 1500, 0)", (file_id, acc))
            # Artificially corrupt storage counter
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 999999 WHERE account_name = ?", (acc,))

        self.db.reconcile_storage_counters()

        cur = self.db.conn.cursor()
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 1528)

    # --------------------------------------------------------------------------
    # 11. Conservative Recovery & Uncertain Ownership Preservation
    # --------------------------------------------------------------------------
    def test_conservative_recovery_uncertain_ownership(self):
        """If a chunk is shared or claimed by an active completed file, recovery NEVER deletes it."""
        acc = "Remote_Shared"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        shared_chunk = "shared_chunk_001"
        valid_file_id = str(uuid.uuid4())
        crashed_file_id = str(uuid.uuid4())

        # Valid file already owns shared_chunk
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'completed.bin', 2000, datetime('now'), 'completed')", (valid_file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES (?, ?, ?, 1, 2000, 0)", (shared_chunk, valid_file_id, acc))

        # Crashed upload references the same chunk
        op_id = "op_overlap_011"
        self.db.create_upload_journal_entry(
            op_id=op_id, file_id=crashed_file_id, file_name="crashed.bin",
            total_size_bytes=2000, total_expected_chunks=1, data_chunks_count=1
        )
        self.db.update_upload_journal_status(op_id, "uploading")
        self.db.record_journal_chunk(op_id, shared_chunk, acc, 1, 2000, is_parity=0, status="uploaded")

        with patch("subprocess.Popen", side_effect=self._record_rclone_call):
            self.db.cleanup_incomplete_uploads()

        # Shared chunk was preserved, NEVER deleted!
        self.assertNotIn(f"{acc}:CloudPool_Vault/{shared_chunk}.enc", self.deleted_remote_objects)

        # Valid file and its chunk remain intact in database
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (valid_file_id,))
        self.assertIsNotNone(cur.fetchone())
        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = ?", (shared_chunk,))
        self.assertIsNotNone(cur.fetchone())


if __name__ == "__main__":
    unittest.main()
