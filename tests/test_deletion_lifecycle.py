"""
Automated Test Suite for CloudPool Reliable Deletion Lifecycle
Tests transaction safety, persistent jobs, exit code verification, partial deletion,
retries, timeout handling, offline accounts, zero-byte files, and crash recovery.
All tests use temporary SQLite databases and mocked Rclone subprocesses.
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


class TestDeletionLifecycle(unittest.TestCase):
    def setUp(self):
        """Create an isolated temporary SQLite database and network engine for each test."""
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db_path = self.temp_db_file.name
        self.db = DatabaseEngine(db_path=self.db_path)
        self.net = NetworkEngine()
        self.net.db = self.db  # Wire network engine to test database

        # Default mock: all accounts exist in rclone.conf
        self.db.is_remote_in_rclone_config = lambda name: True

    def tearDown(self):
        """Clean up database connection and temporary files."""
        try:
            self.db.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def _create_mock_proc(self, returncode=0, stderr=""):
        """Helper to create a mocked subprocess.Popen instance."""
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_proc.returncode = returncode
        mock_proc.communicate.return_value = ("", stderr)
        return mock_proc

    @patch("subprocess.Popen")
    def test_successful_deletion(self, mock_popen):
        """Test successful deletion of a file with confirmed remote wipe and quota reclamation."""
        mock_popen.return_value = self._create_mock_proc(returncode=0)

        acc = "Mega_Test"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        
        # Set account used_bytes to 40 MB
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 41943040 WHERE account_name = ?", (acc,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'doc.pdf', 41943040, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c1', ?, ?, 1, 20971520, 0)", (file_id, acc))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c2', ?, ?, 2, 20971520, 0)", (file_id, acc))

        res = self.net.delete_file(file_id)

        # Assert full completion
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["deleted_chunks"], 2)
        self.assertEqual(res["failed_chunks"], 0)

        # Verify file and chunks are gone from SQLite
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())
        cur.execute("SELECT chunk_id FROM file_chunks WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())

        # Verify storage quota was decremented to 0
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)

        # Verify persistent job status is completed
        job = self.db.get_deletion_job(res["job_id"])
        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["deleted_chunks"], 2)

    @patch("subprocess.Popen")
    def test_remote_failure(self, mock_popen):
        """Test that a remote Rclone failure preserves metadata and prevents quota decrement."""
        mock_popen.return_value = self._create_mock_proc(returncode=1, stderr="Error 403: Forbidden - Access Denied")

        acc = "OneDrive_Fail"
        self.db.register_account(acc, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE")
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 20971520 WHERE account_name = ?", (acc,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'secure.zip', 20971520, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('fail_c1', ?, ?, 1, 20971520, 0)", (file_id, acc))

        res = self.net.delete_file(file_id)

        # Assert failure status
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["failed_chunks"], 1)
        self.assertIn("Forbidden", res["error_message"])

        # File and chunk MUST still exist in database
        cur = self.db.conn.cursor()
        cur.execute("SELECT deletion_status FROM virtual_files WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["deletion_status"], "failed")

        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = 'fail_c1'")
        self.assertIsNotNone(cur.fetchone())

        # Quota MUST NOT be decremented
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 20971520)

        # Job record must reflect failure
        job = self.db.get_deletion_job(res["job_id"])
        self.assertEqual(job["status"], "failed")

    @patch("subprocess.Popen")
    def test_timeout(self, mock_popen):
        """Test that process timeout during deletion is handled gracefully without crashing."""
        mock_proc = MagicMock()
        mock_proc.pid = 8888
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["rclone"], timeout=30)
        mock_popen.return_value = mock_proc

        acc = "Timeout_Remote"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'slow.bin', 1000, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('timeout_c1', ?, ?, 1, 1000, 0)", (file_id, acc))

        res = self.net.delete_file(file_id)

        self.assertEqual(res["status"], "failed")
        self.assertIn("timed out", res["error_message"].lower())

        # Verify chunk is still intact
        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = 'timeout_c1'")
        self.assertIsNotNone(cur.fetchone())

    def test_offline_account(self):
        """Test that attempting deletion on an offline / unconfigured account is caught before execution."""
        acc = "Offline_Remote_1"
        self.db.register_account(acc, "Google Drive", raw_gb=15.0, buffer_gb=0.5, tier="STABLE")
        
        # Simulate offline: is_remote_in_rclone_config returns False
        self.db.is_remote_in_rclone_config = lambda name: False

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'offline.dat', 500, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('off_c1', ?, ?, 1, 500, 0)", (file_id, acc))

        res = self.net.delete_file(file_id)

        self.assertEqual(res["status"], "failed")
        self.assertIn("offline", res["error_message"])

        # Chunk preserved
        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = 'off_c1'")
        self.assertIsNotNone(cur.fetchone())

    @patch("subprocess.Popen")
    def test_one_successful_and_one_failed_chunk(self, mock_popen):
        """Test partial deletion when one chunk succeeds and another fails."""
        # Chunk 1 succeeds, Chunk 2 fails
        mock_popen.side_effect = [
            self._create_mock_proc(returncode=0),
            self._create_mock_proc(returncode=1, stderr="Network connection reset")
        ]

        acc1 = "Remote_Good"
        acc2 = "Remote_Bad"
        self.db.register_account(acc1, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc2, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 20000000 WHERE account_name = ?", (acc1,))
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 20000000 WHERE account_name = ?", (acc2,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'split.iso', 40000000, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('good_c1', ?, ?, 1, 20000000, 0)", (file_id, acc1))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('bad_c2', ?, ?, 2, 20000000, 0)", (file_id, acc2))

        res = self.net.delete_file(file_id)

        self.assertEqual(res["status"], "partially_deleted")
        self.assertEqual(res["deleted_chunks"], 1)
        self.assertEqual(res["failed_chunks"], 1)

        # Chunk 1 confirmed deleted, Chunk 2 preserved
        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = 'good_c1'")
        self.assertIsNone(cur.fetchone(), "Chunk 1 should be deleted from SQLite.")
        cur.execute("SELECT chunk_id FROM file_chunks WHERE chunk_id = 'bad_c2'")
        self.assertIsNotNone(cur.fetchone(), "Chunk 2 must be preserved in SQLite.")

        # Acc1 decremented, Acc2 preserved
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc1,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc2,))
        self.assertEqual(cur.fetchone()["used_bytes"], 20000000)

        # File marked partially_deleted
        cur.execute("SELECT deletion_status FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertEqual(cur.fetchone()["deletion_status"], "partially_deleted")

    @patch("subprocess.Popen")
    def test_repeated_deletion(self, mock_popen):
        """Test retrying deletion on a partially deleted file completes safely without double deletion."""
        # First attempt: Chunk 1 succeeds, Chunk 2 fails
        mock_popen.side_effect = [
            self._create_mock_proc(returncode=0),
            self._create_mock_proc(returncode=1, stderr="HTTP 500 Server Error")
        ]

        acc = "Remote_Retry"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 4000 WHERE account_name = ?", (acc,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'retry.txt', 4000, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('part_c1', ?, ?, 1, 2000, 0)", (file_id, acc))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('part_c2', ?, ?, 2, 2000, 0)", (file_id, acc))

        res1 = self.net.delete_file(file_id)
        self.assertEqual(res1["status"], "partially_deleted")

        # Second attempt (Retry): Now Chunk 2 succeeds
        mock_popen.side_effect = [
            self._create_mock_proc(returncode=0)
        ]

        res2 = self.net.delete_file(file_id)
        self.assertEqual(res2["status"], "completed")
        self.assertEqual(res2["deleted_chunks"], 1)

        # All chunks and file gone, used_bytes exactly 0 (no negative quota)
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())
        cur.execute("SELECT chunk_id FROM file_chunks WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 0)

        # Third attempt (Idempotent call on already deleted file)
        res3 = self.net.delete_file(file_id)
        self.assertEqual(res3["status"], "completed")
        self.assertEqual(res3["deleted_chunks"], 0)

    def test_restart_during_deletion(self):
        """Test that jobs interrupted during execution are transitioned to partially_deleted or failed on restart."""
        acc = "Remote_Interrupted"
        self.db.register_account(acc, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE")

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, deletion_status) VALUES (?, 'crashed.dat', 1000, datetime('now'), 'deleting')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('crash_c1', ?, ?, 1, 1000, 0)", (file_id, acc))
            # Simulate job record stuck in 'deleting'
            self.db.conn.execute("""
                INSERT INTO deletion_jobs (job_id, file_id, file_name, total_chunks, deleted_chunks, failed_chunks, status, created_at, updated_at)
                VALUES ('job_stuck', ?, 'crashed.dat', 1, 0, 0, 'deleting', datetime('now'), datetime('now'))
            """, (file_id,))

        # Run startup recovery
        recovered = self.db.recover_interrupted_deletions()
        self.assertEqual(recovered, 1)

        job = self.db.get_deletion_job("job_stuck")
        self.assertEqual(job["status"], "failed")
        self.assertIn("restart", job["error_message"].lower())

        cur = self.db.conn.cursor()
        cur.execute("SELECT deletion_status FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertEqual(cur.fetchone()["deletion_status"], "failed")

    def test_database_transaction_failure(self):
        """Test transaction atomicity: a database commit error keeps chunk and quota intact."""
        acc = "Remote_TxFail"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 1000 WHERE account_name = ?", (acc,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'tx.bin', 1000, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('tx_c1', ?, ?, 1, 1000, 0)", (file_id, acc))

        # Monkey-patch delete_chunk_record_atomic to simulate database failure
        def mock_failing_delete(*args, **kwargs):
            raise sqlite3.OperationalError("Simulated disk I/O failure")

        self.db.delete_chunk_record_atomic = mock_failing_delete

        with patch("subprocess.Popen", return_value=self._create_mock_proc(returncode=0)):
            res = self.net.delete_file(file_id)

        self.assertEqual(res["status"], "failed")
        self.assertIn("Simulated disk I/O failure", res["error_message"])

        # Quota remains intact
        cur = self.db.conn.cursor()
        cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["used_bytes"], 1000)

    def test_zero_byte_file_deletion(self):
        """Test deleting a zero-byte file that has 0 chunks completes instantly and cleanly."""
        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'empty.txt', 0, datetime('now'))", (file_id,))

        res = self.net.delete_file(file_id)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["deleted_chunks"], 0)

        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertIsNone(cur.fetchone())

    @patch("subprocess.Popen")
    def test_file_with_multiple_chunks(self, mock_popen):
        """Test deleting a multi-chunk file sharded across multiple cloud accounts."""
        mock_popen.return_value = self._create_mock_proc(returncode=0)

        acc1 = "Mega_Shard_1"
        acc2 = "Mega_Shard_2"
        acc3 = "OneDrive_Shard_3"
        self.db.register_account(acc1, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc2, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc3, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE")
        with self.db.conn:
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 40000000 WHERE account_name = ?", (acc1,))
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 40000000 WHERE account_name = ?", (acc2,))
            self.db.conn.execute("UPDATE cloud_accounts SET used_bytes = 20000000 WHERE account_name = ?", (acc3,))

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'big_dataset.tar', 100000000, datetime('now'))", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('multi_c1', ?, ?, 1, 20000000, 0)", (file_id, acc1))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('multi_c2', ?, ?, 2, 20000000, 0)", (file_id, acc1))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('multi_c3', ?, ?, 3, 20000000, 0)", (file_id, acc2))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('multi_c4', ?, ?, 4, 20000000, 0)", (file_id, acc2))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('multi_c5', ?, ?, 9999, 20000000, 1)", (file_id, acc3))

        res = self.net.delete_file(file_id)

        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["deleted_chunks"], 5)
        self.assertEqual(res["failed_chunks"], 0)

        # Quotas decremented across all 3 remotes
        cur = self.db.conn.cursor()
        for name in [acc1, acc2, acc3]:
            cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = ?", (name,))
            self.assertEqual(cur.fetchone()["used_bytes"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
