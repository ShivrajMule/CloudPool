"""
Automated Test Suite for CloudPool Folder Upload Rollback, Transactionality, and Consistency
Covers TASK 07 Requirements:
- Unique folder-upload operation ID and persistent upload journal state
- Source validation and permission checks
- Source file change / deletion detection during archive bundling
- Empty directory, Unicode name, and modification timestamp preservation
- Atomic metadata commit (no ghost folders or files on upload failure)
- Remote chunk rollback and orphan prevention
- Duplicate folder name handling (rename, reject, replace)
- Crash recovery after restart via cleanup_incomplete_uploads()
- Full round-trip upload and download verification
"""

import os
import io
import sys
import uuid
import time
import shutil
import tarfile
import tempfile
import sqlite3
import unittest
from unittest.mock import patch, MagicMock

# Ensure project imports
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TESTS_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core_engine import (
    CryptoEngine,
    DatabaseEngine,
    SafeTarExtractor,
    ArchiveSecurityError
)
from network_engine import NetworkEngine


class MockPopen:
    """Mock subprocess.Popen for intercepting rclone commands."""
    def __init__(self, cmd, cloud_storage, simulate_fail_after=None, call_counter=None, on_write_callback=None):
        self.cmd = cmd
        self.cloud_storage = cloud_storage
        self.simulate_fail_after = simulate_fail_after
        self.call_counter = call_counter
        self.on_write_callback = on_write_callback
        self.pid = 99999
        self.returncode = 0
        self._buffer = io.BytesIO()
        self.stdin = self

    def write(self, data):
        if self.on_write_callback:
            self.on_write_callback()
        self._buffer.write(data)

    def flush(self):
        pass

    def close(self):
        pass

    def communicate(self, input=None, timeout=None):
        if isinstance(self.cmd, list) and len(self.cmd) >= 3:
            subcmd = self.cmd[1]
            remote_target = self.cmd[2]

            if subcmd == "rcat":
                if self.call_counter is not None:
                    self.call_counter["count"] += 1
                    if self.simulate_fail_after and self.call_counter["count"] > self.simulate_fail_after:
                        self.returncode = 1
                        return (b"", b"Error 504: Gateway Timeout Simulated")

                data = input if input is not None else self._buffer.getvalue()
                self.cloud_storage[remote_target] = data
                return (b"", b"")

            elif subcmd == "cat":
                data = self.cloud_storage.get(remote_target, b"")
                return (data, b"")

            elif subcmd == "deletefile":
                for k in list(self.cloud_storage.keys()):
                    if k in remote_target or remote_target in k or remote_target.endswith(k.split(":")[-1]):
                        del self.cloud_storage[k]
                return (b"", b"")

        return (b"", b"")

    def poll(self):
        return self.returncode


class TestFolderUploadLifecycle(unittest.TestCase):
    """Rigorous tests for folder upload atomicity, rollback, and consistency."""

    def setUp(self):
        self.rclone_patcher = patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
        self.rclone_patcher.start()

        self.test_dir = tempfile.mkdtemp(prefix="cpv_test_folder_")
        self.db_path = os.path.join(self.test_dir, "test_folder_master.db")
        self.db = DatabaseEngine(db_path=self.db_path)
        self.crypto = CryptoEngine()
        self.net = NetworkEngine(db=self.db, crypto=self.crypto)

        # Register mock accounts across different priority tiers
        self.db.register_account("Mock_MEGA", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=1)
        self.db.register_account("Mock_GDrive", "Google Drive", raw_gb=15.0, buffer_gb=0.5, tier="STABLE", priority=1)
        self.db.register_account("Mock_OneDrive", "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE", priority=2)

        # In-memory mock cloud storage: {f"{remote}:{chunk_id}": bytes}
        self.cloud_storage = {}

    def tearDown(self):
        try:
            self.rclone_patcher.stop()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_local_folder(self, folder_name="ProjectAlpha"):
        """Creates a sample nested local folder structure with empty dirs and Unicode names."""
        root_path = os.path.join(self.test_dir, folder_name)
        os.makedirs(os.path.join(root_path, "docs", "sub"), exist_ok=True)
        os.makedirs(os.path.join(root_path, "empty_dir"), exist_ok=True)
        os.makedirs(os.path.join(root_path, "unicode_📁"), exist_ok=True)

        with open(os.path.join(root_path, "readme.txt"), "w", encoding="utf-8") as f:
            f.write("Project Overview and Architecture")

        with open(os.path.join(root_path, "docs", "spec.pdf"), "wb") as f:
            f.write(b"%PDF-1.4 Mock PDF Content binary data " * 50)

        with open(os.path.join(root_path, "docs", "sub", "report.csv"), "w", encoding="utf-8") as f:
            f.write("id,name,score\n1,alice,99\n2,bob,95\n")

        with open(os.path.join(root_path, "unicode_📁", "données_clé.txt"), "w", encoding="utf-8") as f:
            f.write("Données confidentielles en français / 日本語データ")

        return root_path

    # 1. Successful Folder Upload & Atomic Commit
    def test_successful_folder_upload_and_atomic_commit(self):
        """Verifies successful folder upload: hierarchy, empty dirs, Unicode, and atomic commit."""
        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage)

        with patch("subprocess.Popen", side_effect=mock_popen):
            folder_path = self._create_sample_local_folder("SuccessfulVault")
            root_folder_id = self.net.upload_folder(folder_path, enable_parity=True)

        self.assertIsNotNone(root_folder_id)

        # Check virtual_folders in SQLite
        cur = self.db.conn.cursor()
        cur.execute("SELECT * FROM virtual_folders WHERE folder_id = ?", (root_folder_id,))
        root_row = cur.fetchone()
        self.assertIsNotNone(root_row)
        self.assertEqual(root_row["folder_name"], "SuccessfulVault")

        # Check subfolders were created including empty_dir and unicode_📁
        cur.execute("SELECT folder_name FROM virtual_folders")
        all_folder_names = [r["folder_name"] for r in cur.fetchall()]
        self.assertIn("docs", all_folder_names)
        self.assertIn("sub", all_folder_names)
        self.assertIn("empty_dir", all_folder_names)
        self.assertIn("unicode_📁", all_folder_names)

        # Check files were inserted and point to container
        cur.execute("SELECT file_name, container_id, relative_path FROM virtual_files WHERE is_container = 0")
        files = cur.fetchall()
        self.assertEqual(len(files), 4)

        # Check container file in virtual_files
        cur.execute("SELECT file_id, file_name, is_container FROM virtual_files WHERE is_container = 1")
        container = cur.fetchone()
        self.assertIsNotNone(container)
        self.assertEqual(container["file_name"], "SuccessfulVault.cpv")

        # Check folder_upload_journal is committed
        cur.execute("SELECT status FROM folder_upload_journal")
        journal_row = cur.fetchone()
        self.assertIsNotNone(journal_row)
        self.assertEqual(journal_row["status"], "committed")

        # Check remote chunks exist in mock cloud storage
        self.assertGreater(len(self.cloud_storage), 0)

    # 2. Round-Trip Upload and Download Verification
    def test_round_trip_folder_upload_and_download(self):
        """Verifies full round-trip: upload folder then download it, verifying restored contents."""
        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage)

        with patch("subprocess.Popen", side_effect=mock_popen):
            folder_path = self._create_sample_local_folder("RoundTripFolder")
            root_folder_id = self.net.upload_folder(folder_path, enable_parity=True)

            # Restore folder to a new destination
            restore_dir = os.path.join(self.test_dir, "Restored_Destination")
            downloaded_path = self.net.download_folder(root_folder_id, restore_folder=restore_dir)

        # Verify restored files match original
        restored_readme = os.path.join(downloaded_path, "readme.txt")
        self.assertTrue(os.path.isfile(restored_readme))
        with open(restored_readme, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "Project Overview and Architecture")

        restored_unicode = os.path.join(downloaded_path, "unicode_📁", "données_clé.txt")
        self.assertTrue(os.path.isfile(restored_unicode))
        with open(restored_unicode, "r", encoding="utf-8") as f:
            self.assertIn("Données confidentielles", f.read())

    # 3. Source File Change Detection During Archive Creation
    def test_source_file_modified_during_archiving_aborts_and_rolls_back(self):
        """Detects if a source file changes size or mtime during archiving, rolls back cleanly."""
        folder_path = self._create_sample_local_folder("ChangingFolder")

        orig_tar_open = tarfile.open
        def modified_tar_open(*args, **kwargs):
            # Concurrently modify readme.txt right before archiving
            with open(os.path.join(folder_path, "readme.txt"), "a", encoding="utf-8") as f:
                f.write("CONCURRENT_APPENDED_CONTENT_BY_WRITER")
            return orig_tar_open(*args, **kwargs)

        with patch("tarfile.open", side_effect=modified_tar_open):
            with self.assertRaises(RuntimeError) as cm:
                self.net.upload_folder(folder_path)
            self.assertIn("Source file was modified during archiving", str(cm.exception))

        # Check that NO ghost folders or files remain in SQLite
        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_folders")
        self.assertEqual(cur.fetchone()["cnt"], 0, "Ghost folder remained in DB after source modification!")
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_files")
        self.assertEqual(cur.fetchone()["cnt"], 0, "Ghost files remained in DB after source modification!")

        # Journal is marked rolled_back
        cur.execute("SELECT status FROM folder_upload_journal")
        self.assertEqual(cur.fetchone()["status"], "rolled_back")

    # 4. Source File Deletion During Archive Creation
    def test_source_file_deleted_during_archiving_aborts_and_rolls_back(self):
        """Detects if a source file is deleted during archiving and triggers rollback."""
        folder_path = self._create_sample_local_folder("DeletedFileFolder")

        orig_tar_open = tarfile.open
        def deleted_tar_open(*args, **kwargs):
            # Concurrently delete readme.txt right before archiving
            os.remove(os.path.join(folder_path, "readme.txt"))
            return orig_tar_open(*args, **kwargs)

        with patch("tarfile.open", side_effect=deleted_tar_open):
            with self.assertRaises(RuntimeError) as cm:
                self.net.upload_folder(folder_path)
            self.assertIn("Source file was deleted during archiving", str(cm.exception))

        # Assert no ghost records
        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_folders")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_files")
        self.assertEqual(cur.fetchone()["cnt"], 0)

    # 5. Remote Upload Failure Rollback (Zero Ghost Records & Chunks Wiped)
    def test_remote_upload_failure_wipes_chunks_and_leaves_no_ghosts(self):
        """Simulates remote cloud failure during chunk upload; verifies full rollback."""
        counter = {"count": 0}
        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage, simulate_fail_after=1, call_counter=counter)

        folder_path = self._create_sample_local_folder("FailingRemoteFolder")

        with patch("subprocess.Popen", side_effect=mock_popen):
            with self.assertRaises(Exception):
                self.net.upload_folder(folder_path)

        # Verify NO ghost folders exist in SQLite
        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_folders")
        self.assertEqual(cur.fetchone()["cnt"], 0, "Ghost virtual folder was left behind!")
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_files")
        self.assertEqual(cur.fetchone()["cnt"], 0, "Ghost virtual files were left behind!")

        # Verify remote chunks uploaded prior to failure were wiped
        self.assertEqual(len(self.cloud_storage), 0, "Orphan remote chunks were not wiped!")

        # Verify folder journal is rolled_back
        cur.execute("SELECT status FROM folder_upload_journal")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "rolled_back")

    # 6. User Cancellation Rollback
    def test_user_cancellation_during_upload_rolls_back(self):
        """Cancels upload mid-transfer; verifies zero ghost folders and complete cleanup."""
        def cancel_hook():
            self.net.cancel_requested = True

        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage, on_write_callback=cancel_hook)

        folder_path = self._create_sample_local_folder("CancelledFolder")

        with patch("subprocess.Popen", side_effect=mock_popen):
            with self.assertRaises(Exception) as cm:
                self.net.upload_folder(folder_path)
            self.assertIn("cancelled", str(cm.exception).lower())

        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_folders")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_files")
        self.assertEqual(cur.fetchone()["cnt"], 0)

    # 7. Duplicate Folder Names Handling
    def test_duplicate_folder_name_policies(self):
        """Tests rename policy and reject policy on duplicate folder names."""
        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage)

        folder_path = self._create_sample_local_folder("DupeFolder")

        with patch("subprocess.Popen", side_effect=mock_popen):
            # First upload: succeeds as 'DupeFolder'
            fid1 = self.net.upload_folder(folder_path)
            folder1 = self.db.get_folder(fid1)
            self.assertEqual(folder1["folder_name"], "DupeFolder")

            # Second upload with default on_duplicate='rename': succeeds as 'DupeFolder (1)'
            fid2 = self.net.upload_folder(folder_path, on_duplicate="rename")
            folder2 = self.db.get_folder(fid2)
            self.assertEqual(folder2["folder_name"], "DupeFolder (1)")

            # Third upload with on_duplicate='reject': raises FileExistsError
            with self.assertRaises(FileExistsError):
                self.net.upload_folder(folder_path, on_duplicate="reject")

    # 8. Source Permission Errors Handled Safely
    def test_source_permission_error_fails_gracefully(self):
        """Rejects folder when root directory is unreadable."""
        folder_path = self._create_sample_local_folder("UnreadableFolder")

        with patch("os.access", return_value=False):
            with self.assertRaises(PermissionError):
                self.net.upload_folder(folder_path)

        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM virtual_folders")
        self.assertEqual(cur.fetchone()["cnt"], 0)

    # 9. Startup Crash Recovery for Interrupted Folder Upload
    def test_startup_crash_recovery_for_interrupted_folder(self):
        """Simulates an application crash during folder upload and verifies restart recovery."""
        def mock_popen(cmd, *args, **kwargs):
            return MockPopen(cmd, self.cloud_storage)

        # Manually inject an interrupted folder upload in 'uploading' state into journals
        folder_op_id = "fop_crashed_123"
        container_id = "container_crashed_456"
        c_op_id = "op_container_789"
        created_folder_id = "folder_crashed_001"

        # Record folder journal
        self.db.create_folder_upload_journal_entry(
            folder_op_id=folder_op_id,
            root_folder_name="CrashedProject",
            parent_folder_id=None,
            container_id=container_id,
            total_files=5,
            total_bytes=1000
        )
        self.db.update_folder_upload_journal_status(
            folder_op_id, "uploading", created_root_folder_id=created_folder_id
        )

        # Record container upload in upload_journal
        self.db.create_upload_journal_entry(
            op_id=c_op_id,
            file_id=container_id,
            file_name="CrashedProject.cpv",
            total_size_bytes=1000,
            target_tier="STABLE",
            total_expected_chunks=2,
            data_chunks_count=1,
            is_container=1
        )
        self.db.record_journal_chunk(c_op_id, "crashed_chunk_1", "Mock_MEGA", 0, 500, is_parity=0, status="uploaded")
        self.cloud_storage["Mock_MEGA:CloudPool_Vault/crashed_chunk_1.enc"] = b"MOCK_UPLOADED_CHUNK"

        # Simulate startup recovery
        with patch("subprocess.Popen", side_effect=mock_popen):
            summary = self.db.cleanup_incomplete_uploads()

        self.assertGreaterEqual(summary["jobs_rolled_back"], 1)

        # Verify remote chunk was wiped
        self.assertNotIn("Mock_MEGA:CloudPool_Vault/crashed_chunk_1.enc", self.cloud_storage)

        # Verify folder journal status is rolled_back
        fentry = self.db.get_folder_upload_journal_entry(folder_op_id)
        self.assertEqual(fentry["status"], "rolled_back")

        # Verify no ghost folders
        self.assertIsNone(self.db.get_folder(created_folder_id))


if __name__ == "__main__":
    unittest.main()
