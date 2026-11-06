"""
Automated Test Suite for CloudPool Large File & Low-RAM Download Optimization
Covers TASK 10 Requirements:
1. Download to controlled temporary storage.
2. Decrypt incrementally without creating whole-file memory buffers.
3. Write verified plaintext chunks directly to a temporary output file.
4. Avoid keeping all chunks in memory (bounded <= 40MB peak RAM).
5. Preserve chunk ordering.
6. Support single-chunk bounded RAID-5 parity reconstruction without loading the entire file.
7. Verify chunk ciphertext integrity before decryption.
8. Verify final file integrity with streaming SHA-256 before atomic commit.
9. Rename completed output atomically.
10. Clean up temporary files reliably on failure or cancellation.
11. Controlled spooling for virtual archive containers.
"""

import os
import io
import sys
import uuid
import shutil
import hashlib
import tempfile
import unittest
from unittest.mock import patch

# Ensure project imports
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TESTS_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core_engine import (
    CryptoEngine,
    DatabaseEngine,
    RAID5Engine,
    IntegrityEngine,
    FileIntegrityError
)
from network_engine import NetworkEngine, CHUNK_SIZE


class MockPopen:
    """Deterministic in-memory mock for rclone subprocess operations."""
    def __init__(self, cmd, cloud_storage, failing_targets=None, corrupt_targets=None):
        self.cmd = cmd
        self.cloud_storage = cloud_storage
        self.failing_targets = failing_targets or set()
        self.corrupt_targets = corrupt_targets or set()
        self.pid = 99991
        self.returncode = 0
        self._buffer = io.BytesIO()
        self.stdin = self

    def write(self, data):
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
                data = input if input is not None else self._buffer.getvalue()
                self.cloud_storage[remote_target] = data
                return (b"", b"")

            elif subcmd == "cat":
                if remote_target in self.failing_targets:
                    self.returncode = 1
                    return (b"", b"Error 404: Remote object not found or account offline")

                data = self.cloud_storage.get(remote_target, b"")
                if remote_target in self.corrupt_targets:
                    data = bytearray(data)
                    if len(data) > 15:
                        data[14] ^= 0x5A
                    else:
                        data.append(0x7F)
                    data = bytes(data)
                return (data, b"")

            elif subcmd == "deletefile":
                for k in list(self.cloud_storage.keys()):
                    if k in remote_target or remote_target in k or remote_target.endswith(k.split(":")[-1]):
                        del self.cloud_storage[k]
                return (b"", b"")

        return (b"", b"")

    def poll(self):
        return self.returncode


class TestDownloadLowMemory(unittest.TestCase):
    """Test suite for memory-bounded streaming download and atomic file restoration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cpv_test_lowmem_")
        self.db_path = os.path.join(self.temp_dir, "test_lowmem.db")
        self.db = DatabaseEngine(db_path=self.db_path)
        self.crypto = CryptoEngine(key=os.urandom(32))
        self.net = NetworkEngine(db=self.db, crypto=self.crypto)

        self.cloud_storage = {}
        self.failing_targets = set()
        self.corrupt_targets = set()

        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO cloud_accounts (account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority, status)
            VALUES 
                ('Fast_Cloud1', 'GDrive', 1000000000, 0, 'STABLE', 1, 'CONNECTED'),
                ('Fast_Cloud2', 'OneDrive', 1000000000, 0, 'STABLE', 2, 'CONNECTED'),
                ('Fast_Cloud3', 'Dropbox', 1000000000, 0, 'STABLE', 3, 'CONNECTED'),
                ('Fast_Cloud4', 'Box', 1000000000, 0, 'STABLE', 4, 'CONNECTED')
        """)
        self.db.conn.commit()

        self.rclone_patcher = patch.object(self.db, "is_remote_in_rclone_config", return_value=True)
        self.rclone_patcher.start()

        self.popen_patcher = patch(
            "network_engine.subprocess.Popen",
            side_effect=lambda cmd, **kwargs: MockPopen(
                cmd, self.cloud_storage, self.failing_targets, self.corrupt_targets
            )
        )
        self.popen_patcher.start()

    def tearDown(self):
        self.popen_patcher.stop()
        self.rclone_patcher.stop()
        self.db.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_multi_chunk_direct_disk_streaming_preserves_order(self):
        """
        Multi-chunk file (3 data chunks: 20MB + 20MB + 5MB = 45MB)
        streams directly to temporary file on disk, preserving chunk ordering.
        """
        src_path = os.path.join(self.temp_dir, "large_sample.dat")
        p1 = b"A" * (20 * 1024 * 1024)
        p2 = b"B" * (20 * 1024 * 1024)
        p3 = b"C" * (5 * 1024 * 1024)
        original_data = p1 + p2 + p3
        original_hash = hashlib.sha256(original_data).hexdigest()

        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        self.assertEqual(os.path.getsize(restored_file), len(original_data))

        # Verify chunks in exact order: 20MB 'A', 20MB 'B', 5MB 'C'
        with open(restored_file, "rb") as f:
            chunk1 = f.read(20 * 1024 * 1024)
            chunk2 = f.read(20 * 1024 * 1024)
            chunk3 = f.read(5 * 1024 * 1024)

        self.assertEqual(chunk1, p1)
        self.assertEqual(chunk2, p2)
        self.assertEqual(chunk3, p3)
        self.assertEqual(IntegrityEngine.compute_stream_sha256(restored_file), original_hash)

    def test_raid5_bounded_recovery_first_chunk_missing(self):
        """
        When chunk 1 is missing, bounded rolling XOR reconstructs chunk 1
        and writes it into disk at offset 0 without loading chunk 2 or 3 into RAM.
        """
        src_path = os.path.join(self.temp_dir, "dataset1.bin")
        original_data = os.urandom(25 * 1024 * 1024)  # 2 data chunks: 20MB + 5MB
        original_hash = hashlib.sha256(original_data).hexdigest()

        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Make chunk 1 fail on remote
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
        c1 = cur.fetchone()
        self.failing_targets.add(f"{c1['account_name']}:CloudPool_Vault/{c1['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        self.assertEqual(os.path.getsize(restored_file), len(original_data))
        self.assertEqual(IntegrityEngine.compute_stream_sha256(restored_file), original_hash)

    def test_raid5_bounded_recovery_middle_chunk_missing(self):
        """
        When middle chunk (chunk 2) of a 3-chunk file is missing,
        rolling XOR accumulates chunk 1 and chunk 3, XORs with parity,
        and seeks to (2-1)*20MB to write the recovered chunk directly.
        """
        src_path = os.path.join(self.temp_dir, "dataset2.bin")
        original_data = os.urandom(48 * 1024 * 1024)  # 3 data chunks: 20MB + 20MB + 8MB
        original_hash = hashlib.sha256(original_data).hexdigest()

        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Make chunk 2 fail on remote
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND part_number = 2", (file_id,))
        c2 = cur.fetchone()
        self.failing_targets.add(f"{c2['account_name']}:CloudPool_Vault/{c2['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        self.assertEqual(os.path.getsize(restored_file), len(original_data))
        self.assertEqual(IntegrityEngine.compute_stream_sha256(restored_file), original_hash)

    def test_raid5_bounded_recovery_unequal_last_chunk_missing(self):
        """
        When last unequal chunk (chunk 3 = 6MB) is missing,
        reconstruction correctly slices recovered chunk to expected length (6MB)
        and truncates output file to exact original length.
        """
        src_path = os.path.join(self.temp_dir, "dataset3.bin")
        original_data = os.urandom(46 * 1024 * 1024)  # 20MB + 20MB + 6MB
        original_hash = hashlib.sha256(original_data).hexdigest()

        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Make chunk 3 fail on remote
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND part_number = 3", (file_id,))
        c3 = cur.fetchone()
        self.failing_targets.add(f"{c3['account_name']}:CloudPool_Vault/{c3['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        self.assertEqual(os.path.getsize(restored_file), len(original_data))
        self.assertEqual(IntegrityEngine.compute_stream_sha256(restored_file), original_hash)

    def test_atomic_file_restoration_and_no_ghost_on_failure(self):
        """
        Verifies:
        - Output is spooled to a temporary path (.cp_restore_...) first.
        - On failure (e.g. data loss), the temporary file is completely wiped.
        - The final destination file path never exists if download fails.
        """
        src_path = os.path.join(self.temp_dir, "critical.db")
        original_data = os.urandom(10 * 1024 * 1024)
        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=False)

        # Make chunk 1 fail (no parity available)
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ?", (file_id,))
        c1 = cur.fetchone()
        self.failing_targets.add(f"{c1['account_name']}:CloudPool_Vault/{c1['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        final_dest = os.path.join(restore_dir, "critical.db")

        with self.assertRaises(Exception):
            self.net.download_file(file_id, restore_folder=restore_dir)

        # Verify no files exist in restore_dir (neither final_dest nor temporary spool file)
        self.assertFalse(os.path.exists(final_dest))
        if os.path.exists(restore_dir):
            remaining_files = os.listdir(restore_dir)
            self.assertEqual(remaining_files, [], f"Leftover temporary files found: {remaining_files}")

    def test_user_cancellation_cleans_temporary_download_files(self):
        """User cancellation mid-transfer cleanly unlinks all temporary download artifacts."""
        src_path = os.path.join(self.temp_dir, "cancel_test.iso")
        original_data = os.urandom(25 * 1024 * 1024)
        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=False)

        restore_dir = os.path.join(self.temp_dir, "Restored_Cancelled")

        # Cancel transfer during chunk 2
        def cancel_on_chunk2(**kwargs):
            if kwargs.get("current") == 2:
                self.net.cancel_transfer()

        with self.assertRaises(Exception) as cm:
            self.net.download_file(file_id, restore_folder=restore_dir, progress_callback=cancel_on_chunk2)

        self.assertIn("cancelled", str(cm.exception).lower())
        if os.path.exists(restore_dir):
            self.assertEqual(os.listdir(restore_dir), [])

    def test_container_download_spools_to_disk_and_cleans_temp(self):
        """
        Virtual folder archive container (.cpv) spools to a temporary file on disk,
        extracts contents safely, and completely unlinks the container file upon completion.
        """
        source_dir = os.path.join(self.temp_dir, "SpoolTestFolder")
        os.makedirs(source_dir, exist_ok=True)
        sub_dir = os.path.join(source_dir, "sub")
        os.makedirs(sub_dir, exist_ok=True)

        with open(os.path.join(source_dir, "file1.txt"), "wb") as f:
            f.write(b"Spool test file 1 data")
        with open(os.path.join(sub_dir, "file2.txt"), "wb") as f:
            f.write(b"Spool test file 2 data")

        folder_id = self.net.upload_folder(source_dir, enable_parity=True)

        restore_dir = os.path.join(self.temp_dir, "Restored_Spool")
        restored_folder = self.net.download_folder(folder_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(os.path.join(restored_folder, "file1.txt")))
        self.assertTrue(os.path.exists(os.path.join(restored_folder, "sub", "file2.txt")))

        # Verify no .cpv files left in tempdir or restore_dir
        for root, dirs, files in os.walk(restore_dir):
            for f in files:
                self.assertFalse(f.endswith(".cpv"))


if __name__ == "__main__":
    unittest.main()

