"""
Automated Test Suite for CloudPool End-to-End File Integrity Verification (SHA-256)
Covers TASK 09 Requirements:
1. Calculate SHA-256 of original file before upload and store in virtual_files.file_hash.
2. Calculate SHA-256 hash for every encrypted chunk and store in file_chunks.ciphertext_hash.
3. Verify downloaded ciphertext before AES-GCM decryption.
4. Tampered ciphertext triggers RAID-5 XOR reconstruction.
5. Verify reconstructed chunks against end-to-end file hash.
6. Verify complete restored file before final commit (atomic rename).
7. Reject restored file and delete temporary file if final SHA-256 verification fails.
8. Never report successful restoration when final integrity verification fails.
9. Support legacy files without stored hashes, marking status as 'legacy_unverified'.
10. Verify folder archive container and individual member file integrity.
11. Bounded streaming hash execution for large files and 0-byte files.
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
        self.pid = 99999
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
                    # Tamper with the ciphertext bytes to simulate in-flight/remote bit corruption
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


class TestIntegrityEnginePrimitives(unittest.TestCase):
    """Unit tests for IntegrityEngine hashing primitives and comparisons."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cpv_integ_prim_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sha256_bytes_and_stream_consistency(self):
        """Streaming hash and byte hash must return identical hex digests."""
        payload = os.urandom(128 * 1024)
        expected_hash = hashlib.sha256(payload).hexdigest()

        file_path = os.path.join(self.temp_dir, "test.bin")
        with open(file_path, "wb") as f:
            f.write(payload)

        bytes_hash = IntegrityEngine.compute_bytes_sha256(payload)
        stream_hash = IntegrityEngine.compute_stream_sha256(file_path)

        self.assertEqual(bytes_hash, expected_hash)
        self.assertEqual(stream_hash, expected_hash)
        self.assertTrue(IntegrityEngine.verify_hash(bytes_hash, stream_hash))

    def test_empty_data_sha256(self):
        """0-byte stream and 0-byte bytes must match standard empty SHA-256."""
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(IntegrityEngine.compute_bytes_sha256(b""), empty_hash)

        empty_file = os.path.join(self.temp_dir, "empty.bin")
        with open(empty_file, "wb") as f:
            pass
        self.assertEqual(IntegrityEngine.compute_stream_sha256(empty_file), empty_hash)

    def test_verify_hash_constant_time_comparison(self):
        """verify_hash must handle case-insensitivity, whitespace, and reject mismatches."""
        h1 = "a1b2c3d4e5f6" + "0" * 52
        h2 = "A1B2C3D4E5F6" + "0" * 52
        h3 = "  " + h1 + "  \n"
        h_bad = "f" * 64

        self.assertTrue(IntegrityEngine.verify_hash(h1, h2))
        self.assertTrue(IntegrityEngine.verify_hash(h1, h3))
        self.assertFalse(IntegrityEngine.verify_hash(h1, h_bad))
        self.assertFalse(IntegrityEngine.verify_hash(None, h1))
        self.assertFalse(IntegrityEngine.verify_hash(h1, ""))

    def test_streaming_hash_preserves_seek_position(self):
        """compute_stream_sha256 on a seekable stream must return cursor to initial position."""
        buf = io.BytesIO(b"Hello World CloudPool 2026")
        buf.seek(6)
        h = IntegrityEngine.compute_stream_sha256(buf)
        self.assertEqual(buf.tell(), 6)
        expected = hashlib.sha256(b"Hello World CloudPool 2026").hexdigest()
        self.assertEqual(h, expected)


class TestFileIntegrityEndToEnd(unittest.TestCase):
    """Comprehensive End-to-End Test Suite for Task 09 File Integrity Verification."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cpv_integ_test_")
        self.db_path = os.path.join(self.temp_dir, "test_integrity.db")
        self.db = DatabaseEngine(db_path=self.db_path)
        self.key = os.urandom(32)
        self.crypto = CryptoEngine(key=self.key)
        self.net = NetworkEngine(db=self.db, crypto=self.crypto)

        self.cloud_storage = {}
        self.failing_targets = set()
        self.corrupt_targets = set()

        # Register 3 cloud accounts across 2 providers to allow data + RAID-5 parity
        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO cloud_accounts (account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority, status)
            VALUES 
                ('Cloud_A', 'GDrive', 500000000, 0, 'STABLE', 1, 'CONNECTED'),
                ('Cloud_B', 'OneDrive', 500000000, 0, 'STABLE', 2, 'CONNECTED'),
                ('Cloud_C', 'Dropbox', 500000000, 0, 'STABLE', 3, 'CONNECTED')
        """)
        self.db.conn.commit()

        # Patch rclone.conf validation so mock accounts are always seen as connected
        self.rclone_patcher = patch.object(self.db, "is_remote_in_rclone_config", return_value=True)
        self.rclone_patcher.start()

        # Patch subprocess.Popen in network_engine with MockPopen
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

    def test_normal_upload_and_download_integrity(self):
        """
        Verifies:
        1. SHA-256 calculated before upload and stored in virtual_files.file_hash.
        2. Chunk ciphertext hashes stored in file_chunks.ciphertext_hash.
        3. Restored file matches original SHA-256 and bit-for-bit content.
        4. virtual_files.integrity_status updated to 'verified'.
        """
        src_path = os.path.join(self.temp_dir, "document.pdf")
        original_data = os.urandom(25 * 1024 * 1024)  # 25 MB (2 data chunks + 1 parity)
        with open(src_path, "wb") as f:
            f.write(original_data)
        original_hash = hashlib.sha256(original_data).hexdigest()

        # Upload
        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Inspect database records
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_hash, hash_algorithm, integrity_status FROM virtual_files WHERE file_id = ?", (file_id,))
        vf = cur.fetchone()
        self.assertIsNotNone(vf)
        self.assertEqual(vf["file_hash"], original_hash)
        self.assertEqual(vf["hash_algorithm"], "SHA-256")
        self.assertEqual(vf["integrity_status"], "verified")

        # Verify chunk ciphertext hashes
        cur.execute("SELECT chunk_id, is_parity, ciphertext_hash FROM file_chunks WHERE file_id = ?", (file_id,))
        chunks = cur.fetchall()
        self.assertEqual(len(chunks), 3)  # 2 data + 1 parity
        for ch in chunks:
            self.assertIsNotNone(ch["ciphertext_hash"])
            self.assertEqual(len(ch["ciphertext_hash"]), 64)

        # Download and verify
        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        with open(restored_file, "rb") as f:
            restored_bytes = f.read()

        self.assertEqual(len(restored_bytes), len(original_data))
        self.assertEqual(hashlib.sha256(restored_bytes).hexdigest(), original_hash)
        self.assertEqual(restored_bytes, original_data)

    def test_tampered_ciphertext_triggers_raid5_reconstruction(self):
        """
        When a data chunk's ciphertext is tampered with on the remote:
        - NetworkEngine detects ciphertext hash mismatch before decryption.
        - Triggers RAID-5 XOR reconstruction to heal the missing chunk.
        - Verifies restored file SHA-256 matches original file hash.
        - Download succeeds without data loss!
        """
        src_path = os.path.join(self.temp_dir, "important_vault.dat")
        original_data = os.urandom(22 * 1024 * 1024)  # 2 data chunks (20MB + 2MB)
        with open(src_path, "wb") as f:
            f.write(original_data)
        original_hash = hashlib.sha256(original_data).hexdigest()

        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Find chunk 1 remote target
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
        c1 = cur.fetchone()
        target_remote_path = f"{c1['account_name']}:CloudPool_Vault/{c1['chunk_id']}.enc"

        # Corrupt chunk 1 ciphertext on remote
        self.corrupt_targets.add(target_remote_path)

        # Download should heal chunk 1 using parity block and verify final hash
        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        with open(restored_file, "rb") as f:
            restored_bytes = f.read()

        self.assertEqual(hashlib.sha256(restored_bytes).hexdigest(), original_hash)
        self.assertEqual(restored_bytes, original_data)

    def test_tampered_ciphertext_multiple_chunks_fails_safely(self):
        """
        When multiple chunk ciphertexts are tampered with, RAID-5 (N+1) protection is exceeded.
        Download must fail safely, never produce corrupted files, and raise an unrecoverable exception.
        """
        src_path = os.path.join(self.temp_dir, "archive.bin")
        original_data = os.urandom(25 * 1024 * 1024)
        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        # Corrupt BOTH data chunks
        cur = self.db.conn.cursor()
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND is_parity = 0", (file_id,))
        for c in cur.fetchall():
            self.corrupt_targets.add(f"{c['account_name']}:CloudPool_Vault/{c['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        with self.assertRaises(Exception) as cm:
            self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertIn("unrecoverable data loss", str(cm.exception).lower())
        # Ensure no corrupted output file was created
        restored_path = os.path.join(restore_dir, "archive.bin")
        self.assertFalse(os.path.exists(restored_path))

    def test_tampered_parity_prevents_corrupted_restoration(self):
        """
        When chunk 1 is missing and parity ciphertext is corrupted:
        Download must detect parity corruption and fail cleanly without writing broken files.
        """
        src_path = os.path.join(self.temp_dir, "code.tar")
        original_data = os.urandom(21 * 1024 * 1024)
        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=True)

        cur = self.db.conn.cursor()
        # Make chunk 1 fail (offline)
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
        c1 = cur.fetchone()
        self.failing_targets.add(f"{c1['account_name']}:CloudPool_Vault/{c1['chunk_id']}.enc")

        # Corrupt parity chunk ciphertext
        cur.execute("SELECT account_name, chunk_id FROM file_chunks WHERE file_id = ? AND is_parity = 1", (file_id,))
        p = cur.fetchone()
        self.corrupt_targets.add(f"{p['account_name']}:CloudPool_Vault/{p['chunk_id']}.enc")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        with self.assertRaises(Exception) as cm:
            self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(
            "unrecoverable data loss" in str(cm.exception).lower() or
            "corrupted" in str(cm.exception).lower()
        )
        self.assertFalse(os.path.exists(os.path.join(restore_dir, "code.tar")))

    def test_tampered_file_hash_metadata_fails_restoration(self):
        """
        If virtual_files.file_hash does not match the actual decrypted file bytes:
        download_file must detect final SHA-256 failure, remove temporary file, and raise FileIntegrityError.
        """
        src_path = os.path.join(self.temp_dir, "financial_report.xlsx")
        original_data = os.urandom(5 * 1024 * 1024)
        with open(src_path, "wb") as f:
            f.write(original_data)

        file_id = self.net.upload_file(src_path, enable_parity=False)

        # Maliciously or accidentally tamper with expected file_hash in database
        bogus_hash = "0" * 64
        with self.db.conn:
            self.db.conn.execute("UPDATE virtual_files SET file_hash = ? WHERE file_id = ?", (bogus_hash, file_id))

        restore_dir = os.path.join(self.temp_dir, "Restored")
        with self.assertRaises(FileIntegrityError) as cm:
            self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertIn("integrity verification failed", str(cm.exception).lower())
        self.assertIn(bogus_hash, str(cm.exception))

        # Destination file must not exist
        target_path = os.path.join(restore_dir, "financial_report.xlsx")
        self.assertFalse(os.path.exists(target_path))

    def test_legacy_file_without_hash_downloads_safely(self):
        """
        Existing vaults with legacy files (file_hash IS NULL, ciphertext_hash IS NULL)
        must remain downloadable, but clearly update status to 'legacy_unverified'.
        """
        src_path = os.path.join(self.temp_dir, "legacy_file.txt")
        content = b"Legacy CloudPool data without SHA-256 hash from older version."
        with open(src_path, "wb") as f:
            f.write(content)

        file_id = self.net.upload_file(src_path, enable_parity=False)

        # Strip file_hash and chunk ciphertext_hash to simulate legacy record
        with self.db.conn:
            self.db.conn.execute("UPDATE virtual_files SET file_hash = NULL, integrity_status = 'unverified' WHERE file_id = ?", (file_id,))
            self.db.conn.execute("UPDATE file_chunks SET ciphertext_hash = NULL WHERE file_id = ?", (file_id,))

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_file = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_file))
        with open(restored_file, "rb") as f:
            self.assertEqual(f.read(), content)

        # Integrity status must be 'legacy_unverified'
        cur = self.db.conn.cursor()
        cur.execute("SELECT integrity_status, file_hash FROM virtual_files WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        self.assertEqual(row["integrity_status"], "legacy_unverified")
        self.assertIsNone(row["file_hash"])

    def test_zero_byte_file_integrity(self):
        """Zero-byte file upload and download must correctly record and verify empty hash."""
        src_path = os.path.join(self.temp_dir, "zero.dat")
        with open(src_path, "wb") as f:
            pass

        file_id = self.net.upload_file(src_path, enable_parity=True)

        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_hash, integrity_status FROM virtual_files WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        self.assertEqual(row["file_hash"], empty_hash)
        self.assertEqual(row["integrity_status"], "verified")

        restore_dir = os.path.join(self.temp_dir, "Restored")
        restored_path = self.net.download_file(file_id, restore_folder=restore_dir)
        self.assertTrue(os.path.exists(restored_path))
        self.assertEqual(os.path.getsize(restored_path), 0)

    def test_folder_upload_and_download_integrity(self):
        """
        Verifies:
        1. upload_folder records SHA-256 for container and for all individual member files.
        2. download_folder verifies container integrity and each extracted file's SHA-256.
        """
        source_dir = os.path.join(self.temp_dir, "MyDocs")
        os.makedirs(source_dir, exist_ok=True)
        sub_dir = os.path.join(source_dir, "SubDocs")
        os.makedirs(sub_dir, exist_ok=True)

        f1_data = b"Hello from file 1" * 500
        f2_data = b"Hello from subfolder file 2" * 1000

        with open(os.path.join(source_dir, "doc1.txt"), "wb") as f:
            f.write(f1_data)
        with open(os.path.join(sub_dir, "doc2.txt"), "wb") as f:
            f.write(f2_data)

        f1_hash = hashlib.sha256(f1_data).hexdigest()
        f2_hash = hashlib.sha256(f2_data).hexdigest()

        folder_id = self.net.upload_folder(source_dir, enable_parity=True)

        # Verify DB integrity hashes for container and files
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_name, file_hash, integrity_status, is_container FROM virtual_files")
        rows = {r["file_name"]: dict(r) for r in cur.fetchall()}

        self.assertIn("doc1.txt", rows)
        self.assertIn("doc2.txt", rows)
        self.assertEqual(rows["doc1.txt"]["file_hash"], f1_hash)
        self.assertEqual(rows["doc1.txt"]["integrity_status"], "verified")
        self.assertEqual(rows["doc2.txt"]["file_hash"], f2_hash)
        self.assertEqual(rows["doc2.txt"]["integrity_status"], "verified")

        self.assertIn("MyDocs.cpv", rows)
        self.assertIsNotNone(rows["MyDocs.cpv"]["file_hash"])
        self.assertEqual(rows["MyDocs.cpv"]["integrity_status"], "verified")

        # Download folder and verify contents
        restore_dir = os.path.join(self.temp_dir, "Restored_Folders")
        restored_folder = self.net.download_folder(folder_id, restore_folder=restore_dir)

        r_f1 = os.path.join(restored_folder, "doc1.txt")
        r_f2 = os.path.join(restored_folder, "SubDocs", "doc2.txt")
        self.assertTrue(os.path.exists(r_f1))
        self.assertTrue(os.path.exists(r_f2))

        with open(r_f1, "rb") as f:
            self.assertEqual(f.read(), f1_data)
        with open(r_f2, "rb") as f:
            self.assertEqual(f.read(), f2_data)

    def test_folder_download_fails_on_corrupted_container_hash(self):
        """If container hash is tampered with or archive is damaged, download_folder raises FileIntegrityError."""
        source_dir = os.path.join(self.temp_dir, "ProjectAssets")
        os.makedirs(source_dir, exist_ok=True)
        with open(os.path.join(source_dir, "asset.json"), "wb") as f:
            f.write(b'{"key": "value"}')

        folder_id = self.net.upload_folder(source_dir, enable_parity=False)

        # Tamper with container's file_hash in database
        with self.db.conn:
            self.db.conn.execute("UPDATE virtual_files SET file_hash = ? WHERE is_container = 1", ("e" * 64,))

        restore_dir = os.path.join(self.temp_dir, "Restored_Corrupted")
        with self.assertRaises(FileIntegrityError) as cm:
            self.net.download_folder(folder_id, restore_folder=restore_dir)

        self.assertIn("container archive corrupted", str(cm.exception).lower())

    def test_single_file_extraction_from_container_verifies_integrity(self):
        """Downloading an individual file packaged inside a virtual archive container verifies its hash."""
        source_dir = os.path.join(self.temp_dir, "BundledProject")
        os.makedirs(source_dir, exist_ok=True)
        file_content = os.urandom(32 * 1024)
        with open(os.path.join(source_dir, "standalone.dat"), "wb") as f:
            f.write(file_content)

        folder_id = self.net.upload_folder(source_dir, enable_parity=False)

        cur = self.db.conn.cursor()
        cur.execute("SELECT file_id FROM virtual_files WHERE file_name = 'standalone.dat'")
        f_row = cur.fetchone()
        file_id = f_row["file_id"]

        restore_dir = os.path.join(self.temp_dir, "Restored_Single")
        restored_path = self.net.download_file(file_id, restore_folder=restore_dir)

        self.assertTrue(os.path.exists(restored_path))
        with open(restored_path, "rb") as f:
            self.assertEqual(f.read(), file_content)

        # Test failure when expected hash is wrong
        with self.db.conn:
            self.db.conn.execute("UPDATE virtual_files SET file_hash = ? WHERE file_id = ?", ("d" * 64, file_id))

        with self.assertRaises(FileIntegrityError):
            self.net.download_file(file_id, restore_folder=restore_dir)


if __name__ == "__main__":
    unittest.main()

