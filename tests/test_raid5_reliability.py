"""
Automated Test Suite for CloudPool RAID-5 Parity Placement and Recovery Reliability
Covers TASK 08 Requirements:
- Mathematical bitwise XOR parity correctness across equal, unequal, empty, single, and multiple chunk files
- Strict failure-domain isolation: Parity must never be placed on the same cloud account as any data chunk
- Rejection of unprotected uploads when strict_parity is requested and N+1 accounts are unavailable
- Deterministic reconstruction for every single-chunk failure position (first, middle, last/unequal)
- Missing parity tolerance: surviving data chunks restore file without parity
- Parity corruption / tampering detection: corrupted parity fails safely
- Multiple chunk failures: correctly identifies unrecoverable data loss and never produces corrupted output
- Metadata accuracy: chunk lengths, ordering, and failure-domain placement
"""

import os
import io
import sys
import uuid
import shutil
import tempfile
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
    RAID5Engine,
    ParityPlacementError
)
from network_engine import NetworkEngine, CHUNK_SIZE


class MockPopen:
    """Deterministic in-memory mock for rclone subprocess operations."""
    def __init__(self, cmd, cloud_storage, failing_targets=None, corrupt_targets=None):
        self.cmd = cmd
        self.cloud_storage = cloud_storage
        self.failing_targets = failing_targets or set()
        self.corrupt_targets = corrupt_targets or set()
        self.pid = 88888
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
                    # Tamper with the ciphertext/tag bytes to simulate corruption
                    data = bytearray(data)
                    if len(data) > 20:
                        data[-5] ^= 0xFF
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


class TestRAID5EngineDirectMath(unittest.TestCase):
    """Direct mathematical unit tests for RAID5Engine XOR computation and reconstruction."""

    def test_xor_equal_sized_chunks(self):
        """Verifies XOR parity computation and recovery across equal-sized chunks."""
        c1 = os.urandom(1024)
        c2 = os.urandom(1024)
        c3 = os.urandom(1024)

        parity = RAID5Engine.compute_parity([c1, c2, c3])
        self.assertEqual(len(parity), 1024)

        # Recover c1
        rec_c1 = RAID5Engine.recover_missing_chunk([c2, c3], parity, 1024)
        self.assertEqual(rec_c1, c1)

        # Recover c2
        rec_c2 = RAID5Engine.recover_missing_chunk([c1, c3], parity, 1024)
        self.assertEqual(rec_c2, c2)

        # Recover c3
        rec_c3 = RAID5Engine.recover_missing_chunk([c1, c2], parity, 1024)
        self.assertEqual(rec_c3, c3)

    def test_xor_unequal_sized_chunks(self):
        """Verifies XOR parity computation and recovery when the final chunk is shorter."""
        c1 = os.urandom(2048)
        c2 = os.urandom(2048)
        c3 = os.urandom(512)  # Unequal partial chunk

        parity = RAID5Engine.compute_parity([c1, c2, c3])
        self.assertEqual(len(parity), 2048, "Parity block must match maximum chunk length")

        # Recover full-length chunk c1
        rec_c1 = RAID5Engine.recover_missing_chunk([c2, c3], parity, 2048)
        self.assertEqual(rec_c1, c1)

        # Recover partial-length chunk c3
        rec_c3 = RAID5Engine.recover_missing_chunk([c1, c2], parity, 512)
        self.assertEqual(rec_c3, c3)
        self.assertEqual(len(rec_c3), 512)

    def test_xor_single_chunk(self):
        """Single chunk file XOR parity equals the data chunk itself."""
        c1 = b"Single data chunk payload"
        parity = RAID5Engine.compute_parity([c1])
        self.assertEqual(parity, c1)

        rec_c1 = RAID5Engine.recover_missing_chunk([], parity, len(c1))
        self.assertEqual(rec_c1, c1)

    def test_xor_empty_chunk(self):
        """0-byte chunk parity computation and recovery."""
        parity = RAID5Engine.compute_parity([b""])
        self.assertEqual(parity, b"")

        rec = RAID5Engine.recover_missing_chunk([], parity, 0)
        self.assertEqual(rec, b"")

    def test_xor_large_buffers(self):
        """Verifies XOR computation on multi-megabyte buffers."""
        c1 = os.urandom(5 * 1024 * 1024)
        c2 = os.urandom(5 * 1024 * 1024)

        parity = RAID5Engine.compute_parity([c1, c2])
        self.assertEqual(len(parity), 5 * 1024 * 1024)

        rec_c1 = RAID5Engine.recover_missing_chunk([c2], parity, len(c1))
        self.assertEqual(rec_c1, c1)


class TestRAID5NetworkPipeline(unittest.TestCase):
    """End-to-end network pipeline tests for RAID-5 failure-domain isolation and recovery."""

    def setUp(self):
        self.rclone_patcher = patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
        self.rclone_patcher.start()

        self.test_dir = tempfile.mkdtemp(prefix="cpv_test_raid_")
        self.db_path = os.path.join(self.test_dir, "test_raid_master.db")
        self.db = DatabaseEngine(db_path=self.db_path)
        self.crypto = CryptoEngine()
        self.net = NetworkEngine(db=self.db, crypto=self.crypto)

        # Register 4 independent cloud accounts across priorities
        self.db.register_account("Cloud_A", "MEGA", raw_gb=50.0, buffer_gb=0.0, tier="STABLE", priority=1)
        self.db.register_account("Cloud_B", "Google Drive", raw_gb=50.0, buffer_gb=0.0, tier="STABLE", priority=1)
        self.db.register_account("Cloud_C", "OneDrive", raw_gb=50.0, buffer_gb=0.0, tier="STABLE", priority=2)
        self.db.register_account("Cloud_D", "Box", raw_gb=50.0, buffer_gb=0.0, tier="STABLE", priority=2)

        self.cloud_storage = {}
        self.failing_targets = set()
        self.corrupt_targets = set()

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

    def _mock_popen_factory(self):
        def _factory(cmd, *args, **kwargs):
            return MockPopen(
                cmd,
                self.cloud_storage,
                failing_targets=self.failing_targets,
                corrupt_targets=self.corrupt_targets
            )
        return _factory

    # 1. Failure-Domain Isolation Enforcement
    def test_failure_domain_isolation_strictly_enforced(self):
        """Verifies that parity chunk is NEVER stored on the same cloud account as any data chunk."""
        # Create a file that splits across 2 data chunks + 1 parity chunk
        data = os.urandom(int(CHUNK_SIZE * 1.5))
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="isolation_test.bin",
                enable_parity=True,
                strict_parity=True
            )

        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id, account_name, part_number, is_parity FROM file_chunks WHERE file_id = ?", (file_id,))
        rows = cur.fetchall()

        data_accounts = {r["account_name"] for r in rows if r["is_parity"] == 0}
        parity_rows = [r for r in rows if r["is_parity"] == 1]

        self.assertEqual(len(parity_rows), 1, "Exactly one parity chunk must be present")
        parity_account = parity_rows[0]["account_name"]

        self.assertNotIn(
            parity_account, data_accounts,
            f"FATAL: Parity account '{parity_account}' collides with data accounts {data_accounts}! Failure-domain isolation violated!"
        )

    def test_insufficient_accounts_for_parity_raises_parity_placement_error(self):
        """When N data chunks consume all available accounts, strict parity raises ParityPlacementError."""
        # Unregister accounts so only 1 account remains
        cur = self.db.conn.cursor()
        cur.execute("DELETE FROM cloud_accounts WHERE account_name IN ('Cloud_B', 'Cloud_C', 'Cloud_D')")
        self.db.conn.commit()

        # Upload a 1-chunk file with parity. Since only 1 account exists, parity cannot be placed on an independent account!
        data = b"TestDataNeedsIndependentParity"
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            with self.assertRaises(ParityPlacementError):
                self.net.upload_stream(
                    stream_obj=stream,
                    total_size=len(data),
                    file_name="fail_isolation.bin",
                    enable_parity=True,
                    strict_parity=True,
                    allow_unprotected_fallback=False
                )

    def test_unprotected_fallback_updates_metadata_honestly(self):
        """When allow_unprotected_fallback=True, parity is omitted and database does not falsely claim RAID."""
        cur = self.db.conn.cursor()
        cur.execute("DELETE FROM cloud_accounts WHERE account_name IN ('Cloud_B', 'Cloud_C', 'Cloud_D')")
        self.db.conn.commit()

        data = b"TestDataAllowsFallback"
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="fallback.bin",
                enable_parity=True,
                strict_parity=False,
                allow_unprotected_fallback=True
            )

        # Check file_chunks has 0 parity chunks
        cur.execute("SELECT COUNT(*) AS cnt FROM file_chunks WHERE file_id = ? AND is_parity = 1", (file_id,))
        self.assertEqual(cur.fetchone()["cnt"], 0, "No parity chunk should be recorded when omitted")

        # Check upload_journal has enable_parity = 0
        cur.execute("SELECT enable_parity FROM upload_journal WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["enable_parity"], 0, "Journal must honestly record enable_parity = 0")

    # 2. Reconstruction Across Every Possible Single-Chunk Failure Position
    def test_single_chunk_recovery_chunk_0_missing(self):
        """Recovers file when chunk 1 (part 1) is missing."""
        data = os.urandom(int(CHUNK_SIZE * 1.5))  # 2 data chunks: part 1 (20MB) + part 2 (10MB)
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="part1_missing.dat",
                enable_parity=True
            )

            # Get chunk_id and account for chunk 1
            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
            c1_row = cur.fetchone()
            target_remote = f"{c1_row['account_name']}:CloudPool_Vault/{c1_row['chunk_id']}.enc"
            self.failing_targets.add(target_remote)

            # Download should recover chunk 1 via RAID-5 XOR
            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), data, "Reconstructed file bytes did not match original!")

    def test_single_chunk_recovery_chunk_1_unequal_final_missing(self):
        """Recovers file when final partial chunk (part 2) is missing."""
        data = os.urandom(int(CHUNK_SIZE * 1.3))  # 2 data chunks: part 1 (20MB) + part 2 (6MB)
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="part2_missing.dat",
                enable_parity=True
            )

            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 2", (file_id,))
            c2_row = cur.fetchone()
            target_remote = f"{c2_row['account_name']}:CloudPool_Vault/{c2_row['chunk_id']}.enc"
            self.failing_targets.add(target_remote)

            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), data, "Reconstructed unequal final chunk did not match original!")

    def test_single_chunk_recovery_middle_chunk_missing(self):
        """Recovers file when a middle chunk (part 2 of 3) is missing."""
        data = os.urandom(int(CHUNK_SIZE * 2.2))  # 3 data chunks: part 1 (20MB), part 2 (20MB), part 3 (4MB)
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="part_mid_missing.dat",
                enable_parity=True
            )

            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 2", (file_id,))
            c_mid_row = cur.fetchone()
            target_remote = f"{c_mid_row['account_name']}:CloudPool_Vault/{c_mid_row['chunk_id']}.enc"
            self.failing_targets.add(target_remote)

            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), data, "Middle chunk reconstruction failed!")

    def test_single_data_chunk_file_missing_recovered_from_parity(self):
        """Recovers a single data chunk file when the single data chunk is missing."""
        data = b"Single data chunk with independent parity protection"
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="single_chunk_rec.txt",
                enable_parity=True
            )

            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
            c1_row = cur.fetchone()
            self.failing_targets.add(f"{c1_row['account_name']}:CloudPool_Vault/{c1_row['chunk_id']}.enc")

            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), data)

    def test_empty_file_with_parity_and_recovery(self):
        """Handles 0-byte file with parity and successful recovery."""
        data = b""
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=0,
                file_name="empty_parity.txt",
                enable_parity=True
            )

            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
            c1_row = cur.fetchone()
            self.failing_targets.add(f"{c1_row['account_name']}:CloudPool_Vault/{c1_row['chunk_id']}.enc")

            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), b"")

    # 3. Missing Parity Tolerance
    def test_missing_parity_does_not_block_healthy_download(self):
        """If all data chunks are intact, a missing parity block does not prevent successful download."""
        data = b"HealthyDataChunksPresent"
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="missing_parity.txt",
                enable_parity=True
            )

            # Mark parity chunk as failing
            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND is_parity = 1", (file_id,))
            par_row = cur.fetchone()
            self.failing_targets.add(f"{par_row['account_name']}:CloudPool_Vault/{par_row['chunk_id']}.enc")

            # Download should succeed without needing parity
            restored_stream = self.net._download_chunks_to_bytes(file_id)
            self.assertEqual(restored_stream.getvalue(), data)

    # 4. Parity Corruption / Tampering
    def test_corrupted_parity_fails_safely_when_needed(self):
        """When a data chunk is missing and the parity block is tampered with, download fails safely."""
        data = b"TestDataForCorruptParity"
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="corrupt_parity.txt",
                enable_parity=True
            )

            # Make chunk 1 missing and parity corrupted
            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number = 1", (file_id,))
            c1_row = cur.fetchone()
            self.failing_targets.add(f"{c1_row['account_name']}:CloudPool_Vault/{c1_row['chunk_id']}.enc")

            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND is_parity = 1", (file_id,))
            par_row = cur.fetchone()
            self.corrupt_targets.add(f"{par_row['account_name']}:CloudPool_Vault/{par_row['chunk_id']}.enc")

            with self.assertRaises(Exception) as cm:
                self.net._download_chunks_to_bytes(file_id)
            self.assertIn("parity block unavailable/corrupted", str(cm.exception).lower())

    # 5. Multiple Failures (Protection Exceeded)
    def test_multiple_missing_chunks_fails_safely_never_corrupted(self):
        """When 2 data chunks fail in single-parity RAID-5, download safely raises unrecoverable error."""
        data = os.urandom(int(CHUNK_SIZE * 2.5))  # 3 data chunks
        stream = io.BytesIO(data)

        with patch("subprocess.Popen", side_effect=self._mock_popen_factory()):
            file_id = self.net.upload_stream(
                stream_obj=stream,
                total_size=len(data),
                file_name="two_missing.bin",
                enable_parity=True
            )

            # Fail both chunk 1 and chunk 2
            cur = self.db.conn.cursor()
            cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ? AND part_number IN (1, 2)", (file_id,))
            for row in cur.fetchall():
                self.failing_targets.add(f"{row['account_name']}:CloudPool_Vault/{row['chunk_id']}.enc")

            with self.assertRaises(Exception) as cm:
                self.net._download_chunks_to_bytes(file_id)
            self.assertIn("single-parity raid-5 protection exceeded", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()

