"""
TASK 14: CloudPool Accurate Storage Accounting and Quota Management Tests.
Tests:
- 28-byte nonce + auth tag AES-256-GCM overhead accounting.
- RAID-5 parity chunk storage accounting.
- Container archive overhead tracking.
- Negative counter prevention (MAX(0, used_bytes - ?)).
- Storage counter reconciliation (reconcile_storage_counters).
- Database migration v2 -> v3 and backfill of encrypted_size_bytes.
- Granular storage pool metrics in get_pool_summary.
- Authoritative cloud provider quota sync (rclone about) and graceful fallbacks.
"""

import io
import json
import os
import sys
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core_engine import (
    DatabaseEngine,
    CryptoEngine,
    format_bytes
)
from network_engine import NetworkEngine, UploadRetryPolicy


class StorageAccountingTestCase(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cp_storage_test_")
        self.db_path = os.path.join(self.test_dir, "test_cloudpool.db")
        self.conf_path = os.path.join(self.test_dir, "rclone.conf")

        with open(self.conf_path, "w") as f:
            f.write("[Remote_Alpha]\ntype = drive\n\n[Remote_Beta]\ntype = mega\n\n[Remote_Gamma]\ntype = onedrive\n")

        self.rclone_patch = patch.dict(os.environ, {"APPDATA": self.test_dir})
        self.rclone_patch.start()

        self.rclone_dir = os.path.join(self.test_dir, "rclone")
        os.makedirs(self.rclone_dir, exist_ok=True)
        shutil.copy2(self.conf_path, os.path.join(self.rclone_dir, "rclone.conf"))

        self.db = DatabaseEngine(self.db_path)
        self.crypto = CryptoEngine()
        self.net = NetworkEngine(self.db, self.crypto)

        # Register accounts
        self.db.register_account("Remote_Alpha", "Google Drive", raw_gb=15.0, buffer_gb=0.0, tier="STABLE", priority=1)
        self.db.register_account("Remote_Beta", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=2)
        self.db.register_account("Remote_Gamma", "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE", priority=3)

    def tearDown(self):
        self.rclone_patch.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _mock_popen_success(self):
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_proc.poll.return_value = None
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.stdin = MagicMock()
        return mock_proc

    # ------------------------------------------------------------------
    # 1. Nonce & Tag Overhead Accounting (28 Bytes per chunk)
    # ------------------------------------------------------------------

    @patch("subprocess.Popen")
    def test_nonce_and_auth_tag_overhead_accounting(self, mock_popen):
        """Verifies remote chunk size accurately adds 28 bytes (12B nonce + 16B tag) in file_chunks & used_bytes."""
        mock_popen.return_value = self._mock_popen_success()

        # 100-byte plaintext payload
        plaintext = b"A" * 100
        stream = io.BytesIO(plaintext)

        file_id = self.net.upload_stream(
            stream_obj=stream,
            total_size=100,
            file_name="test_100b.txt",
            target_tier="STABLE",
            enable_parity=False,
            defer_metadata_sync=True
        )

        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id, account_name, chunk_size_bytes, encrypted_size_bytes FROM file_chunks WHERE file_id = ?", (file_id,))
        rows = cur.fetchall()
        self.assertEqual(len(rows), 1)

        row = rows[0]
        # Plaintext length is 100
        self.assertEqual(row["chunk_size_bytes"], 100)
        # Encrypted ciphertext on remote is exactly 100 + 28 = 128 bytes
        self.assertEqual(row["encrypted_size_bytes"], 128)

        # Account used_bytes must be 128, NOT 100
        acc = self.db.get_account(row["account_name"])
        self.assertEqual(acc["used_bytes"], 128)

        # Upload journal chunk should also track encrypted_size_bytes
        cur.execute("SELECT chunk_size_bytes, encrypted_size_bytes FROM upload_journal_chunks WHERE chunk_id = ?", (row["chunk_id"],))
        uj_row = cur.fetchone()
        self.assertIsNotNone(uj_row)
        self.assertEqual(uj_row["encrypted_size_bytes"], 128)

    # ------------------------------------------------------------------
    # 2. RAID-5 Parity Chunk Storage Accounting
    # ------------------------------------------------------------------

    @patch("subprocess.Popen")
    def test_parity_chunk_storage_accounting(self, mock_popen):
        """Verifies RAID-5 parity blocks account for ciphertext overhead and increment remote used_bytes."""
        mock_popen.return_value = self._mock_popen_success()

        plaintext = b"B" * 250
        stream = io.BytesIO(plaintext)

        file_id = self.net.upload_stream(
            stream_obj=stream,
            total_size=250,
            file_name="parity_test.bin",
            target_tier="STABLE",
            enable_parity=True,
            defer_metadata_sync=True
        )

        cur = self.db.conn.cursor()
        cur.execute("SELECT chunk_id, account_name, chunk_size_bytes, encrypted_size_bytes, is_parity FROM file_chunks WHERE file_id = ?", (file_id,))
        chunks = cur.fetchall()
        self.assertEqual(len(chunks), 2)  # 1 data chunk + 1 parity chunk

        data_chunk = next(c for c in chunks if c["is_parity"] == 0)
        parity_chunk = next(c for c in chunks if c["is_parity"] == 1)

        self.assertEqual(data_chunk["chunk_size_bytes"], 250)
        self.assertEqual(data_chunk["encrypted_size_bytes"], 278)

        self.assertEqual(parity_chunk["chunk_size_bytes"], 250)
        self.assertEqual(parity_chunk["encrypted_size_bytes"], 278)

        # Total remote bytes accounted for across the accounts
        total_used = sum(a["used_bytes"] for a in self.db.get_accounts())
        self.assertEqual(total_used, 278 + 278)

    # ------------------------------------------------------------------
    # 3. Negative Counter Prevention via MAX(0, used_bytes - ?)
    # ------------------------------------------------------------------

    def test_negative_counter_prevention(self):
        """Verifies delete_chunk_record_atomic prevents negative storage counters even on underflow."""
        cur = self.db.conn.cursor()
        cur.execute("UPDATE cloud_accounts SET used_bytes = 50 WHERE account_name = 'Remote_Alpha'")
        self.db.conn.commit()

        # Insert a dummy chunk
        cur.execute("""
            INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at)
            VALUES ('f_neg', 'dummy.dat', 100, datetime('now'))
        """)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes)
            VALUES ('c_neg', 'f_neg', 'Remote_Alpha', 1, 100, 128)
        """)
        self.db.conn.commit()

        # Deduct 128 bytes when current used_bytes is only 50
        self.db.delete_chunk_record_atomic("f_neg", "c_neg", "Remote_Alpha", 100, encrypted_size_bytes=128)

        acc = self.db.get_account("Remote_Alpha")
        self.assertEqual(acc["used_bytes"], 0)
        self.assertGreaterEqual(acc["used_bytes"], 0)

    # ------------------------------------------------------------------
    # 4. Storage Counter Reconciliation
    # ------------------------------------------------------------------

    def test_reconcile_storage_counters(self):
        """Verifies reconcile_storage_counters restores accurate encrypted sums after drift or crash."""
        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at)
            VALUES ('f_drift', 'drift.dat', 1000, datetime('now'))
        """)
        # 2 chunks on Remote_Alpha: (500 + 28) + (500 + 28) = 1056 bytes
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes)
            VALUES ('c_drift1', 'f_drift', 'Remote_Alpha', 1, 500, 528)
        """)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes)
            VALUES ('c_drift2', 'f_drift', 'Remote_Alpha', 2, 500, 528)
        """)
        # Manually corrupt used_bytes
        cur.execute("UPDATE cloud_accounts SET used_bytes = 999999 WHERE account_name = 'Remote_Alpha'")
        cur.execute("UPDATE cloud_accounts SET used_bytes = 888888 WHERE account_name = 'Remote_Beta'")
        self.db.conn.commit()

        self.db.reconcile_storage_counters()

        alpha = self.db.get_account("Remote_Alpha")
        beta = self.db.get_account("Remote_Beta")
        self.assertEqual(alpha["used_bytes"], 1056)
        self.assertEqual(beta["used_bytes"], 0)

    # ------------------------------------------------------------------
    # 5. Schema Migration V2 -> V3 Backfill
    # ------------------------------------------------------------------

    def test_migration_v2_to_v3_backfill(self):
        """Simulates migrating a pre-v3 database: backfills encrypted_size_bytes and updates schema version."""
        tmp = tempfile.mkdtemp()
        try:
            v2_db_path = os.path.join(tmp, "v2_test.db")
            # First initialize full schema
            initial_db = DatabaseEngine(v2_db_path)
            conn = initial_db.conn

            # Register account and chunk with pre-v3 zero encrypted_size_bytes
            initial_db.register_account("Test_Acc", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
            conn.execute("INSERT INTO virtual_files VALUES ('vf_1', 'file.bin', 1000, '2026-01-01', NULL, NULL, 0, NULL, 'active', 'completed', NULL, 'SHA-256', 'unverified')")
            conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes) VALUES ('chk_1', 'vf_1', 'Test_Acc', 1, 1000, 0)")
            conn.execute("UPDATE cloud_accounts SET used_bytes = 1000 WHERE account_name = 'Test_Acc'")
            
            # Roll user_version back to 2 and remove version 3 migration record
            conn.execute("PRAGMA user_version = 2")
            conn.execute("DELETE FROM schema_migrations WHERE version >= 3")
            conn.commit()

            # Now instantiate DatabaseEngine: it must run _migrate_v2_to_v3
            migrated_db = DatabaseEngine(v2_db_path)
            cur = migrated_db.conn.cursor()

            version = cur.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, 3)

            # Check backfill in file_chunks: 1000 + 28 = 1028
            chk = cur.execute("SELECT encrypted_size_bytes FROM file_chunks WHERE chunk_id = 'chk_1'").fetchone()
            self.assertEqual(chk["encrypted_size_bytes"], 1028)

            # Check cloud_accounts quota updated to 1028
            acc = cur.execute("SELECT used_bytes FROM cloud_accounts WHERE account_name = 'Test_Acc'").fetchone()
            self.assertEqual(acc["used_bytes"], 1028)

            # Check schema_migrations audit entry
            versions = [r[0] for r in cur.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
            self.assertEqual(versions, [1, 2, 3])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ------------------------------------------------------------------
    # 6. Granular Storage Pool Metrics in get_pool_summary
    # ------------------------------------------------------------------

    def test_granular_pool_summary_metrics(self):
        """Verifies get_pool_summary returns detailed logical, data, parity, and overhead breakdown."""
        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status, is_container)
            VALUES ('f_sum1', 'doc.pdf', 2000, datetime('now'), 'completed', 0)
        """)
        # 1 data chunk (2000 plaintext + 28 overhead = 2028 enc)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity)
            VALUES ('c_data1', 'f_sum1', 'Remote_Alpha', 1, 2000, 2028, 0)
        """)
        # 1 parity chunk (2000 plaintext + 28 overhead = 2028 enc)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity)
            VALUES ('c_par1', 'f_sum1', 'Remote_Beta', 9999, 2000, 2028, 1)
        """)
        cur.execute("UPDATE cloud_accounts SET used_bytes = 2028 WHERE account_name = 'Remote_Alpha'")
        cur.execute("UPDATE cloud_accounts SET used_bytes = 2028 WHERE account_name = 'Remote_Beta'")
        self.db.conn.commit()

        summary = self.db.get_pool_summary()

        # Plaintext user files
        self.assertEqual(summary["logical_bytes"], 2000)
        # Plaintext data chunks
        self.assertEqual(summary["data_bytes"], 2000)
        # Plaintext parity chunks
        self.assertEqual(summary["parity_bytes"], 2000)
        # Total remote used = 2028 + 2028 = 4056
        self.assertEqual(summary["total_used"], 4056)
        # Overhead = total_used - data_bytes = 4056 - 2000 = 2056 bytes (parity + tags)
        self.assertEqual(summary["overhead_bytes"], 2056)
        # Total chunks = 2
        self.assertEqual(summary["total_chunks"], 2)
        # Free bytes
        self.assertEqual(summary["free_bytes"], summary["total_usable"] - summary["total_used"])

    # ------------------------------------------------------------------
    # 7. Cloud Provider Quota Sync (rclone about)
    # ------------------------------------------------------------------

    @patch("subprocess.run")
    def test_provider_quota_sync_success(self, mock_run):
        """Verifies sync_provider_quota parses 'rclone about' JSON and updates DB."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = json.dumps({
            "total": 16106127360,
            "used": 5368709120,
            "free": 10737418240
        })
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        results = self.db.sync_provider_quota("Remote_Alpha")
        self.assertIn("Remote_Alpha", results)
        self.assertEqual(results["Remote_Alpha"]["status"], "synced")
        self.assertEqual(results["Remote_Alpha"]["provider_total"], 16106127360)
        self.assertEqual(results["Remote_Alpha"]["provider_used"], 5368709120)

        acc = self.db.get_account("Remote_Alpha")
        self.assertEqual(acc["provider_total_bytes"], 16106127360)
        self.assertEqual(acc["provider_used_bytes"], 5368709120)
        self.assertIsNotNone(acc["last_sync_time"])

    @patch("subprocess.run")
    def test_provider_quota_sync_unsupported(self, mock_run):
        """Verifies sync_provider_quota handles remotes where 'about' is unsupported without crashing."""
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stdout = ""
        mock_res.stderr = "Command about not supported by this remote"
        mock_run.return_value = mock_res

        results = self.db.sync_provider_quota("Remote_Beta")
        self.assertIn("Remote_Beta", results)
        self.assertEqual(results["Remote_Beta"]["status"], "unsupported")
        self.assertIsNone(results["Remote_Beta"]["provider_total"])

        # DB should still be intact and queryable
        acc = self.db.get_account("Remote_Beta")
        self.assertIsNone(acc["provider_total_bytes"])

    @patch("subprocess.run")
    def test_provider_quota_sync_offline_or_error(self, mock_run):
        """Verifies sync_provider_quota handles offline remotes or network timeouts gracefully."""
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stdout = ""
        mock_res.stderr = "Failed to about: connection refused"
        mock_run.return_value = mock_res

        results = self.db.sync_provider_quota("Remote_Gamma")
        self.assertIn("Remote_Gamma", results)
        self.assertEqual(results["Remote_Gamma"]["status"], "offline")

    # ------------------------------------------------------------------
    # 8. Deletion Quota Roundtrip Accuracy
    # ------------------------------------------------------------------

    @patch("subprocess.Popen")
    def test_deletion_quota_reconciliation_exact(self, mock_popen):
        """Verifies deleting chunks deducts exact encrypted size and restores account quota to baseline."""
        mock_popen.return_value = self._mock_popen_success()

        init_used = sum(a["used_bytes"] for a in self.db.get_accounts())
        self.assertEqual(init_used, 0)

        # Upload a 500-byte file without parity
        stream = io.BytesIO(b"Z" * 500)
        file_id = self.net.upload_stream(
            stream_obj=stream,
            total_size=500,
            file_name="roundtrip.bin",
            target_tier="STABLE",
            enable_parity=False,
            defer_metadata_sync=True
        )

        after_upload = sum(a["used_bytes"] for a in self.db.get_accounts())
        self.assertEqual(after_upload, 528)  # 500 + 28

        # Delete the file
        res = self.net.delete_file(file_id)
        self.assertEqual(res["status"], "completed")

        after_delete = sum(a["used_bytes"] for a in self.db.get_accounts())
        self.assertEqual(after_delete, 0)

    # ------------------------------------------------------------------
    # 9. Detailed get_account_chunks_count Metrics
    # ------------------------------------------------------------------

    def test_get_account_chunks_count_detailed(self):
        """Verifies get_account_chunks_count returns count, plaintext bytes, and encrypted bytes."""
        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at)
            VALUES ('f_stat', 'stats.bin', 100, datetime('now'))
        """)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes)
            VALUES ('c_stat1', 'f_stat', 'Remote_Alpha', 1, 100, 128)
        """)
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes)
            VALUES ('c_stat2', 'f_stat', 'Remote_Alpha', 2, 200, 228)
        """)
        self.db.conn.commit()

        stats = self.db.get_account_chunks_count("Remote_Alpha")
        self.assertEqual(stats["count"], 2)
        self.assertEqual(stats["bytes"], 300)
        self.assertEqual(stats["encrypted_bytes"], 356)


if __name__ == "__main__":
    unittest.main()
