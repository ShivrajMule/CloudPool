"""
Automated Test Suite for CloudPool Account Lifecycle & Database Integrity
Tests account unregistration, chunk reference tracing, safe disconnection,
foreign-key constraint enforcement, transaction atomicity, and rollback.
All tests run against isolated temporary SQLite databases.
"""

import os
import sys
import uuid
import sqlite3
import tempfile
import unittest

# Ensure CloudPool_Project is in path
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from core_engine import DatabaseEngine


class TestAccountLifecycle(unittest.TestCase):
    def setUp(self):
        """Create an isolated temporary SQLite database for each test."""
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db_path = self.temp_db_file.name
        self.db = DatabaseEngine(db_path=self.db_path)

    def tearDown(self):
        """Safely close connection and remove temporary database file."""
        try:
            self.db.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_empty_account_unregistration(self):
        """Test that an account with 0 chunks can be safely and cleanly unregistered."""
        acc_name = "Mock_Mega_Empty"
        self.db.register_account(acc_name, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=1)

        # Verify account is registered and has 0 chunks
        refs = self.db.get_account_references(acc_name)
        self.assertEqual(refs["chunks_count"], 0)
        self.assertEqual(refs["file_count"], 0)

        # Unregister the account
        success = self.db.unregister_account(acc_name)
        self.assertTrue(success)

        # Verify account no longer exists in database
        accounts = self.db.get_accounts()
        names = [a["account_name"] for a in accounts]
        self.assertNotIn(acc_name, names)

    def test_account_with_one_chunk(self):
        """Test that unregistering an account owning 1 chunk is strictly blocked."""
        acc_name = "Mock_OneDrive_OneChunk"
        self.db.register_account(acc_name, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE", priority=1)

        # Create a virtual file and assign 1 chunk to this account
        file_id = str(uuid.uuid4())
        cur = self.db.conn.cursor()
        with self.db.conn:
            cur.execute("""
                INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at)
                VALUES (?, 'document.pdf', 1048576, datetime('now'))
            """, (file_id,))
            cur.execute("""
                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity)
                VALUES ('chunk_001', ?, ?, 1, 1048576, 0)
            """, (file_id, acc_name))

        # Verify references are tracked
        refs = self.db.get_account_references(acc_name)
        self.assertEqual(refs["chunks_count"], 1)
        self.assertEqual(refs["file_count"], 1)
        self.assertIn("document.pdf", refs["file_names"])

        # Attempting unregistration MUST raise ValueError
        with self.assertRaises(ValueError) as ctx:
            self.db.unregister_account(acc_name)

        self.assertIn("Cannot unregister remote", str(ctx.exception))
        self.assertIn("1 stored chunk", str(ctx.exception))

        # Verify account and chunk metadata are 100% preserved
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (acc_name,))
        self.assertIsNotNone(cur.fetchone())
        cur.execute("SELECT chunk_id FROM file_chunks WHERE account_name = ?", (acc_name,))
        self.assertIsNotNone(cur.fetchone())

    def test_account_with_multiple_chunks(self):
        """Test that an account holding multiple data and parity chunks across files cannot be deleted."""
        acc_name = "Mock_GoogleDrive_Multi"
        self.db.register_account(acc_name, "Google Drive", raw_gb=15.0, buffer_gb=0.5, tier="STABLE", priority=2)

        file1_id = str(uuid.uuid4())
        file2_id = str(uuid.uuid4())
        cur = self.db.conn.cursor()
        with self.db.conn:
            cur.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'video.mp4', 50000000, datetime('now'))", (file1_id,))
            cur.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'archive.zip', 20000000, datetime('now'))", (file2_id,))
            
            # Insert 3 data chunks and 1 parity chunk on this remote
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c1', ?, ?, 1, 20971520, 0)", (file1_id, acc_name))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c2', ?, ?, 2, 20971520, 0)", (file1_id, acc_name))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c3', ?, ?, 9999, 20971520, 1)", (file1_id, acc_name))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c4', ?, ?, 1, 20000000, 0)", (file2_id, acc_name))

        refs = self.db.get_account_references(acc_name)
        self.assertEqual(refs["chunks_count"], 4)
        self.assertEqual(refs["file_count"], 2)
        self.assertIn("video.mp4", refs["file_names"])
        self.assertIn("archive.zip", refs["file_names"])

        # Attempt unregister -> must be rejected
        with self.assertRaises(ValueError) as ctx:
            self.db.unregister_account(acc_name)
        self.assertIn("4 stored chunk(s)", str(ctx.exception))

        # Confirm all 4 chunks remain in database
        cur.execute("SELECT COUNT(*) FROM file_chunks WHERE account_name = ?", (acc_name,))
        self.assertEqual(cur.fetchone()[0], 4)

    def test_disconnected_account(self):
        """Test safe disconnection of an account holding chunks, metadata preservation, and reconnection."""
        acc_name = "Mock_Box_Disconnect"
        self.db.register_account(acc_name, "Box", raw_gb=10.0, buffer_gb=0.0, tier="STABLE", priority=1)

        file_id = str(uuid.uuid4())
        cur = self.db.conn.cursor()
        with self.db.conn:
            cur.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'test.bin', 1000, datetime('now'))", (file_id,))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c_box', ?, ?, 1, 1000, 0)", (file_id, acc_name))

        # Safely disconnect account
        success = self.db.disconnect_account(acc_name)
        self.assertTrue(success)

        # Check account status is DISCONNECTED
        cur.execute("SELECT status FROM cloud_accounts WHERE account_name = ?", (acc_name,))
        self.assertEqual(cur.fetchone()["status"], "DISCONNECTED")

        # Verify active_only query excludes it
        active_accs = self.db.get_accounts(active_only=True)
        self.assertNotIn(acc_name, [a["account_name"] for a in active_accs])

        # Verify full get_accounts query includes it with status DISCONNECTED
        all_accs = self.db.get_accounts(active_only=False)
        match = next((a for a in all_accs if a["account_name"] == acc_name), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["status"], "DISCONNECTED")

        # Verify all chunk records remain 100% intact
        self.assertEqual(self.db.get_account_chunks_count(acc_name)["count"], 1)

        # Reconnect account
        recon_success = self.db.reconnect_account(acc_name)
        self.assertTrue(recon_success)
        cur.execute("SELECT status FROM cloud_accounts WHERE account_name = ?", (acc_name,))
        self.assertEqual(cur.fetchone()["status"], "CONNECTED")

    def test_account_with_orphaned_metadata(self):
        """Test that chunks without matching virtual_files rows still block unregistration."""
        acc_name = "Mock_Dropbox_Orphan"
        self.db.register_account(acc_name, "Dropbox", raw_gb=2.0, buffer_gb=0.0, tier="STABLE", priority=1)

        # Insert a chunk whose file_id is NOT in virtual_files (orphaned chunk metadata)
        orphan_file_id = str(uuid.uuid4())
        cur = self.db.conn.cursor()
        # Temporarily disable FK check only to create the orphaned chunk scenario for testing
        cur.execute("PRAGMA foreign_keys = OFF")
        cur.execute("""
            INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity)
            VALUES ('orphan_c1', ?, ?, 1, 512, 0)
        """, (orphan_file_id, acc_name))
        self.db.conn.commit()
        cur.execute("PRAGMA foreign_keys = ON")

        refs = self.db.get_account_references(acc_name)
        self.assertEqual(refs["chunks_count"], 1)
        self.assertIn(f"FileID:{orphan_file_id[:8]}", refs["file_names"])

        # Must still block unregistration
        with self.assertRaises(ValueError):
            self.db.unregister_account(acc_name)

    def test_foreign_key_constraint_enforcement(self):
        """Test that SQLite PRAGMA foreign_keys is strictly ON and blocks direct raw DELETE."""
        acc_name = "Mock_FK_Enforced"
        self.db.register_account(acc_name, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        # Verify foreign keys pragma is active
        cur = self.db.conn.cursor()
        cur.execute("PRAGMA foreign_keys")
        fk_status = cur.fetchone()[0]
        self.assertEqual(fk_status, 1, "PRAGMA foreign_keys must be 1 (enabled).")

        file_id = str(uuid.uuid4())
        with self.db.conn:
            cur.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'fk.dat', 100, datetime('now'))", (file_id,))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('fk_chunk', ?, ?, 1, 100, 0)", (file_id, acc_name))

        # A direct raw SQL DELETE bypassing unregister_account MUST trigger sqlite3.IntegrityError
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.conn:
                cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (acc_name,))

        # Verify account was not deleted
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (acc_name,))
        self.assertIsNotNone(cur.fetchone())

    def test_repeated_unregister_attempts(self):
        """Test that unregistering an already unregistered account raises ValueError cleanly without corruption."""
        acc_name = "Mock_Repeat"
        self.db.register_account(acc_name, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE")

        # First unregister succeeds
        self.assertTrue(self.db.unregister_account(acc_name))

        # Second unregister attempt raises ValueError
        with self.assertRaises(ValueError) as ctx:
            self.db.unregister_account(acc_name)
        self.assertIn("is not registered", str(ctx.exception))

    def test_database_rollback_on_failure(self):
        """Test that transactions roll back atomically on any failure."""
        acc1 = "Mock_Atomic_1"
        acc2 = "Mock_Atomic_2"
        self.db.register_account(acc1, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
        self.db.register_account(acc2, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        # Add a chunk to acc2
        file_id = str(uuid.uuid4())
        cur = self.db.conn.cursor()
        with self.db.conn:
            cur.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at) VALUES (?, 'roll.bin', 10, datetime('now'))", (file_id,))
            cur.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('c_roll', ?, ?, 1, 10, 0)", (file_id, acc2))

        # Execute a compound block that attempts to unregister acc1 and then fails on acc2
        try:
            with self.db.conn:
                cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (acc1,))
                # This will raise foreign key integrity error
                cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (acc2,))
        except sqlite3.IntegrityError:
            pass

        # Because transaction rolled back, acc1 MUST still be in cloud_accounts!
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (acc1,))
        self.assertIsNotNone(cur.fetchone(), "acc1 should be preserved due to transaction rollback.")

    def test_upload_routing_ignores_disconnected_account(self):
        """Test that NetworkEngine._get_eligible_account never selects a DISCONNECTED account."""
        from network_engine import NetworkEngine
        net = NetworkEngine()
        net.db = self.db  # Wire to isolated test database

        # Mock is_remote_in_rclone_config to return True for our test accounts
        self.db.is_remote_in_rclone_config = lambda name: True

        # Register two accounts: one disconnected (priority 1), one connected (priority 2)
        self.db.register_account("Acc_P1_Disc", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=1, status="DISCONNECTED")
        self.db.register_account("Acc_P2_Conn", "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE", priority=2, status="CONNECTED")

        # Query eligible account
        selected = net._get_eligible_account(1048576, tier="STABLE")
        self.assertIsNotNone(selected)
        # Even though Acc_P1_Disc has higher priority (P1 < P2), it MUST be skipped because it is DISCONNECTED!
        self.assertEqual(selected["account_name"], "Acc_P2_Conn")


if __name__ == "__main__":
    unittest.main(verbosity=2)
