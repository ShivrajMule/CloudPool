"""
TASK 12: CloudPool SQLite Concurrency, Transactions & Schema Migration Tests
Tests thread safety, WAL mode, schema versioning, backup/restore validation.
"""
import os
import sys
import time
import uuid
import shutil
import tempfile
import sqlite3
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core_engine import DatabaseEngine


def fresh_db():
    """Returns a DatabaseEngine backed by a fresh temporary SQLite file."""
    tmp_dir = tempfile.mkdtemp()
    db = DatabaseEngine(os.path.join(tmp_dir, "test.db"))
    return db, tmp_dir


class TestSchemaVersioning(unittest.TestCase):
    """Schema migration and version tracking."""

    def test_schema_version_is_current(self):
        db, tmp = fresh_db()
        try:
            version = db.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, DatabaseEngine.SCHEMA_VERSION)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_all_expected_tables_exist(self):
        db, tmp = fresh_db()
        try:
            tables = {r[0] for r in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            required = {
                "cloud_accounts", "virtual_folders", "virtual_files",
                "file_chunks", "deletion_jobs", "upload_journal",
                "upload_journal_chunks", "folder_upload_journal",
                "schema_migrations",
            }
            self.assertTrue(required.issubset(tables),
                            f"Missing tables: {required - tables}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_schema_migrations_table_has_entries(self):
        db, tmp = fresh_db()
        try:
            rows = db.conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            versions = [r[0] for r in rows]
            self.assertEqual(versions, [1, 2, 3])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_indexes_created(self):
        db, tmp = fresh_db()
        try:
            indexes = {r[0] for r in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
            expected = {
                "idx_file_chunks_file_id",
                "idx_file_chunks_account",
                "idx_virtual_files_folder",
                "idx_upload_journal_status",
                "idx_deletion_jobs_status",
            }
            self.assertTrue(expected.issubset(indexes),
                            f"Missing indexes: {expected - indexes}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_migration_idempotent_on_reinit(self):
        """Re-creating DatabaseEngine on the same DB should not raise or change version."""
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "idempotent.db")
            db1 = DatabaseEngine(path)
            v1 = db1.conn.execute("PRAGMA user_version").fetchone()[0]

            db2 = DatabaseEngine(path)
            v2 = db2.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(v1, v2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_existing_db_without_user_version_migrates_cleanly(self):
        """
        Simulate an older database (user_version=0) that pre-dates schema
        versioning; _run_migrations should bring it up to SCHEMA_VERSION.
        """
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "old.db")
        try:
            # Create a minimal legacy database that already has the core tables
            # but user_version = 0 (never had schema versioning).
            conn = sqlite3.connect(path)
            conn.execute("""
                CREATE TABLE cloud_accounts (
                    account_name TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    usable_capacity_bytes INTEGER NOT NULL,
                    used_bytes INTEGER DEFAULT 0,
                    reliability_tier TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE virtual_files (
                    file_id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    uploaded_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE virtual_folders (
                    folder_id TEXT PRIMARY KEY,
                    folder_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE file_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    part_number INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE deletion_jobs (
                    job_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    deleted_chunks INTEGER DEFAULT 0,
                    failed_chunks INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE upload_journal (
                    op_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    total_expected_chunks INTEGER NOT NULL,
                    data_chunks_count INTEGER NOT NULL,
                    status TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE upload_journal_chunks (
                    op_id TEXT NOT NULL,
                    chunk_id TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    part_number INTEGER NOT NULL,
                    chunk_size_bytes INTEGER NOT NULL,
                    status TEXT,
                    PRIMARY KEY (op_id, chunk_id)
                )
            """)
            conn.execute("""
                CREATE TABLE folder_upload_journal (
                    folder_op_id TEXT PRIMARY KEY,
                    root_folder_name TEXT NOT NULL,
                    container_id TEXT NOT NULL,
                    total_files INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    status TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("PRAGMA user_version = 0")
            conn.commit()
            conn.close()

            # DatabaseEngine should migrate without error
            db = DatabaseEngine(path)
            new_version = db.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(new_version, DatabaseEngine.SCHEMA_VERSION)

            # New columns should have been added to existing tables
            cols_vf = {c[1] for c in db.conn.execute("PRAGMA table_info(virtual_files)").fetchall()}
            self.assertIn("file_hash", cols_vf)
            self.assertIn("integrity_status", cols_vf)

            cols_fc = {c[1] for c in db.conn.execute("PRAGMA table_info(file_chunks)").fetchall()}
            self.assertIn("ciphertext_hash", cols_fc)
            self.assertIn("is_parity", cols_fc)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestConnectionConfiguration(unittest.TestCase):
    """WAL mode, foreign keys, busy timeout."""

    def test_wal_mode_enabled(self):
        db, tmp = fresh_db()
        try:
            mode = db.conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(mode.lower(), "wal")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_foreign_keys_enforced(self):
        db, tmp = fresh_db()
        try:
            fk = db.conn.execute("PRAGMA foreign_keys").fetchone()[0]
            self.assertEqual(fk, 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_thread_local_connections_are_distinct(self):
        """Each thread must receive its own independent connection object."""
        db, tmp = fresh_db()
        connections = {}
        barrier = threading.Barrier(3)

        def worker(name):
            c = db._get_conn()
            connections[name] = id(c)
            barrier.wait()

        threads = [threading.Thread(target=worker, args=(f"T{i}",)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        try:
            conn_ids = list(connections.values())
            self.assertEqual(len(set(conn_ids)), 3,
                             "All three threads should have distinct connection objects")

            main_id = id(db._get_conn())
            for tid, cid in connections.items():
                self.assertNotEqual(cid, main_id,
                                    f"Thread {tid} connection should differ from main thread's connection")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_worker_thread_has_wal_and_foreign_keys(self):
        """Thread-local connections must also have WAL and FK enabled."""
        db, tmp = fresh_db()
        results = {}

        def worker():
            conn = db._get_conn()
            results["journal_mode"] = conn.execute("PRAGMA journal_mode").fetchone()[0]
            results["foreign_keys"] = conn.execute("PRAGMA foreign_keys").fetchone()[0]

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        try:
            self.assertEqual(results["journal_mode"].lower(), "wal")
            self.assertEqual(results["foreign_keys"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestConcurrentAccess(unittest.TestCase):
    """Concurrent reads and writes must not corrupt data or deadlock."""

    def _make_account(self, db, name="Acct_A"):
        db.register_account(name, "MEGA", raw_gb=20.0, buffer_gb=0.0,
                            tier="STABLE", priority=1)

    def test_concurrent_reads_do_not_block_each_other(self):
        """Multiple threads should be able to read simultaneously (WAL guarantee)."""
        db, tmp = fresh_db()
        self._make_account(db)
        errors = []
        barrier = threading.Barrier(5)

        def reader():
            try:
                barrier.wait()
                for _ in range(20):
                    db.get_accounts()
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        try:
            self.assertEqual(errors, [], f"Concurrent read errors: {errors}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_concurrent_writes_serialize_safely(self):
        """
        Multiple threads writing distinct account names simultaneously must
        all succeed without data loss or corruption.
        """
        db, tmp = fresh_db()
        errors = []
        barrier = threading.Barrier(10)

        def writer(idx):
            try:
                barrier.wait()
                db.register_account(
                    f"Acct_{idx}", "Google Drive",
                    raw_gb=15.0, buffer_gb=0.5,
                    tier="STABLE", priority=idx
                )
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        try:
            self.assertEqual(errors, [], f"Concurrent write errors: {errors}")
            accounts = db.get_accounts()
            self.assertEqual(len(accounts), 10,
                             f"Expected 10 accounts, got {len(accounts)}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_concurrent_reads_and_write_do_not_corrupt(self):
        """Readers and a single writer running concurrently must not raise or corrupt."""
        db, tmp = fresh_db()
        self._make_account(db)
        errors = []
        stop_event = threading.Event()

        def continuous_reader():
            while not stop_event.is_set():
                try:
                    db.get_pool_summary()
                except Exception as exc:
                    errors.append(f"reader: {exc}")
                    break

        def continuous_writer():
            for i in range(5):
                try:
                    db.register_account(
                        f"Acct_W{i}", "OneDrive",
                        raw_gb=5.0, buffer_gb=0.0,
                        tier="STABLE", priority=i + 10
                    )
                    time.sleep(0.01)
                except Exception as exc:
                    errors.append(f"writer: {exc}")
                    break
            stop_event.set()

        readers = [threading.Thread(target=continuous_reader) for _ in range(4)]
        writer = threading.Thread(target=continuous_writer)
        for r in readers:
            r.start()
        writer.start()
        writer.join(timeout=10)
        stop_event.set()
        for r in readers:
            r.join(timeout=5)

        try:
            self.assertEqual(errors, [], f"Concurrent r/w errors: {errors}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestBackupAndRestore(unittest.TestCase):
    """Database backup creation and validated restoration."""

    def test_backup_creates_readable_sqlite_file(self):
        db, tmp = fresh_db()
        backup_path = os.path.join(tmp, "backup.db")
        try:
            result = db.backup_database(backup_path)
            self.assertEqual(result, backup_path)
            self.assertTrue(os.path.exists(backup_path))
            # Validate it's a real SQLite database
            test_conn = sqlite3.connect(backup_path)
            check = test_conn.execute("PRAGMA integrity_check").fetchone()[0]
            test_conn.close()
            self.assertEqual(check.lower(), "ok")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_backup_preserves_data(self):
        db, tmp = fresh_db()
        backup_path = os.path.join(tmp, "backup.db")
        try:
            db.register_account("GDrive_1", "Google Drive", raw_gb=15.0,
                                buffer_gb=0.5, tier="STABLE")
            db.backup_database(backup_path)

            test_conn = sqlite3.connect(backup_path)
            test_conn.row_factory = sqlite3.Row
            rows = test_conn.execute("SELECT account_name FROM cloud_accounts").fetchall()
            test_conn.close()
            names = [r["account_name"] for r in rows]
            self.assertIn("GDrive_1", names)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_backup_to_same_path_raises(self):
        db, tmp = fresh_db()
        try:
            with self.assertRaises(ValueError):
                db.backup_database(db.db_path)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_restore_from_valid_backup_succeeds(self):
        db, tmp = fresh_db()
        backup_path = os.path.join(tmp, "backup.db")
        try:
            db.register_account("Original_Acct", "MEGA", raw_gb=20.0,
                                buffer_gb=0.0, tier="STABLE")
            db.backup_database(backup_path)

            # Add another account after backup (should disappear after restore)
            db.register_account("Post_Backup_Acct", "Box", raw_gb=10.0,
                                buffer_gb=0.0, tier="STABLE")
            accounts_before_restore = {a["account_name"] for a in db.get_accounts()}
            self.assertIn("Post_Backup_Acct", accounts_before_restore)

            db.restore_database(backup_path)

            accounts_after_restore = {a["account_name"] for a in db.get_accounts()}
            self.assertIn("Original_Acct", accounts_after_restore)
            self.assertNotIn("Post_Backup_Acct", accounts_after_restore)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_restore_from_nonexistent_backup_raises(self):
        db, tmp = fresh_db()
        try:
            with self.assertRaises(FileNotFoundError):
                db.restore_database(os.path.join(tmp, "nonexistent.db"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_restore_from_corrupt_file_raises_and_preserves_live_db(self):
        db, tmp = fresh_db()
        try:
            db.register_account("SafeAcct", "MEGA", raw_gb=20.0,
                                buffer_gb=0.0, tier="STABLE")
            corrupt_path = os.path.join(tmp, "corrupt.db")
            with open(corrupt_path, "wb") as f:
                f.write(b"THIS IS NOT A SQLITE DATABASE --- CORRUPT DATA HERE")

            with self.assertRaises(RuntimeError):
                db.restore_database(corrupt_path)

            # Live database must still be intact
            accounts = {a["account_name"] for a in db.get_accounts()}
            self.assertIn("SafeAcct", accounts)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_validate_database_file_rejects_non_sqlite(self):
        tmp = tempfile.mkdtemp()
        try:
            fake_path = os.path.join(tmp, "fake.db")
            with open(fake_path, "wb") as f:
                f.write(b"\x00" * 500)
            with self.assertRaises(RuntimeError):
                DatabaseEngine._validate_database_file(fake_path)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_validate_database_file_accepts_valid_sqlite(self):
        tmp = tempfile.mkdtemp()
        try:
            valid_path = os.path.join(tmp, "valid.db")
            conn = sqlite3.connect(valid_path)
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.commit()
            conn.close()
            # Should not raise
            DatabaseEngine._validate_database_file(valid_path)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


    def test_restore_from_same_path_raises(self):
        """Restoring onto the exact same live database path should raise ValueError."""
        db, tmp = fresh_db()
        try:
            with self.assertRaises(ValueError):
                db.restore_database(db.db_path)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_migration_failure_rollback(self):
        """A failing migration step must roll back atomically and preserve schema version & data."""
        db, tmp = fresh_db()
        try:
            # Register an account to verify data survival
            db.register_account("Surviving_Account", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")
            initial_version = db.conn.execute("PRAGMA user_version").fetchone()[0]

            def failing_migration_v4(conn):
                conn.execute("CREATE TABLE partial_table_fail (id INTEGER PRIMARY KEY)")
                raise RuntimeError("Deliberate disk/schema corruption simulation")

            # Temporarily patch migrations list in _run_migrations
            original_run = db._run_migrations
            def patched_run_migrations(conn):
                cur = conn.execute("PRAGMA user_version")
                curr = cur.fetchone()[0]
                migrations = [
                    db._migrate_v0_to_v1,
                    db._migrate_v1_to_v2,
                    db._migrate_v2_to_v3,
                    failing_migration_v4,
                ]
                for step_idx, fn in enumerate(migrations):
                    target_ver = step_idx + 1
                    if curr >= target_ver:
                        continue
                    try:
                        conn.execute("BEGIN")
                        fn(conn)
                        conn.execute(f"PRAGMA user_version = {target_ver}")
                        conn.execute("COMMIT")
                        curr = target_ver
                    except Exception as exc:
                        try:
                            conn.execute("ROLLBACK")
                        except Exception:
                            pass
                        raise RuntimeError(f"Failed upgrading: {exc}") from exc

            # Running migration should fail
            conn = db._get_conn()
            with self.assertRaises(RuntimeError):
                patched_run_migrations(conn)

            # user_version must not have advanced
            ver_after = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(ver_after, initial_version)

            # partial_table_fail must have been rolled back
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertNotIn("partial_table_fail", tables)

            # Pre-existing data must still exist intact
            accounts = {a["account_name"] for a in db.get_accounts()}
            self.assertIn("Surviving_Account", accounts)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_migration_preserves_existing_data(self):
        """Migrating from an unversioned baseline must preserve all pre-existing records."""
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "preserve_data.db")
        try:
            conn = sqlite3.connect(path)
            conn.execute("""
                CREATE TABLE cloud_accounts (
                    account_name TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    usable_capacity_bytes INTEGER NOT NULL,
                    used_bytes INTEGER DEFAULT 0,
                    reliability_tier TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE virtual_files (
                    file_id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    uploaded_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE file_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    part_number INTEGER NOT NULL,
                    chunk_size_bytes INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                INSERT INTO cloud_accounts (account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier)
                VALUES ('ExistingMega', 'MEGA', 1000000, 5000, 'STABLE')
            """)
            conn.execute("""
                INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at)
                VALUES ('f-1234', 'pre_migration.pdf', 5000, '2026-01-01T00:00:00')
            """)
            conn.execute("""
                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes)
                VALUES ('chunk_1', 'f-1234', 'ExistingMega', 1, 5000)
            """)
            conn.commit()
            conn.close()

            # Initialize DatabaseEngine on this database
            db = DatabaseEngine(path)
            accounts = db.get_accounts()
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0]["account_name"], "ExistingMega")

            files = db.get_virtual_files()
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["file_name"], "pre_migration.pdf")
            self.assertEqual(files[0]["file_id"], "f-1234")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
