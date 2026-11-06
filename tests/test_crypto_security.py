"""
Automated Test Suite for CloudPool Encryption and Master-Key Security Hardening (TASK 05)
Tests:
- Correct password
- Incorrect password
- Modified ciphertext
- Modified authentication tag
- Wrong key length
- Missing key
- Invalid backup version
- Corrupted backup
- Backup restoration
- Repeated backup creation (unique salt & nonce)
- Nonce uniqueness testing (10,000 samples)
- Existing encrypted file compatibility (Version 1 legacy support)
- DPAPI master key protection and migration
All tests use temporary SQLite databases and isolated test keys. Never touches real cloud data or production keys.
"""

import os
import sys
import uuid
import json
import base64
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure CloudPool_Project is in path
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from core_engine import (
    CryptoEngine,
    MetadataEngine,
    DatabaseEngine,
    is_dpapi_available,
    dpapi_protect,
    dpapi_unprotect,
    BACKUP_MAGIC,
    BACKUP_VERSION_CURRENT,
    PBKDF2_ITERATIONS_V2,
    PBKDF2_ITERATIONS_V1,
    METADATA_SALT_LEGACY
)


class TestCryptoSecurity(unittest.TestCase):
    def setUp(self):
        """Create an isolated temporary environment with custom paths for every test."""
        self.test_dir = tempfile.mkdtemp(prefix="cloudpool_crypto_test_")
        self.db_path = os.path.join(self.test_dir, "test_master.db")
        self.key_path = os.path.join(self.test_dir, "test_master.key")
        self.key_path_dpapi = os.path.join(self.test_dir, "test_master.key.dpapi")
        self.vault_dir = os.path.join(self.test_dir, "local_vault")
        os.makedirs(self.vault_dir, exist_ok=True)

        # Patch core_engine paths to target our test directory
        self.patchers = [
            patch("core_engine.DB_PATH", self.db_path),
            patch("core_engine.KEY_PATH", self.key_path),
            patch("core_engine.KEY_PATH_DPAPI", self.key_path_dpapi),
            patch("core_engine.VAULT_DIR", self.vault_dir),
            patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
        ]
        for p in self.patchers:
            p.start()

        # Initialize test database
        self.db = DatabaseEngine(db_path=self.db_path)
        self.crypto = CryptoEngine()

    def tearDown(self):
        """Clean up all patchers and temporary directory."""
        try:
            self.db.close()
        except Exception:
            pass
        for p in self.patchers:
            p.stop()
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # 1. Correct Password
    # --------------------------------------------------------------------------
    def test_correct_password(self):
        """A valid recovery passphrase decrypts and restores database and master key."""
        passphrase = "Secure_Recovery_Passphrase_2026!"
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)
        self.assertTrue(os.path.exists(backup_path))

        with open(backup_path, "rb") as f:
            backup_bytes = f.read()

        # Import into fresh database
        res = MetadataEngine.import_encrypted_backup(backup_bytes, passphrase)
        self.assertTrue(res)

    # --------------------------------------------------------------------------
    # 2. Incorrect Password
    # --------------------------------------------------------------------------
    def test_incorrect_password(self):
        """An incorrect passphrase raises InvalidTag and returns 0 unauthenticated data."""
        passphrase = "CorrectSecretPassword!123"
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)

        with open(backup_path, "rb") as f:
            backup_bytes = f.read()

        with self.assertRaises(InvalidTag):
            MetadataEngine.import_encrypted_backup(backup_bytes, "WrongSecretPassword!456")

    # --------------------------------------------------------------------------
    # 3. Modified Ciphertext
    # --------------------------------------------------------------------------
    def test_modified_ciphertext(self):
        """Tampering with a single byte in ciphertext fails AES-GCM authentication."""
        passphrase = "Tamper_Detection_Passphrase_2026"
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)

        with open(backup_path, "rb") as f:
            backup_bytes = bytearray(f.read())

        # Tamper with byte in ciphertext body (after 39-byte header + nonce)
        tamper_idx = len(backup_bytes) // 2
        backup_bytes[tamper_idx] ^= 0x55

        with self.assertRaises(InvalidTag):
            MetadataEngine.import_encrypted_backup(bytes(backup_bytes), passphrase)

    # --------------------------------------------------------------------------
    # 4. Modified Authentication Tag
    # --------------------------------------------------------------------------
    def test_modified_authentication_tag(self):
        """Tampering with the 16-byte authentication tag fails tag verification."""
        passphrase = "Tag_Tamper_Passphrase_2026"
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)

        with open(backup_path, "rb") as f:
            backup_bytes = bytearray(f.read())

        # Tamper with the last byte (part of 16-byte tag)
        backup_bytes[-1] ^= 0xAA

        with self.assertRaises(InvalidTag):
            MetadataEngine.import_encrypted_backup(bytes(backup_bytes), passphrase)

    # --------------------------------------------------------------------------
    # 5. Wrong Key Length
    # --------------------------------------------------------------------------
    def test_wrong_key_length(self):
        """CryptoEngine strictly rejects any key that is not exactly 32 bytes (256-bit)."""
        with self.assertRaises(ValueError):
            CryptoEngine(key=b"too_short_16byte")
        with self.assertRaises(ValueError):
            CryptoEngine(key=b"24_bytes_aes_key_rejected!")
        with self.assertRaises(ValueError):
            CryptoEngine(key=b"a" * 31)
        with self.assertRaises(ValueError):
            CryptoEngine(key=b"a" * 33)

        # 32 bytes is valid
        valid_engine = CryptoEngine(key=b"a" * 32)
        self.assertEqual(len(valid_engine.key), 32)

    # --------------------------------------------------------------------------
    # 6. Missing Key
    # --------------------------------------------------------------------------
    def test_missing_key(self):
        """When no key exists, a cryptographically secure 256-bit key is generated."""
        # Ensure neither key file exists
        if os.path.exists(self.key_path):
            os.remove(self.key_path)
        if os.path.exists(self.key_path_dpapi):
            os.remove(self.key_path_dpapi)

        engine = CryptoEngine()
        self.assertEqual(len(engine.key), 32)
        # Key file must now exist
        self.assertTrue(os.path.exists(self.key_path) or os.path.exists(self.key_path_dpapi))

        # Re-instantiating loads the exact same key
        engine2 = CryptoEngine()
        self.assertEqual(engine.key, engine2.key)

    # --------------------------------------------------------------------------
    # 7. Invalid Backup Version
    # --------------------------------------------------------------------------
    def test_invalid_backup_version(self):
        """Backups with unsupported version identifiers are rejected cleanly."""
        passphrase = "Version_Test_Passphrase"
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)

        with open(backup_path, "rb") as f:
            backup_bytes = bytearray(f.read())

        # Version byte is at index 4 (after b"CPBK")
        backup_bytes[4] = 99  # Invalid version 99

        with self.assertRaises(ValueError) as ctx:
            MetadataEngine.import_encrypted_backup(bytes(backup_bytes), passphrase)
        self.assertIn("Unsupported backup version", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 8. Corrupted Backup
    # --------------------------------------------------------------------------
    def test_corrupted_backup(self):
        """Truncated or corrupted payloads raise clean exceptions without crashes."""
        with self.assertRaises(ValueError):
            MetadataEngine.import_encrypted_backup(b"", "pass")
        with self.assertRaises(ValueError):
            MetadataEngine.import_encrypted_backup(b"short", "pass")
        with self.assertRaises(ValueError):
            MetadataEngine.import_encrypted_backup(b"CPBK\x02\x01\x00\x00", "pass")

    # --------------------------------------------------------------------------
    # 9. Backup Restoration
    # --------------------------------------------------------------------------
    def test_backup_restoration(self):
        """End-to-end backup and restore verifies identical tables, accounts, and master key."""
        passphrase = "Full_Restoration_Passphrase_2026!"
        acc = "MEGA_Backup_Account"
        self.db.register_account(acc, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE")

        file_id = str(uuid.uuid4())
        with self.db.conn:
            self.db.conn.execute("INSERT INTO virtual_files (file_id, file_name, total_size_bytes, uploaded_at, upload_status) VALUES (?, 'saved.docx', 8888, datetime('now'), 'completed')", (file_id,))
            self.db.conn.execute("INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, is_parity) VALUES ('chunk_saved', ?, ?, 1, 8888, 0)", (file_id, acc))

        orig_key = self.crypto.key
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)

        # Clear database and wipe key
        self.db.close()
        os.remove(self.db_path)
        if os.path.exists(self.key_path):
            os.remove(self.key_path)
        if os.path.exists(self.key_path_dpapi):
            os.remove(self.key_path_dpapi)

        with open(backup_path, "rb") as f:
            backup_bytes = f.read()

        # Restore
        res = MetadataEngine.import_encrypted_backup(backup_bytes, passphrase)
        self.assertTrue(res)

        # Verify key was restored identically
        restored_crypto = CryptoEngine()
        self.assertEqual(restored_crypto.key, orig_key)

        # Verify database contents restored identically
        restored_db = DatabaseEngine(db_path=self.db_path)
        cur = restored_db.conn.cursor()
        cur.execute("SELECT file_name FROM virtual_files WHERE file_id = ?", (file_id,))
        self.assertEqual(cur.fetchone()["file_name"], "saved.docx")
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (acc,))
        self.assertEqual(cur.fetchone()["account_name"], acc)

    # --------------------------------------------------------------------------
    # 10. Repeated Backup Creation (Unique Salt & Nonce)
    # --------------------------------------------------------------------------
    def test_repeated_backup_creation(self):
        """Repeated backups with identical data and password produce unique ciphertexts, salts, and nonces."""
        passphrase = "Consistent_Password_123"
        backups = []
        for _ in range(5):
            bp = MetadataEngine.export_encrypted_backup(passphrase)
            with open(bp, "rb") as f:
                backups.append(f.read())

        # All 5 ciphertexts must be distinct
        self.assertEqual(len(set(backups)), 5)

        # Extract salts (index 11 to 27) and nonces (index 27 to 39)
        salts = [b[11:27] for b in backups]
        nonces = [b[27:39] for b in backups]

        self.assertEqual(len(set(salts)), 5, "Every backup must have a unique random salt.")
        self.assertEqual(len(set(nonces)), 5, "Every backup must have a unique random nonce.")

    # --------------------------------------------------------------------------
    # 11. Nonce Uniqueness Testing (10,000 Nonces)
    # --------------------------------------------------------------------------
    def test_nonce_uniqueness(self):
        """Verify that 10,000 encrypted chunks generate 10,000 unique nonces without collision."""
        nonces = set()
        test_payload = b"Sample encrypted chunk payload block for nonce testing"
        for _ in range(10000):
            enc = self.crypto.encrypt_data(test_payload)
            nonce = enc[:12]
            nonces.add(nonce)

        self.assertEqual(len(nonces), 10000, "Collision detected in 12-byte nonce generation!")

    # --------------------------------------------------------------------------
    # 12. Existing Encrypted File Compatibility (Version 1 Legacy Support)
    # --------------------------------------------------------------------------
    def test_existing_encrypted_file_compatibility(self):
        """Legacy Version 1 backups (static salt + 100,000 iters) decrypt cleanly with new engine."""
        passphrase = "Legacy_Password_2026"
        key_bytes = b"LegacyMasterKey32BytesLong12345!"
        db_bytes = b"SQLite format 3\x00DummyDatabaseContent"

        # Construct legacy Version 1 payload
        legacy_payload = json.dumps({
            "version": 1,
            "created_at": "2026-01-01T00:00:00",
            "master_key_b64": base64.b64encode(key_bytes).decode("utf-8"),
            "db_b64": base64.b64encode(db_bytes).decode("utf-8")
        }).encode("utf-8")

        # Encrypt with Version 1 parameters
        legacy_derived, _, _ = MetadataEngine.derive_key(
            passphrase, salt=METADATA_SALT_LEGACY, iterations=PBKDF2_ITERATIONS_V1, version=1
        )
        aesgcm = AESGCM(legacy_derived)
        nonce = os.urandom(12)
        legacy_backup_bytes = nonce + aesgcm.encrypt(nonce, legacy_payload, None)

        # Import using modern engine
        res = MetadataEngine.import_encrypted_backup(legacy_backup_bytes, passphrase)
        self.assertTrue(res)

        # Verify key restored
        loaded_crypto = CryptoEngine()
        self.assertEqual(loaded_crypto.key, key_bytes)

    # --------------------------------------------------------------------------
    # 13. DPAPI Master Key Protection and Migration
    # --------------------------------------------------------------------------
    def test_dpapi_master_key_protection_and_migration(self):
        """Legacy plaintext master.key is securely migrated to master.key.dpapi."""
        if not is_dpapi_available():
            self.skipTest("Windows DPAPI not available in current test environment.")

        # Wipe DPAPI key and write legacy plaintext key
        if os.path.exists(self.key_path_dpapi):
            os.remove(self.key_path_dpapi)

        test_key = b"PlaintextKeyToMigrateIntoDPAPI!!"
        with open(self.key_path, "wb") as f:
            f.write(test_key)

        # Instantiate CryptoEngine - triggers migration
        engine = CryptoEngine()
        self.assertEqual(engine.key, test_key)

        # master.key.dpapi must now exist
        self.assertTrue(os.path.exists(self.key_path_dpapi))

        # Plaintext master.key should be renamed to .migrated or removed
        self.assertFalse(os.path.exists(self.key_path))
        self.assertTrue(os.path.exists(self.key_path + ".migrated"))

        # Verify DPAPI readback
        with open(self.key_path_dpapi, "rb") as f:
            enc_blob = f.read()
        decrypted_key = dpapi_unprotect(enc_blob)
        self.assertEqual(decrypted_key, test_key)


if __name__ == "__main__":
    unittest.main()
