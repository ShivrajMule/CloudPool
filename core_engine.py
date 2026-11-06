import os
import io
import json
import uuid
import base64
import sqlite3
import threading
import configparser
import subprocess
import concurrent.futures
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Project Paths
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "cloudpool_master.db")
VAULT_DIR = os.path.join(APP_DIR, "local_vault")
KEY_PATH = os.path.join(APP_DIR, "master.key")
RCLONE_LOCAL = os.path.join(APP_DIR, "rclone.exe")
RCLONE_BIN = RCLONE_LOCAL if os.path.exists(RCLONE_LOCAL) else "rclone"

# Default salt for metadata archive key derivation
METADATA_SALT = b"CloudPool_Meta_Vault_Salt_2026_Secure"
DEFAULT_META_PASSPHRASE = "CloudPool_Master_Passphrase_Vault_2026"

os.makedirs(VAULT_DIR, exist_ok=True)


def format_bytes(num_bytes):
    """Converts bytes into human-readable string (B, KB, MB, GB, TB)."""
    if num_bytes is None:
        return "0 B"
    num_bytes = float(num_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}" if unit in ['MB', 'GB', 'TB'] else f"{int(num_bytes)} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


# Standalone worker functions for multiprocessing parallel CPU encryption across Ryzen 7 cores
def _encrypt_chunk_worker(payload):
    """
    Multiprocessing worker function for parallel CPU encryption.
    Runs on an independent CPU core, bypassing Python's GIL.
    payload: (key_bytes, raw_bytes)
    returns: (nonce + ciphertext) bytes
    """
    key, raw_bytes = payload
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, raw_bytes, None)


def _decrypt_chunk_worker(payload):
    """
    Multiprocessing worker function for parallel CPU decryption.
    payload: (key_bytes, encrypted_bytes)
    returns: plaintext bytes
    """
    key, encrypted_bytes = payload
    aesgcm = AESGCM(key)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


class ProcessManager:
    """
    Tracks all active spawned Rclone child processes and guarantees
    immediate, hard OS-level termination with zero background persistence.
    """
    _lock = threading.Lock()
    _active_pids = set()

    @classmethod
    def register_pid(cls, pid):
        if pid:
            with cls._lock:
                cls._active_pids.add(pid)

    @classmethod
    def unregister_pid(cls, pid):
        if pid:
            with cls._lock:
                cls._active_pids.discard(pid)

    @classmethod
    def kill_all_processes(cls):
        """Immediately and aggressively terminates all child rclone.exe processes and frees all resources."""
        with cls._lock:
            pids = list(cls._active_pids)
            cls._active_pids.clear()

        # 1. Force kill tracked child PIDs and process trees
        for pid in pids:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=5)
            except Exception:
                pass

        # 2. Hard sweep on any orphaned rclone.exe processes spawned by this session
        try:
            subprocess.run(["taskkill", "/F", "/IM", "rclone.exe"], capture_output=True, timeout=5)
        except Exception:
            pass


class CryptoEngine:
    """Handles AES-256-GCM Encryption for 20MB chunks and parity blocks."""
    def __init__(self):
        self.key = self._load_or_create_key()
        # Scale parallel workers to the Ryzen 7 multi-core processor (up to 8 cores)
        self.num_workers = min(os.cpu_count() or 4, 8)

    def _load_or_create_key(self):
        if os.path.exists(KEY_PATH):
            with open(KEY_PATH, "rb") as f:
                return f.read()
        else:
            new_key = AESGCM.generate_key(bit_length=256)
            with open(KEY_PATH, "wb") as f:
                f.write(new_key)
            return new_key

    def encrypt_data(self, data_bytes):
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # Unique 96-bit nonce for each chunk
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        return nonce + ciphertext  # Prepend nonce for decryption

    def decrypt_data(self, encrypted_bytes):
        aesgcm = AESGCM(self.key)
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def parallel_encrypt_chunks(self, raw_chunks):
        """
        Distributes AES-256-GCM encryption across multiple CPU cores simultaneously
        using a ProcessPoolExecutor (bypassing the Python GIL).
        """
        if not raw_chunks:
            return []
        if len(raw_chunks) == 1:
            return [self.encrypt_data(raw_chunks[0])]

        tasks = [(self.key, chunk) for chunk in raw_chunks]
        workers = min(len(raw_chunks), self.num_workers)
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                return list(executor.map(_encrypt_chunk_worker, tasks))
        except Exception as e:
            print(f"[CRYPTO FALLBACK] Process pool fallback to direct execution: {e}")
            return [self.encrypt_data(c) for c in raw_chunks]

    def parallel_decrypt_chunks(self, encrypted_chunks):
        """
        Distributes AES-256-GCM decryption across multiple CPU cores simultaneously.
        """
        if not encrypted_chunks:
            return []
        if len(encrypted_chunks) == 1:
            return [self.decrypt_data(encrypted_chunks[0])]

        tasks = [(self.key, chunk) for chunk in encrypted_chunks]
        workers = min(len(encrypted_chunks), self.num_workers)
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                return list(executor.map(_decrypt_chunk_worker, tasks))
        except Exception as e:
            print(f"[CRYPTO FALLBACK] Process pool fallback to direct execution: {e}")
            return [self.decrypt_data(c) for c in encrypted_chunks]


class RAID5Engine:
    """Bitwise XOR Erasure Coding Engine for N+1 single-parity chunk protection."""
    @staticmethod
    def compute_parity(chunks):
        """Computes bitwise XOR across a list of raw byte buffers."""
        if not chunks:
            return b""
        if len(chunks) == 1:
            return chunks[0]
        
        max_len = max(len(c) for c in chunks)
        try:
            import numpy as np
            res = np.zeros(max_len, dtype=np.uint8)
            for c in chunks:
                if len(c) < max_len:
                    arr = np.zeros(max_len, dtype=np.uint8)
                    arr[:len(c)] = np.frombuffer(c, dtype=np.uint8)
                else:
                    arr = np.frombuffer(c, dtype=np.uint8)
                res = np.bitwise_xor(res, arr)
            return res.tobytes()
        except ImportError:
            parity = bytearray(max_len)
            for c in chunks:
                for i in range(len(c)):
                    parity[i] ^= c[i]
            return bytes(parity)

    @staticmethod
    def recover_missing_chunk(surviving_chunks, parity_chunk, original_len):
        """
        Reconstructs the single missing chunk:
        Missing = Surviving_1 ^ Surviving_2 ^ ... ^ Parity
        """
        all_buffers = list(surviving_chunks) + [parity_chunk]
        recovered_full = RAID5Engine.compute_parity(all_buffers)
        return recovered_full[:original_len]


class MetadataEngine:
    """Handles passphrase-based encryption of the database and remote metadata mirroring."""
    @staticmethod
    def derive_key(passphrase, salt=METADATA_SALT):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def export_encrypted_backup(passphrase=DEFAULT_META_PASSPHRASE):
        """Bundles cloudpool_master.db and master.key into an AES-256-GCM encrypted package."""
        if not os.path.exists(DB_PATH) or not os.path.exists(KEY_PATH):
            return None

        with open(DB_PATH, "rb") as f:
            db_bytes = f.read()
        with open(KEY_PATH, "rb") as f:
            key_bytes = f.read()

        payload = json.dumps({
            "version": 1,
            "created_at": datetime.utcnow().isoformat(),
            "master_key_b64": base64.b64encode(key_bytes).decode("utf-8"),
            "db_b64": base64.b64encode(db_bytes).decode("utf-8")
        }).encode("utf-8")

        key = MetadataEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_pkg = nonce + aesgcm.encrypt(nonce, payload, None)

        backup_path = os.path.join(VAULT_DIR, "cloudpool_metadata.enc")
        with open(backup_path, "wb") as f:
            f.write(encrypted_pkg)
        return backup_path

    @staticmethod
    def import_encrypted_backup(backup_bytes, passphrase=DEFAULT_META_PASSPHRASE):
        """Decrypts a metadata package and restores master.key and cloudpool_master.db."""
        key = MetadataEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = backup_bytes[:12]
        ciphertext = backup_bytes[12:]
        decrypted_json = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        data = json.loads(decrypted_json)

        key_bytes = base64.b64decode(data["master_key_b64"])
        db_bytes = base64.b64decode(data["db_b64"])

        with open(KEY_PATH, "wb") as f:
            f.write(key_bytes)
        with open(DB_PATH, "wb") as f:
            f.write(db_bytes)
        return True

    @staticmethod
    def sync_metadata_to_cloud(db, passphrase=DEFAULT_META_PASSPHRASE):
        """Silently syncs encrypted metadata backup to 2 independent cloud accounts under :CloudPool_Meta/."""
        backup_path = MetadataEngine.export_encrypted_backup(passphrase)
        if not backup_path or not os.path.exists(backup_path):
            return []

        accounts = db.get_accounts()
        if not accounts:
            return []

        selected_remotes = []
        seen_providers = set()
        for a in accounts:
            if a["provider"] not in seen_providers:
                selected_remotes.append(a["account_name"])
                seen_providers.add(a["provider"])
            if len(selected_remotes) >= 2:
                break

        if len(selected_remotes) < 2 and len(accounts) >= 2:
            for a in accounts:
                if a["account_name"] not in selected_remotes:
                    selected_remotes.append(a["account_name"])
                    if len(selected_remotes) >= 2:
                        break

        synced_to = []
        for remote in selected_remotes:
            target = f"{remote}:CloudPool_Meta/"
            cmd = [RCLONE_BIN, "copy", backup_path, target]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if res.returncode == 0:
                    synced_to.append(remote)
            except Exception:
                pass

        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except Exception:
                pass

        return synced_to

    @staticmethod
    def restore_metadata_from_cloud(passphrase=DEFAULT_META_PASSPHRASE):
        """Disaster Recovery: Fetches the encrypted metadata backup from any configured remote and restores state."""
        import configparser
        conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
        if not os.path.exists(conf_path):
            raise FileNotFoundError("rclone.conf not found. Ensure Rclone remotes are configured.")

        cfg = configparser.ConfigParser()
        cfg.read(conf_path)
        remotes = cfg.sections()

        temp_target = os.path.join(VAULT_DIR, "cloudpool_metadata_restore.enc")
        fetched = False
        source_remote = None

        for remote in remotes:
            cmd = [RCLONE_BIN, "copy", f"{remote}:CloudPool_Meta/cloudpool_metadata.enc", VAULT_DIR]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if res.returncode == 0 and os.path.exists(temp_target):
                    fetched = True
                    source_remote = remote
                    break
            except Exception:
                continue

        if not fetched:
            raise Exception("No CloudPool metadata backup found across any of your configured remotes.")

        try:
            with open(temp_target, "rb") as f:
                backup_bytes = f.read()
            MetadataEngine.import_encrypted_backup(backup_bytes, passphrase)
            return source_remote
        finally:
            if os.path.exists(temp_target):
                os.remove(temp_target)


class DatabaseEngine:
    """Manages the SQLite map of where all your chunks are stored."""
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self.cleanup_incomplete_uploads()
        self.prune_ghost_remotes()

    def prune_ghost_remotes(self):
        """
        Scans registered cloud_accounts in SQLite against rclone.conf.
        If an account does NOT exist in rclone.conf and has 0 chunks, it is an
        accidental registration (e.g. accidentally added OneDrive_2) and is safely pruned.
        Returns list of pruned account names.
        """
        conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
        if not os.path.exists(conf_path):
            return []
        config = configparser.ConfigParser()
        try:
            config.read(conf_path)
            valid_sections = set(config.sections())
        except Exception:
            return []

        cur = self.conn.cursor()
        cur.execute("SELECT account_name FROM cloud_accounts")
        registered = [r["account_name"] for r in cur.fetchall()]

        pruned = []
        for acc in registered:
            if acc not in valid_sections:
                stats = self.get_account_chunks_count(acc)
                if stats["count"] == 0:
                    cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (acc,))
                    pruned.append(acc)
        if pruned:
            self.conn.commit()
            print(f"[ACCOUNT SANITIZER] Pruned {len(pruned)} accidental / ghost remote(s): {', '.join(pruned)}")
        return pruned

    def cleanup_incomplete_uploads(self):
        """
        Scans for any broken/partial virtual file uploads caused by an interrupted network,
        forced app close, or power loss, and safely rolls them back to prevent corruption.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT file_id, file_name, total_size_bytes FROM virtual_files")
        all_files = cur.fetchall()
        cleaned = 0

        CHUNK_SIZE = 20 * 1024 * 1024
        for f in all_files:
            file_id = f["file_id"]
            tot_size = f["total_size_bytes"]
            expected_data_chunks = max(1, (tot_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if tot_size > 0 else 1

            cur.execute("SELECT COUNT(*) as cnt FROM file_chunks WHERE file_id = ? AND is_parity = 0", (file_id,))
            cnt_row = cur.fetchone()
            actual_data_chunks = cnt_row["cnt"] if cnt_row else 0

            if actual_data_chunks < expected_data_chunks:
                # Incomplete upload detected
                print(f"[CRASH RECOVERY] Interrupted file '{f['file_name']}' detected ({actual_data_chunks}/{expected_data_chunks} chunks). Rolling back...")
                cur.execute("SELECT account_name, chunk_size_bytes FROM file_chunks WHERE file_id = ?", (file_id,))
                for ch in cur.fetchall():
                    cur.execute("UPDATE cloud_accounts SET used_bytes = MAX(0, used_bytes - ?) WHERE account_name = ?", (ch["chunk_size_bytes"], ch["account_name"]))
                cur.execute("DELETE FROM file_chunks WHERE file_id = ?", (file_id,))
                cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
                cleaned += 1

        if cleaned > 0:
            self.conn.commit()
            print(f"[CRASH RECOVERY] Cleaned up {cleaned} interrupted upload record(s).")
        return cleaned

    def _init_schema(self):
        cur = self.conn.cursor()
        # Table 1: Your connected Rclone accounts with Priority support
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cloud_accounts (
                account_name TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                usable_capacity_bytes INTEGER NOT NULL,
                used_bytes INTEGER DEFAULT 0,
                reliability_tier TEXT NOT NULL,
                priority INTEGER DEFAULT 1
            )
        """)
        # Safe migration for existing databases created without the priority column
        cur.execute("PRAGMA table_info(cloud_accounts)")
        columns = [col[1] for col in cur.fetchall()]
        if "priority" not in columns:
            cur.execute("ALTER TABLE cloud_accounts ADD COLUMN priority INTEGER DEFAULT 1")

        # Table 2: Virtual Folders (Hierarchical Virtual File System)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS virtual_folders (
                folder_id TEXT PRIMARY KEY,
                folder_name TEXT NOT NULL,
                parent_folder_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_folder_id) REFERENCES virtual_folders(folder_id) ON DELETE CASCADE
            )
        """)

        # Table 3: The virtual files you see in the UI
        cur.execute("""
            CREATE TABLE IF NOT EXISTS virtual_files (
                file_id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                total_size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                folder_id TEXT,
                FOREIGN KEY(folder_id) REFERENCES virtual_folders(folder_id) ON DELETE SET NULL
            )
        """)
        # Safe migration for existing databases created without the folder_id or container columns
        cur.execute("PRAGMA table_info(virtual_files)")
        vf_cols = [col[1] for col in cur.fetchall()]
        if "folder_id" not in vf_cols:
            cur.execute("ALTER TABLE virtual_files ADD COLUMN folder_id TEXT")
        if "container_id" not in vf_cols:
            cur.execute("ALTER TABLE virtual_files ADD COLUMN container_id TEXT")
        if "is_container" not in vf_cols:
            cur.execute("ALTER TABLE virtual_files ADD COLUMN is_container INTEGER DEFAULT 0")
        if "relative_path" not in vf_cols:
            cur.execute("ALTER TABLE virtual_files ADD COLUMN relative_path TEXT")

        # Table 4: The map tracking every encrypted chunk & parity block
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_chunks (
                chunk_id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                account_name TEXT NOT NULL,
                part_number INTEGER NOT NULL,
                chunk_size_bytes INTEGER DEFAULT 0,
                is_parity INTEGER DEFAULT 0,
                FOREIGN KEY(file_id) REFERENCES virtual_files(file_id) ON DELETE CASCADE,
                FOREIGN KEY(account_name) REFERENCES cloud_accounts(account_name)
            )
        """)
        
        # Schema Migration: Add chunk_size_bytes and is_parity if missing in existing database
        col_names = [c[1] for c in cur.execute("PRAGMA table_info(file_chunks)").fetchall()]
        if "chunk_size_bytes" not in col_names:
            cur.execute("ALTER TABLE file_chunks ADD COLUMN chunk_size_bytes INTEGER DEFAULT 0")
        if "is_parity" not in col_names:
            cur.execute("ALTER TABLE file_chunks ADD COLUMN is_parity INTEGER DEFAULT 0")

        self.conn.commit()

    def register_account(self, account_name, provider, raw_gb, buffer_gb, tier, priority=1):
        """Registers or updates an account, enforcing buffers and allocation priority."""
        GB = 1024 * 1024 * 1024
        usable_bytes = int((raw_gb - buffer_gb) * GB)
        
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cloud_accounts 
            (account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority)
            VALUES (?, ?, ?, 0, ?, ?)
            ON CONFLICT(account_name) DO UPDATE SET
                usable_capacity_bytes = excluded.usable_capacity_bytes,
                reliability_tier = excluded.reliability_tier,
                priority = excluded.priority
        """, (account_name, provider, usable_bytes, tier, priority))
        self.conn.commit()

    def get_accounts(self):
        """Returns all connected cloud accounts sorted by allocation priority, then remaining free space."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority,
                   (usable_capacity_bytes - used_bytes) AS free_bytes
            FROM cloud_accounts 
            ORDER BY priority ASC, (usable_capacity_bytes - used_bytes) DESC
        """)
        return [dict(row) for row in cur.fetchall()]

    def unregister_account(self, account_name):
        """Safely removes a cloud remote registration from SQLite."""
        cur = self.conn.cursor()
        cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (account_name,))
        self.conn.commit()

    def get_account_chunks_count(self, account_name):
        """Returns the number of chunks and total bytes stored on a remote."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT COUNT(*), COALESCE(SUM(chunk_size_bytes), 0) 
            FROM file_chunks 
            WHERE account_name = ?
        """, (account_name,))
        row = cur.fetchone()
        return {"count": row[0], "bytes": row[1]}

    def is_remote_in_rclone_config(self, account_name):
        """Validates whether account_name exists in rclone.conf."""
        conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
        if not os.path.exists(conf_path):
            return False
        cfg = configparser.ConfigParser()
        try:
            cfg.read(conf_path)
            return account_name in cfg.sections()
        except Exception:
            return False

    def get_unregistered_rclone_remotes(self):
        """Scans rclone.conf and returns list of remotes configured in Rclone but not yet in CloudPool."""
        conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
        if not os.path.exists(conf_path):
            return []
        cfg = configparser.ConfigParser()
        try:
            cfg.read(conf_path)
            all_remotes = cfg.sections()
        except Exception:
            return []

        cur = self.conn.cursor()
        cur.execute("SELECT account_name FROM cloud_accounts")
        registered = {r["account_name"] for r in cur.fetchall()}
        return [r for r in all_remotes if r not in registered]

    # -------------------------------------------------------------
    # VIRTUAL FILE SYSTEM (VFS) & FOLDER MANAGEMENT
    # -------------------------------------------------------------
    def create_folder(self, folder_name, parent_folder_id=None):
        """Creates a new virtual folder under parent_folder_id (or root if None)."""
        clean_name = folder_name.strip().strip("/\\")
        if not clean_name:
            raise ValueError("Folder name cannot be empty.")
        if parent_folder_id in ("", "root", "ROOT", "None"):
            parent_folder_id = None

        folder_id = str(uuid.uuid4())
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO virtual_folders (folder_id, folder_name, parent_folder_id, created_at)
            VALUES (?, ?, ?, datetime('now'))
        """, (folder_id, clean_name, parent_folder_id))
        self.conn.commit()
        return folder_id

    def get_folder(self, folder_id):
        """Fetches a single virtual folder record by ID."""
        if not folder_id:
            return None
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM virtual_folders WHERE folder_id = ?", (folder_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_all_folders(self):
        """Returns all virtual folders sorted by name."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM virtual_folders ORDER BY folder_name ASC")
        return [dict(row) for row in cur.fetchall()]

    def get_subfolders(self, parent_folder_id=None):
        """Returns immediate child folders under parent_folder_id."""
        if parent_folder_id in ("", "root", "ROOT", "None"):
            parent_folder_id = None
        cur = self.conn.cursor()
        if parent_folder_id is None:
            cur.execute("SELECT * FROM virtual_folders WHERE parent_folder_id IS NULL OR parent_folder_id = '' ORDER BY folder_name ASC")
        else:
            cur.execute("SELECT * FROM virtual_folders WHERE parent_folder_id = ? ORDER BY folder_name ASC", (parent_folder_id,))
        return [dict(row) for row in cur.fetchall()]

    def get_folder_path(self, folder_id):
        """
        Returns list of ancestor folder dicts from root down to folder_id:
        [{folder_id, folder_name}, ...]
        """
        if not folder_id:
            return []
        path = []
        curr_id = folder_id
        visited = set()
        while curr_id and curr_id not in visited:
            visited.add(curr_id)
            folder = self.get_folder(curr_id)
            if not folder:
                break
            path.append({"folder_id": folder["folder_id"], "folder_name": folder["folder_name"]})
            curr_id = folder.get("parent_folder_id")
        path.reverse()
        return path

    def get_folder_path_string(self, folder_id):
        """Returns virtual path string, e.g. '/Screenshots/College'."""
        if not folder_id:
            return "/"
        path = self.get_folder_path(folder_id)
        if not path:
            return "/"
        return "/" + "/".join(p["folder_name"] for p in path)

    def get_directory_contents(self, current_folder_id=None):
        """
        Fetches all folders and files inside a specific directory.
        Includes item count for folders and chunk/parity info for files.
        """
        if current_folder_id in ("", "root", "ROOT", "None"):
            current_folder_id = None

        cur = self.conn.cursor()
        # 1. Sub-folders
        if current_folder_id is None:
            cur.execute("SELECT * FROM virtual_folders WHERE parent_folder_id IS NULL OR parent_folder_id = '' ORDER BY folder_name ASC")
        else:
            cur.execute("SELECT * FROM virtual_folders WHERE parent_folder_id = ? ORDER BY folder_name ASC", (current_folder_id,))
        raw_folders = [dict(r) for r in cur.fetchall()]

        # Compute item counts for each folder
        folders = []
        for f in raw_folders:
            f_id = f["folder_id"]
            cur.execute("SELECT COUNT(*) FROM virtual_files WHERE folder_id = ? AND (is_container IS NULL OR is_container = 0)", (f_id,))
            f_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM virtual_folders WHERE parent_folder_id = ?", (f_id,))
            sub_count = cur.fetchone()[0]
            f["file_count"] = f_count
            f["subfolder_count"] = sub_count
            f["total_items"] = f_count + sub_count
            folders.append(f)

        # 2. Files
        if current_folder_id is None:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       vf.container_id, vf.relative_path,
                       COALESCE(fc_dir.chunk_count, fc_cnt.chunk_count, 1) AS chunk_count,
                       COALESCE(fc_dir.has_parity, fc_cnt.has_parity, 1) AS has_parity
                FROM virtual_files vf
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_dir ON vf.file_id = fc_dir.file_id
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_cnt ON vf.container_id = fc_cnt.file_id
                WHERE (vf.is_container IS NULL OR vf.is_container = 0)
                  AND (vf.folder_id IS NULL OR vf.folder_id = '')
                ORDER BY vf.uploaded_at DESC
            """)
        else:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       vf.container_id, vf.relative_path,
                       COALESCE(fc_dir.chunk_count, fc_cnt.chunk_count, 1) AS chunk_count,
                       COALESCE(fc_dir.has_parity, fc_cnt.has_parity, 1) AS has_parity
                FROM virtual_files vf
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_dir ON vf.file_id = fc_dir.file_id
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_cnt ON vf.container_id = fc_cnt.file_id
                WHERE (vf.is_container IS NULL OR vf.is_container = 0)
                  AND vf.folder_id = ?
                ORDER BY vf.uploaded_at DESC
            """, (current_folder_id,))
        files = [dict(r) for r in cur.fetchall()]

        return {"folders": folders, "files": files}

    def rename_folder(self, folder_id, new_name):
        """Renames a virtual folder."""
        clean_name = new_name.strip().strip("/\\")
        if not clean_name:
            raise ValueError("Folder name cannot be empty.")
        cur = self.conn.cursor()
        cur.execute("UPDATE virtual_folders SET folder_name = ? WHERE folder_id = ?", (clean_name, folder_id))
        self.conn.commit()

    def rename_virtual_file(self, file_id, new_name):
        """Renames a virtual file."""
        clean_name = new_name.strip().strip("/\\")
        if not clean_name:
            raise ValueError("File name cannot be empty.")
        cur = self.conn.cursor()
        cur.execute("UPDATE virtual_files SET file_name = ? WHERE file_id = ?", (clean_name, file_id))
        self.conn.commit()

    def move_file_to_folder(self, file_id, target_folder_id):
        """Moves a virtual file to target_folder_id (or root if None)."""
        if target_folder_id in ("", "root", "ROOT", "None"):
            target_folder_id = None
        cur = self.conn.cursor()
        cur.execute("UPDATE virtual_files SET folder_id = ? WHERE file_id = ?", (target_folder_id, file_id))
        self.conn.commit()

    def move_folder(self, folder_id, target_parent_id):
        """Moves a folder under target_parent_id, ensuring no cycle."""
        if target_parent_id in ("", "root", "ROOT", "None"):
            target_parent_id = None
        if target_parent_id == folder_id:
            raise ValueError("Cannot move a folder into itself.")

        # Check cyclic dependency: target_parent_id cannot be a descendant of folder_id
        if target_parent_id:
            descendants = self.get_descendant_folders(folder_id)
            if target_parent_id in [d["folder_id"] for d in descendants]:
                raise ValueError("Cannot move a folder into one of its own subfolders.")

        cur = self.conn.cursor()
        cur.execute("UPDATE virtual_folders SET parent_folder_id = ? WHERE folder_id = ?", (target_parent_id, folder_id))
        self.conn.commit()

    def get_descendant_folders(self, folder_id):
        """Recursively collects all subfolder records under folder_id."""
        descendants = []
        queue = [folder_id]
        cur = self.conn.cursor()
        while queue:
            curr = queue.pop(0)
            cur.execute("SELECT * FROM virtual_folders WHERE parent_folder_id = ?", (curr,))
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                descendants.append(r)
                queue.append(r["folder_id"])
        return descendants

    def get_descendant_files(self, folder_id):
        """Recursively collects all files inside folder_id and all its child subfolders."""
        all_folder_ids = [folder_id] + [f["folder_id"] for f in self.get_descendant_folders(folder_id)]
        placeholders = ",".join("?" for _ in all_folder_ids)
        cur = self.conn.cursor()
        cur.execute(f"""
            SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                   vf.container_id, vf.relative_path,
                   COALESCE(fc_dir.chunk_count, fc_cnt.chunk_count, 1) AS chunk_count,
                   COALESCE(fc_dir.has_parity, fc_cnt.has_parity, 1) AS has_parity
            FROM virtual_files vf
            LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_dir ON vf.file_id = fc_dir.file_id
            LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_cnt ON vf.container_id = fc_cnt.file_id
            WHERE (vf.is_container IS NULL OR vf.is_container = 0)
              AND vf.folder_id IN ({placeholders})
            ORDER BY vf.uploaded_at DESC
        """, tuple(all_folder_ids))
        return [dict(r) for r in cur.fetchall()]

    def get_file(self, file_id):
        """Fetches a single virtual file record by file_id."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM virtual_files WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_folder_container(self, folder_id):
        """Returns the virtual archive container for this folder if one exists."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM virtual_files WHERE folder_id = ? AND is_container = 1", (folder_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def delete_virtual_folder_record(self, folder_id):
        """Deletes a virtual folder from SQLite (subfolders deleted recursively)."""
        descendant_folders = self.get_descendant_folders(folder_id)
        folder_ids_to_del = [folder_id] + [d["folder_id"] for d in descendant_folders]
        cur = self.conn.cursor()
        for fid in folder_ids_to_del:
            # Files in these folders move to root if not deleted
            cur.execute("UPDATE virtual_files SET folder_id = NULL WHERE folder_id = ?", (fid,))
            cur.execute("DELETE FROM virtual_folders WHERE folder_id = ?", (fid,))
        self.conn.commit()

    def search_vfs(self, query):
        """
        Searches virtual folders and files matching query (case-insensitive).
        Returns {'folders': [...], 'files': [...]}, each augmented with full virtual path!
        """
        clean_q = f"%{query.strip()}%"
        cur = self.conn.cursor()

        # Folders
        cur.execute("SELECT * FROM virtual_folders WHERE folder_name LIKE ? ORDER BY folder_name ASC", (clean_q,))
        folders = [dict(r) for r in cur.fetchall()]
        for f in folders:
            f["path_str"] = self.get_folder_path_string(f["folder_id"])

        # Files
        cur.execute("""
            SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                   COUNT(fc.chunk_id) AS chunk_count,
                   MAX(fc.is_parity) AS has_parity
            FROM virtual_files vf
            LEFT JOIN file_chunks fc ON vf.file_id = fc.file_id
            WHERE vf.file_name LIKE ?
            GROUP BY vf.file_id
            ORDER BY vf.file_name ASC
        """, (clean_q,))
        files = [dict(r) for r in cur.fetchall()]
        for fl in files:
            fl["path_str"] = self.get_folder_path_string(fl.get("folder_id"))

        return {"folders": folders, "files": files}

    def get_virtual_files(self, folder_id=None, all_folders=True):
        """Returns virtual files with chunk counts and parity."""
        cur = self.conn.cursor()
        if all_folders:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       COUNT(fc.chunk_id) AS chunk_count,
                       MAX(fc.is_parity) AS has_parity
                FROM virtual_files vf
                LEFT JOIN file_chunks fc ON vf.file_id = fc.file_id
                GROUP BY vf.file_id
                ORDER BY vf.uploaded_at DESC
            """)
        elif folder_id is None:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       COUNT(fc.chunk_id) AS chunk_count,
                       MAX(fc.is_parity) AS has_parity
                FROM virtual_files vf
                LEFT JOIN file_chunks fc ON vf.file_id = fc.file_id
                WHERE vf.folder_id IS NULL OR vf.folder_id = ''
                GROUP BY vf.file_id
                ORDER BY vf.uploaded_at DESC
            """)
        else:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       COUNT(fc.chunk_id) AS chunk_count,
                       MAX(fc.is_parity) AS has_parity
                FROM virtual_files vf
                LEFT JOIN file_chunks fc ON vf.file_id = fc.file_id
                WHERE vf.folder_id = ?
                GROUP BY vf.file_id
                ORDER BY vf.uploaded_at DESC
            """, (folder_id,))
        return [dict(row) for row in cur.fetchall()]

    def delete_virtual_file(self, file_id):
        """Removes a virtual file and its chunks from the database."""
        cur = self.conn.cursor()
        cur.execute("DELETE FROM file_chunks WHERE file_id = ?", (file_id,))
        cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
        self.conn.commit()

    def get_pool_summary(self):
        """Returns aggregated pool statistics."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT 
                COALESCE(SUM(usable_capacity_bytes), 0) AS total_usable,
                COALESCE(SUM(used_bytes), 0) AS total_used,
                COUNT(account_name) AS account_count
            FROM cloud_accounts
        """)
        row = cur.fetchone()
        cur.execute("SELECT COUNT(file_id) AS file_count FROM virtual_files")
        file_row = cur.fetchone()
        cur.execute("SELECT COUNT(folder_id) AS folder_count FROM virtual_folders")
        folder_row = cur.fetchone()
        return {
            "total_usable": row["total_usable"],
            "total_used": row["total_used"],
            "free_bytes": max(0, row["total_usable"] - row["total_used"]),
            "account_count": row["account_count"],
            "file_count": file_row["file_count"],
            "folder_count": folder_row["folder_count"] if folder_row else 0
        }

    def sync_from_rclone_config(self):
        """
        Scans %APPDATA%/rclone/rclone.conf and automatically registers any
        detected remotes into SQLite, enforcing priority tiers and 500 MB buffer.
        """
        conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
        if not os.path.exists(conf_path):
            return 0
        
        config = configparser.ConfigParser()
        try:
            config.read(conf_path)
        except Exception:
            return 0

        cur = self.conn.cursor()
        cur.execute("SELECT account_name FROM cloud_accounts")
        existing = {row["account_name"] for row in cur.fetchall()}

        synced_count = 0
        for section in config.sections():
            if section not in existing:
                remote_type = config.get(section, "type", fallback="").lower()
                # Determine default priority based on account name & provider
                if section == "Gmail_1":
                    priority = 99  # Last resort 5TB account
                elif section == "OneDrive_1":
                    priority = 3   # Expiring / temporary 120GB account
                elif section.startswith("Gmail"):
                    priority = 2   # Secondary Gmail pool
                else:
                    priority = 1   # Primary workhorses (MEGA, permanent OneDrive)

                if remote_type == "drive":
                    self.register_account(section, "Google Drive", raw_gb=15.0, buffer_gb=0.5, tier="STABLE", priority=priority)
                    synced_count += 1
                elif remote_type == "mega":
                    self.register_account(section, "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=priority)
                    synced_count += 1
                elif remote_type == "onedrive":
                    self.register_account(section, "OneDrive", raw_gb=5.0, buffer_gb=0.0, tier="STABLE", priority=priority)
                    synced_count += 1
                elif remote_type == "box":
                    self.register_account(section, "Box", raw_gb=10.0, buffer_gb=0.0, tier="STABLE", priority=priority)
                    synced_count += 1
                elif remote_type == "dropbox":
                    self.register_account(section, "Dropbox", raw_gb=2.0, buffer_gb=0.0, tier="STABLE", priority=priority)
                    synced_count += 1
                else:
                    self.register_account(section, remote_type.capitalize() or "Cloud", raw_gb=10.0, buffer_gb=0.0, tier="STABLE", priority=priority)
                    synced_count += 1

        return synced_count


if __name__ == "__main__":
    print("Initializing Core Engine with Priority, RAID-5, and Metadata Mirroring...")
    crypto = CryptoEngine()
    db = DatabaseEngine()
    print("Core initialized successfully.")
