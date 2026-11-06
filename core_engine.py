import os
import io
import re
import hmac
import time
import atexit
import shutil
import hashlib
import tarfile
import tempfile
import json
import uuid
import base64
import sqlite3
import threading
import configparser
import subprocess
import concurrent.futures
import ctypes
from ctypes import wintypes
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Project Paths
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "cloudpool_master.db")
VAULT_DIR = os.path.join(APP_DIR, "local_vault")
KEY_PATH = os.path.join(APP_DIR, "master.key")
KEY_PATH_DPAPI = os.path.join(APP_DIR, "master.key.dpapi")
RCLONE_LOCAL = os.path.join(APP_DIR, "rclone.exe")
RCLONE_BIN = RCLONE_LOCAL if os.path.exists(RCLONE_LOCAL) else "rclone"

# Cryptographic Constants & Standards
BACKUP_MAGIC = b"CPBK"
BACKUP_VERSION_CURRENT = 2
PBKDF2_ITERATIONS_V2 = 600000
PBKDF2_ITERATIONS_V1 = 100000
METADATA_SALT_LEGACY = b"CloudPool_Meta_Vault_Salt_2026_Secure"
METADATA_SALT = METADATA_SALT_LEGACY  # Backward-compatibility alias
LEGACY_DEFAULT_META_PASSPHRASE = "CloudPool_Master_Passphrase_Vault_2026"
DEFAULT_META_PASSPHRASE = LEGACY_DEFAULT_META_PASSPHRASE  # Backward-compatibility alias

os.makedirs(VAULT_DIR, exist_ok=True)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_char))
    ]


def is_dpapi_available() -> bool:
    """Returns True if Windows DPAPI (CryptProtectData) is available on this system."""
    if os.name != "nt" or os.environ.get("CLOUDPOOL_DISABLE_DPAPI") == "1":
        return False
    try:
        return hasattr(ctypes, "windll") and hasattr(ctypes.windll, "crypt32")
    except Exception:
        return False


def dpapi_protect(data: bytes, description: str = "CloudPoolMasterKey") -> bytes:
    """Encrypts data using Windows Data Protection API (DPAPI) bound to the current user."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data to protect must be bytes or bytearray.")
    data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(bytes(data), len(data)), ctypes.POINTER(ctypes.c_char)))
    data_out = DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    res = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(data_in),
        description,
        None,
        None,
        None,
        0x1,
        ctypes.byref(data_out)
    )
    if not res:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(data_out.pbData)


def dpapi_unprotect(encrypted_data: bytes) -> bytes:
    """Decrypts data using Windows Data Protection API (DPAPI)."""
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise TypeError("Data to unprotect must be bytes or bytearray.")
    data_in = DATA_BLOB(len(encrypted_data), ctypes.cast(ctypes.create_string_buffer(bytes(encrypted_data), len(encrypted_data)), ctypes.POINTER(ctypes.c_char)))
    data_out = DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    res = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        None,
        None,
        None,
        0x1,
        ctypes.byref(data_out)
    )
    if not res:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(data_out.pbData)


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
    if len(encrypted_bytes) < 28:
        raise ValueError(f"Ciphertext too short: {len(encrypted_bytes)} bytes (minimum 28 bytes required).")
    aesgcm = AESGCM(key)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


class ProcessInfo:
    """Tracks metadata and lifecycle state of a CloudPool-owned child process."""
    def __init__(self, proc, op_id="global", description=""):
        self.proc = proc
        self.pid = proc.pid if hasattr(proc, "pid") else proc
        self.op_id = op_id
        self.description = description
        self.start_time = time.time()
        self.status = "RUNNING"  # RUNNING, COMPLETED, FAILED, TERMINATED, CANCELLED, TIMED_OUT
        self.exit_code = None

    def poll(self):
        """Polls process if hasattr poll, updating status and exit_code."""
        if hasattr(self.proc, "poll"):
            rc = self.proc.poll()
            if rc is not None:
                self.exit_code = rc
                if self.status == "RUNNING":
                    self.status = "COMPLETED" if rc == 0 else "FAILED"
            return rc
        return self.exit_code


class ProcessManager:
    """
    Enterprise-Grade Windows Process Isolation & Lifecycle Management (TASK 11):
    - Strict process isolation: tracks every process started by CloudPool.
    - Associating with unique operation IDs (op_id).
    - Windows Job Object kernel binding (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) to guarantee
      zero zombie/abandoned processes even on hard crashes.
    - Scoped cancellation: cancel_operation(op_id) terminates only processes for that operation.
    - Process-tree termination strictly by PID (taskkill /F /T /PID <pid>).
    - Never executes global 'taskkill /IM rclone.exe' to prevent collateral damage to other apps.
    - Handles timeouts, already-terminated processes, and captures exit codes safely.
    - Automatic cleanup via atexit.
    """
    _lock = threading.Lock()
    _tracked_processes = {}  # pid -> ProcessInfo
    _op_processes = {}        # op_id -> set of pids
    _job_object_handle = None
    _job_initialized = False

    @classmethod
    def _init_job_object(cls):
        """Initializes a Windows Job Object bound to terminate all child processes on parent exit."""
        if cls._job_initialized or os.name != "nt":
            return
        cls._job_initialized = True
        try:
            kernel32 = ctypes.windll.kernel32
            h_job = kernel32.CreateJobObjectW(None, None)
            if not h_job:
                return

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('PerProcessUserTimeLimit', wintypes.LARGE_INTEGER),
                    ('PerJobUserTimeLimit', wintypes.LARGE_INTEGER),
                    ('LimitFlags', wintypes.DWORD),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', wintypes.DWORD),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', wintypes.DWORD),
                    ('SchedulingClass', wintypes.DWORD),
                ]

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ('ReadOperationCount', ctypes.c_uint64),
                    ('WriteOperationCount', ctypes.c_uint64),
                    ('OtherOperationCount', ctypes.c_uint64),
                    ('ReadTransferCount', ctypes.c_uint64),
                    ('WriteTransferCount', ctypes.c_uint64),
                    ('OtherTransferCount', ctypes.c_uint64),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ('IoInfo', IO_COUNTERS),
                    ('ProcessMemoryLimit', ctypes.c_size_t),
                    ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryLimit', ctypes.c_size_t),
                    ('PeakJobMemoryLimit', ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            # 0x2000 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            info.BasicLimitInformation.LimitFlags = 0x2000
            res = kernel32.SetInformationJobObject(
                h_job,
                9,  # JobObjectExtendedLimitInformation
                ctypes.byref(info),
                ctypes.sizeof(info)
            )
            if res:
                cls._job_object_handle = h_job
        except Exception:
            cls._job_object_handle = None

    @classmethod
    def _assign_to_job(cls, proc):
        """Assigns child process handle to Windows Job Object."""
        if not cls._job_object_handle or not hasattr(proc, "_handle") or not proc._handle:
            return
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.AssignProcessToJobObject(cls._job_object_handle, int(proc._handle))
        except Exception:
            pass

    @classmethod
    def register_process(cls, proc, op_id="global", description=""):
        """Registers a process under a specific operation ID."""
        cls._init_job_object()
        cls._assign_to_job(proc)

        pid = proc.pid if hasattr(proc, "pid") else proc
        if not pid:
            return None

        info = ProcessInfo(proc, op_id=op_id, description=description)
        with cls._lock:
            cls._tracked_processes[pid] = info
            if op_id not in cls._op_processes:
                cls._op_processes[op_id] = set()
            cls._op_processes[op_id].add(pid)
        return info

    @classmethod
    def register_pid(cls, pid, op_id="global", description=""):
        """Backward-compatible registration for raw PIDs."""
        if pid:
            return cls.register_process(pid, op_id=op_id, description=description)

    @classmethod
    def unregister_process(cls, proc, op_id=None, exit_code=None):
        """Unregisters a process and marks its terminal state."""
        pid = proc.pid if hasattr(proc, "pid") else proc
        if not pid:
            return

        with cls._lock:
            info = cls._tracked_processes.get(pid)
            if info:
                if exit_code is not None:
                    info.exit_code = exit_code
                elif hasattr(proc, "poll"):
                    info.exit_code = proc.poll()

                if info.status == "RUNNING":
                    info.status = "COMPLETED" if (info.exit_code == 0) else "FAILED"

                cls._tracked_processes.pop(pid, None)

            # Clean from op map
            for oid in list(cls._op_processes.keys()):
                cls._op_processes[oid].discard(pid)
                if not cls._op_processes[oid]:
                    cls._op_processes.pop(oid, None)

    @classmethod
    def unregister_pid(cls, pid):
        """Backward-compatible unregistration for raw PIDs."""
        if pid:
            cls.unregister_process(pid)

    @classmethod
    def terminate_process(cls, proc_or_pid, timeout=5):
        """
        Safely and strictly terminates a specific process and its process tree.
        Uses process PID only. Never uses process-name global termination.
        Handles already-terminated processes and captures exit codes.
        """
        pid = proc_or_pid.pid if hasattr(proc_or_pid, "pid") else proc_or_pid
        proc = proc_or_pid if hasattr(proc_or_pid, "poll") else None

        if not pid:
            return 0

        # Check if already terminated
        if proc and proc.poll() is not None:
            return proc.returncode

        # Terminate specific process tree by PID only
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=timeout
                )
            except Exception:
                pass
        else:
            try:
                if proc:
                    proc.kill()
                else:
                    os.kill(pid, 9)
            except Exception:
                pass

        # Wait and capture exit code
        if proc:
            try:
                proc.wait(timeout=timeout)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass
            return proc.returncode

        return 0

    @classmethod
    def cancel_operation(cls, op_id, timeout=5):
        """
        Cancels all active processes belonging to a specific operation ID.
        Terminates only processes registered under this op_id.
        """
        if not op_id:
            return []

        with cls._lock:
            pids = list(cls._op_processes.get(op_id, set()))

        cancelled_pids = []
        for pid in pids:
            with cls._lock:
                info = cls._tracked_processes.get(pid)
                if info:
                    info.status = "CANCELLED"
                proc_to_kill = info.proc if info else pid

            cls.terminate_process(proc_to_kill, timeout=timeout)
            cancelled_pids.append(pid)
            cls.unregister_process(proc_to_kill, op_id=op_id)

        return cancelled_pids

    @classmethod
    def kill_all_processes(cls, timeout=5):
        """
        Terminates ALL active CloudPool-owned child processes.
        Strictly operates on CloudPool-registered PIDs; NEVER executes
        global 'taskkill /IM rclone.exe' to prevent collateral damage.
        """
        with cls._lock:
            active_items = list(cls._tracked_processes.values())
            cls._tracked_processes.clear()
            cls._op_processes.clear()

        for info in active_items:
            try:
                cls.terminate_process(info.proc or info.pid, timeout=timeout)
            except Exception:
                pass

    @classmethod
    def get_active_processes(cls, op_id=None):
        """Returns list of currently running processes (pruning already terminated ones)."""
        active = []
        with cls._lock:
            pids = list(cls._tracked_processes.keys())

        for pid in pids:
            with cls._lock:
                info = cls._tracked_processes.get(pid)
            if not info:
                continue

            if op_id and info.op_id != op_id:
                continue

            # Poll process
            if hasattr(info.proc, "poll"):
                rc = info.proc.poll()
                if rc is not None:
                    # Already terminated
                    cls.unregister_process(info.proc)
                    continue

            active.append({
                "pid": info.pid,
                "op_id": info.op_id,
                "description": info.description,
                "status": info.status,
                "start_time": info.start_time
            })

        return active


# Register clean termination of all CloudPool child processes upon interpreter exit
atexit.register(ProcessManager.kill_all_processes)


class CryptoEngine:
    """Handles AES-256-GCM Encryption with DPAPI Protected Master Key."""
    def __init__(self, key=None):
        if key is not None:
            if not isinstance(key, (bytes, bytearray)):
                raise TypeError("Master key must be bytes or bytearray.")
            if len(key) != 32:
                raise ValueError(f"Invalid master key length: {len(key)} bytes (expected 32 bytes for AES-256).")
            self.key = bytes(key)
        else:
            self.key = self._load_or_create_key()
            if len(self.key) != 32:
                raise ValueError(f"Invalid master key length: {len(self.key)} bytes (expected 32 bytes for AES-256).")
        # Scale parallel workers to multi-core processor (up to 8 cores)
        self.num_workers = min(os.cpu_count() or 4, 8)

    def _load_or_create_key(self):
        """
        Loads the 256-bit AES master key, enforcing Windows DPAPI encryption.
        Provides a seamless, safe migration path from legacy plaintext master.key.
        """
        # 1. First priority: Load from DPAPI-protected store
        if os.path.exists(KEY_PATH_DPAPI) and is_dpapi_available():
            try:
                with open(KEY_PATH_DPAPI, "rb") as f:
                    enc_key = f.read()
                raw_key = dpapi_unprotect(enc_key)
                if len(raw_key) != 32:
                    raise ValueError(f"Invalid decrypted master key length: {len(raw_key)} bytes (expected 32).")
                return raw_key
            except Exception as e:
                print(f"[KEYSTORE WARNING] Failed to decrypt master.key.dpapi: {e}")

        # 2. Second priority: Migrate legacy plaintext master.key if it exists
        if os.path.exists(KEY_PATH):
            with open(KEY_PATH, "rb") as f:
                raw_key = f.read()
            if len(raw_key) != 32:
                raise ValueError(f"Invalid master.key length: {len(raw_key)} bytes (expected 32).")

            # Perform safe migration to DPAPI if available
            if is_dpapi_available():
                tmp_dpapi = KEY_PATH_DPAPI + ".tmp"
                try:
                    enc_blob = dpapi_protect(raw_key)
                    with open(tmp_dpapi, "wb") as f:
                        f.write(enc_blob)
                    # Verify readback immediately before touching old key
                    with open(tmp_dpapi, "rb") as f:
                        test_dec = dpapi_unprotect(f.read())
                    if test_dec != raw_key:
                        raise ValueError("DPAPI key verification failed during migration.")

                    # Atomic commit
                    os.replace(tmp_dpapi, KEY_PATH_DPAPI)
                    print("[KEYSTORE MIGRATION] Successfully secured master key with Windows DPAPI.")
                    # Keep legacy key backup safely as .migrated
                    migrated_backup = KEY_PATH + ".migrated"
                    if not os.path.exists(migrated_backup):
                        os.rename(KEY_PATH, migrated_backup)
                    else:
                        os.remove(KEY_PATH)
                except Exception as mig_err:
                    print(f"[KEYSTORE MIGRATION WARNING] DPAPI migration postponed: {mig_err}")
                    if os.path.exists(tmp_dpapi):
                        try:
                            os.remove(tmp_dpapi)
                        except Exception:
                            pass
            return raw_key

        # 3. Third priority: Generate new cryptographically secure 256-bit key
        new_key = os.urandom(32)
        if is_dpapi_available():
            try:
                enc_blob = dpapi_protect(new_key)
                with open(KEY_PATH_DPAPI, "wb") as f:
                    f.write(enc_blob)
                return new_key
            except Exception as e:
                print(f"[KEYSTORE WARNING] DPAPI protect failed for new key: {e}")

        # Fallback to direct file storage if DPAPI is unavailable
        with open(KEY_PATH, "wb") as f:
            f.write(new_key)
        return new_key

    def encrypt_data(self, data_bytes):
        """
        Encrypts data using AES-256-GCM with a unique 96-bit (12-byte) nonce.
        Returns: nonce (12 bytes) + ciphertext + authentication tag (16 bytes).
        """
        if not isinstance(data_bytes, (bytes, bytearray)):
            raise TypeError("Data to encrypt must be bytes or bytearray.")
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # Unique 96-bit nonce for each chunk
        ciphertext = aesgcm.encrypt(nonce, bytes(data_bytes), None)
        return nonce + ciphertext

    def decrypt_data(self, encrypted_bytes):
        """
        Decrypts AES-256-GCM encrypted data after verifying the 16-byte authentication tag.
        Raises InvalidTag if ciphertext, tag, or nonce has been altered.
        """
        if not isinstance(encrypted_bytes, (bytes, bytearray)):
            raise TypeError("Encrypted data must be bytes or bytearray.")
        if len(encrypted_bytes) < 28:
            raise ValueError(f"Ciphertext too short: {len(encrypted_bytes)} bytes (minimum 28 bytes required for 12-byte nonce + 16-byte tag).")
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
    def derive_key(passphrase, salt=None, iterations=PBKDF2_ITERATIONS_V2, version=BACKUP_VERSION_CURRENT):
        """
        Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
        Version 2: 600,000 iterations with unique 16-byte cryptographically secure salt.
        Version 1: Legacy support with 100,000 iterations.
        Returns: (derived_key: bytes, salt: bytes, iterations: int)
        """
        if not passphrase:
            raise ValueError("Passphrase cannot be empty for key derivation.")
        if not isinstance(passphrase, str):
            if isinstance(passphrase, bytes):
                passphrase = passphrase.decode("utf-8")
            else:
                raise TypeError("Passphrase must be a string or utf-8 bytes.")

        if version == 1:
            salt = salt or METADATA_SALT_LEGACY
            iterations = iterations or PBKDF2_ITERATIONS_V1
        else:
            if salt is None:
                salt = os.urandom(16)
            iterations = iterations or PBKDF2_ITERATIONS_V2

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        derived = kdf.derive(passphrase.encode("utf-8"))
        return derived, salt, iterations

    @staticmethod
    def export_encrypted_backup(passphrase, backup_path=None):
        """
        Bundles cloudpool_master.db and decrypted master.key into a versioned,
        AES-256-GCM encrypted package authenticated with PBKDF2-HMAC-SHA256.
        Requires a user-defined passphrase.
        """
        if not passphrase:
            raise ValueError("A user-defined recovery passphrase is required to export metadata backup.")

        if not os.path.exists(DB_PATH):
            return None

        # Obtain the master key from CryptoEngine
        crypto = CryptoEngine()
        master_key_bytes = crypto.key

        # Ensure WAL is checkpointed into DB_PATH before reading raw file bytes
        try:
            with sqlite3.connect(DB_PATH) as checkpoint_conn:
                checkpoint_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass

        with open(DB_PATH, "rb") as f:
            db_bytes = f.read()

        payload = json.dumps({
            "version": BACKUP_VERSION_CURRENT,
            "created_at": datetime.utcnow().isoformat(),
            "master_key_b64": base64.b64encode(master_key_bytes).decode("utf-8"),
            "db_b64": base64.b64encode(db_bytes).decode("utf-8")
        }).encode("utf-8")

        # Derive key with fresh random 16-byte salt and 600,000 iterations
        salt = os.urandom(16)
        iterations = PBKDF2_ITERATIONS_V2
        derived_key, salt, iterations = MetadataEngine.derive_key(
            passphrase, salt=salt, iterations=iterations, version=BACKUP_VERSION_CURRENT
        )

        # Construct Header (27 bytes prefix)
        # MAGIC(4) + VERSION(1) + KDF_ID(1) + ITERATIONS(4) + SALT_LEN(1) + SALT(16)
        header_prefix = (
            BACKUP_MAGIC +
            bytes([BACKUP_VERSION_CURRENT]) +
            bytes([1]) +  # 1 = PBKDF2-HMAC-SHA256
            iterations.to_bytes(4, byteorder="big") +
            bytes([len(salt)]) +
            salt
        )

        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        # Authenticate header_prefix as Associated Data (AAD)
        ciphertext = aesgcm.encrypt(nonce, payload, associated_data=header_prefix)

        # Full package = header_prefix (27 bytes) + nonce (12 bytes) + ciphertext + tag
        encrypted_pkg = header_prefix + nonce + ciphertext

        target_path = backup_path or os.path.join(VAULT_DIR, "cloudpool_metadata.enc")
        with open(target_path, "wb") as f:
            f.write(encrypted_pkg)
        return target_path

    @staticmethod
    def import_encrypted_backup(backup_bytes, passphrase):
        """
        Decrypts a metadata package and restores master.key (DPAPI protected) and cloudpool_master.db.
        Supports both Version 2 (Authenticated Header) and Version 1 (Legacy).
        Raises InvalidTag on incorrect passphrase or tampered ciphertext.
        """
        if not passphrase:
            raise ValueError("Passphrase is required to import metadata backup.")
        if not backup_bytes or len(backup_bytes) < 28:
            raise ValueError("Corrupted or invalid metadata backup payload (too short).")

        decrypted_json = None

        # Check for Version 2 header: MAGIC "CPBK"
        if backup_bytes.startswith(BACKUP_MAGIC):
            if len(backup_bytes) < 40:  # 27 header + 12 nonce + minimum tag
                raise ValueError("Corrupted backup package: truncated header.")

            version = backup_bytes[4]
            if version != 2:
                raise ValueError(f"Unsupported backup version: {version}. This application supports version 1 and 2.")

            kdf_id = backup_bytes[5]
            if kdf_id != 1:
                raise ValueError(f"Unsupported KDF algorithm identifier: {kdf_id}.")

            iterations = int.from_bytes(backup_bytes[6:10], byteorder="big")
            salt_len = backup_bytes[10]
            salt_end = 11 + salt_len
            salt = backup_bytes[11:salt_end]
            header_prefix = backup_bytes[:salt_end]

            nonce = backup_bytes[salt_end:salt_end + 12]
            ciphertext = backup_bytes[salt_end + 12:]

            derived_key, _, _ = MetadataEngine.derive_key(
                passphrase, salt=salt, iterations=iterations, version=2
            )
            aesgcm = AESGCM(derived_key)
            # AESGCM automatically verifies authentication tag and header_prefix AAD
            payload_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=header_prefix)
            decrypted_json = payload_bytes.decode("utf-8")

        else:
            # Fallback: Version 1 (Legacy format: 12-byte nonce + AES-GCM ciphertext with static salt)
            try:
                derived_key, _, _ = MetadataEngine.derive_key(
                    passphrase, salt=METADATA_SALT_LEGACY, iterations=PBKDF2_ITERATIONS_V1, version=1
                )
                aesgcm = AESGCM(derived_key)
                nonce = backup_bytes[:12]
                ciphertext = backup_bytes[12:]
                payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                decrypted_json = payload_bytes.decode("utf-8")
            except Exception:
                # If both formats fail, raise clear authentication failure
                raise InvalidTag("Decryption failed: Incorrect recovery passphrase or corrupted backup.")

        data = json.loads(decrypted_json)
        key_bytes = base64.b64decode(data["master_key_b64"])
        db_bytes = base64.b64decode(data["db_b64"])

        if len(key_bytes) != 32:
            raise ValueError(f"Corrupted master key in backup: {len(key_bytes)} bytes (expected 32).")

        # Save master key with DPAPI protection
        if is_dpapi_available():
            enc_blob = dpapi_protect(key_bytes)
            with open(KEY_PATH_DPAPI, "wb") as f:
                f.write(enc_blob)
            if os.path.exists(KEY_PATH):
                try:
                    os.remove(KEY_PATH)
                except Exception:
                    pass
        else:
            with open(KEY_PATH, "wb") as f:
                f.write(key_bytes)

        # Restore database and clean up any old WAL / SHM files
        for ext in ["-wal", "-shm"]:
            wal_file = DB_PATH + ext
            if os.path.exists(wal_file):
                try:
                    os.remove(wal_file)
                except Exception:
                    pass

        with open(DB_PATH, "wb") as f:
            f.write(db_bytes)

        return True

    @staticmethod
    def sync_metadata_to_cloud(db, passphrase=None):
        """
        Silently syncs encrypted metadata backup to 2 independent cloud accounts under :CloudPool_Meta/.
        Requires a user recovery passphrase. Never uses a hardcoded default passphrase.
        """
        if not passphrase:
            passphrase = os.environ.get("CLOUDPOOL_RECOVERY_PASSPHRASE")
            if not passphrase:
                # Security hardening: never silently encrypt with a public default passphrase
                return []

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
    def restore_metadata_from_cloud(passphrase):
        """Disaster Recovery: Fetches the encrypted metadata backup from any configured remote and restores state."""
        if not passphrase:
            raise ValueError("A recovery passphrase is required for disaster recovery.")
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


class ArchiveSecurityError(Exception):
    """Base exception for archive extraction security violations."""
    pass


class PathTraversalError(ArchiveSecurityError):
    """Raised when an archive entry attempts directory traversal."""
    pass


class DiskSpaceError(ArchiveSecurityError):
    """Raised when destination storage has insufficient free space."""
    pass


class ArchiveBombError(ArchiveSecurityError):
    """Raised when an archive exceeds size or member count limits."""
    pass


class DuplicateArchiveEntryError(ArchiveSecurityError):
    """Raised when an archive contains duplicate member names and overwriting is disallowed."""
    pass


class ParityPlacementError(Exception):
    """Raised when RAID-5 parity cannot be placed on an independent cloud failure domain."""
    pass


class SafeTarExtractor:
    """
    Secure TAR Archive Extractor for CloudPool Virtual Archives:
    - Pre-validates all members before extracting any bytes.
    - Strictly rejects path traversal (../, absolute POSIX/Windows, drive letters, UNC, ADS colons, null bytes).
    - Blocks Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) and trailing dots/spaces.
    - Rejects symlinks and hardlinks pointing outside the destination root.
    - Prohibits special device entries (FIFOs, character/block devices).
    - Enforces member count limits, total uncompressed size limits, and single-file size limits (bomb protection).
    - Verifies available destination disk space before extraction.
    - Performs atomic directory extraction via an isolated staging sandbox.
    - Cleans up temporary resources reliably on failure or cancellation.
    - Independent of Python 3.12+ tarfile.data_filter, ensuring full backward and forward compatibility.
    """

    RESERVED_DEVICE_NAMES = frozenset(
        {'CON', 'PRN', 'AUX', 'NUL'} |
        {f'COM{i}' for i in range(1, 10)} |
        {f'LPT{i}' for i in range(1, 10)}
    )

    DEFAULT_MAX_FILE_COUNT = 10000
    DEFAULT_MAX_TOTAL_SIZE = 50 * 1024 * 1024 * 1024  # 50 GB
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024   # 10 GB
    DEFAULT_DISK_MARGIN = 50 * 1024 * 1024            # 50 MB safety margin

    @classmethod
    def is_safe_relative_path(cls, path: str) -> tuple[bool, str]:
        """
        Validates whether a path is a safe relative path for extraction.
        Returns (is_safe: bool, reason: str).
        """
        if not path or not isinstance(path, str):
            return False, "Path is empty or not a string"

        if '\0' in path:
            return False, "Null byte detected in path"

        norm = path.replace('\\', '/').strip()
        if not norm:
            return False, "Path is empty after normalization"

        # Check absolute or UNC
        if norm.startswith('/') or norm.startswith('//'):
            return False, "Absolute POSIX or UNC path is not permitted"
        if path.startswith('\\\\') or path.startswith('//'):
            return False, "UNC path is not permitted"

        # Check drive letters (C:, D:, c:foo, etc.)
        if os.path.splitdrive(path)[0] or re.match(r'^[a-zA-Z]:', norm):
            return False, "Windows drive letter is not permitted"

        # Component-by-component inspection
        parts = norm.split('/')
        for part in parts:
            if part in ('', '.'):
                continue
            if part == '..':
                return False, "Parent directory traversal ('..') detected"
            if ':' in part:
                return False, "Alternate Data Stream or colon detected"
            if part.endswith('.') or part.endswith(' ') or part.startswith(' '):
                return False, "Trailing or leading dot/space detected in component"
            stem = part.split('.')[0].upper()
            if stem in cls.RESERVED_DEVICE_NAMES:
                return False, f"Windows reserved device name detected: '{stem}'"
            if len(part) > 255:
                return False, f"Path component exceeds 255 characters: '{part[:30]}...'"

        return True, "Safe"

    @classmethod
    def validate_path(cls, path: str):
        """Raises PathTraversalError if path is unsafe."""
        is_safe, reason = cls.is_safe_relative_path(path)
        if not is_safe:
            raise PathTraversalError(f"Unsafe archive path '{path}': {reason}")

    @classmethod
    def validate_member(
        cls,
        member: tarfile.TarInfo,
        dest_dir: str,
        seen_paths: set = None,
        overwrite: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE
    ) -> str:
        """
        Validates an individual archive member against security rules.
        Returns the canonical target path.
        """
        cls.validate_path(member.name)

        # Disallow dangerous or special file types
        if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
            raise ArchiveSecurityError(
                f"Extraction of special device file '{member.name}' (type {member.type}) is prohibited."
            )

        canonical_dest = os.path.realpath(os.path.abspath(dest_dir))
        target_path = os.path.realpath(os.path.abspath(os.path.join(canonical_dest, member.name)))

        # Canonical path must reside strictly within canonical destination
        try:
            common = os.path.commonpath([canonical_dest, target_path])
        except ValueError:
            # Different drives on Windows (e.g., C: vs D:)
            raise PathTraversalError(f"Member '{member.name}' target crosses filesystem roots")

        if common != canonical_dest:
            raise PathTraversalError(
                f"Member '{member.name}' escapes destination root '{dest_dir}'"
            )

        # Handle symlinks and hardlinks
        if member.issym() or member.islnk():
            link_target = member.linkname
            if not link_target:
                raise PathTraversalError(f"Link member '{member.name}' has empty link target")

            # Check for drive letter / absolute path in link target
            if (link_target.startswith('/') or link_target.startswith('\\')
                    or os.path.splitdrive(link_target)[0] or re.match(r'^[a-zA-Z]:', link_target)):
                raise PathTraversalError(f"Link member '{member.name}' points to absolute/drive path: '{link_target}'")
            if '\0' in link_target or ':' in link_target:
                raise PathTraversalError(f"Link member '{member.name}' contains invalid characters in link target")

            # Resolve link target relative to member's parent directory
            member_parent = os.path.dirname(target_path)
            resolved_link = os.path.realpath(os.path.abspath(os.path.join(member_parent, link_target)))
            try:
                link_common = os.path.commonpath([canonical_dest, resolved_link])
            except ValueError:
                raise PathTraversalError(f"Link '{member.name}' -> '{link_target}' crosses drive roots")

            if link_common != canonical_dest:
                raise PathTraversalError(
                    f"Link member '{member.name}' -> '{link_target}' resolves outside extraction root"
                )

        # Check individual file size limit
        if member.size > max_file_size:
            raise ArchiveBombError(
                f"Member '{member.name}' size ({member.size} bytes) exceeds maximum file limit ({max_file_size} bytes)"
            )

        # Check duplicate member names
        norm_name = os.path.normpath(member.name.replace('\\', '/')).lower()
        if seen_paths is not None:
            if norm_name in seen_paths and not overwrite:
                raise DuplicateArchiveEntryError(
                    f"Duplicate entry detected in archive: '{member.name}'"
                )
            seen_paths.add(norm_name)

        return target_path

    @classmethod
    def check_disk_space(cls, dest_dir: str, required_bytes: int, margin: int = DEFAULT_DISK_MARGIN):
        """Verifies that the target filesystem has sufficient free bytes."""
        probe = os.path.abspath(dest_dir)
        while not os.path.exists(probe):
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent

        try:
            free_bytes = shutil.disk_usage(probe).free
        except Exception:
            # If disk usage cannot be determined, proceed safely
            return

        needed = required_bytes + margin
        if free_bytes < needed:
            raise DiskSpaceError(
                f"Insufficient disk space in '{probe}': requires {needed:,} bytes "
                f"({required_bytes:,} uncompressed + {margin:,} margin), but only {free_bytes:,} bytes free."
            )

    @classmethod
    def extract_archive(
        cls,
        tar: tarfile.TarFile,
        dest_dir: str,
        overwrite: bool = True,
        max_file_count: int = DEFAULT_MAX_FILE_COUNT,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        disk_margin: int = DEFAULT_DISK_MARGIN
    ) -> str:
        """
        Securely extracts all entries from a TAR archive into dest_dir:
        1. Pre-scans and validates all members.
        2. Enforces archive size, count, and disk space limits.
        3. Extracts to an isolated temporary directory.
        4. Atomically merges/replaces into dest_dir.
        5. Cleans up staging resources on completion or failure.
        """
        members = tar.getmembers()
        if len(members) > max_file_count:
            raise ArchiveBombError(
                f"Archive contains {len(members)} files, exceeding limit of {max_file_count}"
            )

        total_uncompressed = sum(m.size for m in members if m.isreg() or m.islnk())
        if total_uncompressed > max_total_size:
            raise ArchiveBombError(
                f"Archive uncompressed size ({total_uncompressed} bytes) exceeds limit ({max_total_size} bytes)"
            )

        cls.check_disk_space(dest_dir, total_uncompressed, margin=disk_margin)

        # Pre-validate all members before writing anything
        seen_paths = set()
        for member in members:
            cls.validate_member(
                member,
                dest_dir,
                seen_paths=seen_paths,
                overwrite=overwrite,
                max_file_size=max_file_size
            )

        # Isolated staging directory
        dest_parent = os.path.dirname(os.path.abspath(dest_dir))
        if os.path.exists(dest_parent):
            stage_base = dest_parent
        else:
            stage_base = tempfile.gettempdir()

        stage_dir = tempfile.mkdtemp(prefix="cpv_stage_", dir=stage_base)
        try:
            canonical_stage = os.path.realpath(os.path.abspath(stage_dir))

            for member in members:
                # Target path in stage_dir
                stage_target = os.path.realpath(os.path.abspath(os.path.join(canonical_stage, member.name)))
                if os.path.commonpath([canonical_stage, stage_target]) != canonical_stage:
                    raise PathTraversalError(f"Staged path escapes sandbox: '{member.name}'")

                if member.isdir():
                    os.makedirs(stage_target, exist_ok=True)
                elif member.isreg():
                    os.makedirs(os.path.dirname(stage_target), exist_ok=True)
                    f_in = tar.extractfile(member)
                    if f_in is not None:
                        bytes_written = 0
                        with open(stage_target, "wb") as f_out:
                            while True:
                                chunk = f_in.read(65536)
                                if not chunk:
                                    break
                                bytes_written += len(chunk)
                                if bytes_written > max_file_size:
                                    raise ArchiveBombError(
                                        f"File '{member.name}' exceeded max size during extraction"
                                    )
                                f_out.write(chunk)
                        f_in.close()
                elif member.issym():
                    os.makedirs(os.path.dirname(stage_target), exist_ok=True)
                    try:
                        os.symlink(member.linkname, stage_target)
                    except OSError:
                        pass
                elif member.islnk():
                    os.makedirs(os.path.dirname(stage_target), exist_ok=True)
                    src_link = os.path.join(os.path.dirname(stage_target), member.linkname)
                    if os.path.exists(src_link):
                        try:
                            os.link(src_link, stage_target)
                        except OSError:
                            shutil.copy2(src_link, stage_target)

            # Atomic merge / copy to dest_dir
            cls._merge_staging_to_dest(stage_dir, dest_dir, overwrite=overwrite)
            return dest_dir

        finally:
            if os.path.exists(stage_dir):
                shutil.rmtree(stage_dir, ignore_errors=True)

    @classmethod
    def _merge_staging_to_dest(cls, stage_dir: str, dest_dir: str, overwrite: bool = True):
        """Merges staging directory contents into final dest_dir."""
        os.makedirs(dest_dir, exist_ok=True)
        for root, dirs, files in os.walk(stage_dir):
            rel = os.path.relpath(root, stage_dir)
            target_sub = dest_dir if rel == "." else os.path.join(dest_dir, rel)
            os.makedirs(target_sub, exist_ok=True)

            for f in files:
                src_file = os.path.join(root, f)
                dst_file = os.path.join(target_sub, f)

                if os.path.exists(dst_file) and not overwrite:
                    raise DuplicateArchiveEntryError(f"Destination file already exists: {dst_file}")

                try:
                    os.replace(src_file, dst_file)
                except OSError:
                    shutil.copy2(src_file, dst_file)
                    try:
                        os.remove(src_file)
                    except OSError:
                        pass

    @classmethod
    def extract_single_file(
        cls,
        tar: tarfile.TarFile,
        member_name: str,
        dest_file_path: str,
        overwrite: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE
    ) -> str:
        """
        Securely extracts a single named member from a TAR archive to dest_file_path.
        """
        cls.validate_path(member_name)
        norm_target_name = member_name.replace('\\', '/')

        matched_member = None
        for m in tar.getmembers():
            if m.name.replace('\\', '/') == norm_target_name:
                matched_member = m
                break

        if not matched_member:
            raise FileNotFoundError(f"Member '{member_name}' not found in archive")

        dest_dir = os.path.dirname(os.path.abspath(dest_file_path))
        os.makedirs(dest_dir, exist_ok=True)
        cls.validate_member(matched_member, dest_dir, overwrite=overwrite, max_file_size=max_file_size)

        cls.check_disk_space(dest_dir, matched_member.size)

        if os.path.exists(dest_file_path) and not overwrite:
            raise DuplicateArchiveEntryError(f"Destination file already exists: {dest_file_path}")

        tmp_dest = dest_file_path + f".cpv_tmp_{uuid.uuid4().hex[:8]}"
        try:
            f_in = tar.extractfile(matched_member)
            if f_in is None:
                raise ArchiveSecurityError(f"Member '{member_name}' is not extractable as a file")

            bytes_written = 0
            with open(tmp_dest, "wb") as f_out:
                while True:
                    chunk = f_in.read(65536)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > max_file_size:
                        raise ArchiveBombError(f"File '{member_name}' exceeded size limit during extraction")
                    f_out.write(chunk)
            f_in.close()

            os.replace(tmp_dest, dest_file_path)
            return dest_file_path
        finally:
            if os.path.exists(tmp_dest):
                try:
                    os.remove(tmp_dest)
                except OSError:
                    pass


class FileIntegrityError(Exception):
    """Raised when SHA-256 end-to-end file or chunk integrity verification fails."""
    pass


class IntegrityEngine:
    """
    End-to-End Cryptographic Integrity Verification Engine:
    - Calculates streaming SHA-256 hashes without exhausting physical RAM.
    - Computes and verifies SHA-256 ciphertext checksums before decryption.
    - Validates reconstructed RAID-5 chunks.
    - Validates complete restored files against original hashes.
    - Constant-time hash comparisons via hmac.compare_digest.
    """

    DEFAULT_BLOCK_SIZE = 65536  # 64 KB blocks

    @classmethod
    def compute_stream_sha256(cls, stream_or_path, block_size=DEFAULT_BLOCK_SIZE) -> str:
        """
        Calculates SHA-256 hex digest for a file path or readable stream.
        Preserves stream position if seekable.
        """
        hasher = hashlib.sha256()

        if isinstance(stream_or_path, (str, os.PathLike)):
            with open(stream_or_path, "rb") as f:
                while True:
                    block = f.read(block_size)
                    if not block:
                        break
                    hasher.update(block)
        else:
            orig_pos = None
            if hasattr(stream_or_path, "seekable") and stream_or_path.seekable():
                try:
                    orig_pos = stream_or_path.tell()
                    stream_or_path.seek(0)
                except Exception:
                    orig_pos = None

            while True:
                block = stream_or_path.read(block_size)
                if not block:
                    break
                hasher.update(block)

            if orig_pos is not None:
                try:
                    stream_or_path.seek(orig_pos)
                except Exception:
                    pass

        return hasher.hexdigest()

    @classmethod
    def compute_bytes_sha256(cls, data: bytes) -> str:
        """Calculates SHA-256 hex digest for in-memory bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data to hash must be bytes or bytearray.")
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def verify_hash(cls, actual_hash: str, expected_hash: str) -> bool:
        """Constant-time comparison of two hex digest strings."""
        if not actual_hash or not expected_hash:
            return False
        return hmac.compare_digest(actual_hash.strip().lower(), expected_hash.strip().lower())


class DatabaseEngine:
    """
    Manages the SQLite map of where all your chunks are stored.

    Thread-Safety Model
    -------------------
    Each calling thread receives its own dedicated SQLite connection via
    threading.local().  Sharing a single connection across threads (even with
    check_same_thread=False) causes lock races under concurrent uploads /
    downloads.  Thread-local connections eliminate this entirely.

    Every connection is configured with:
    - PRAGMA journal_mode = WAL   → concurrent readers never block a writer
    - PRAGMA foreign_keys = ON    → referential integrity always enforced
    - PRAGMA busy_timeout = 30000 → retry for up to 30 s before SQLITE_BUSY

    Schema versioning uses PRAGMA user_version.  Migrations are applied in
    order at startup; each migration runs inside a single atomic transaction
    so a mid-migration crash leaves the schema unchanged.
    """

    # Bump this when you add a new migration step below.
    SCHEMA_VERSION = 3

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._local = threading.local()   # thread-local connection storage
        self._write_lock = threading.Lock()  # serialise writes for SQLite WAL safety

        # Run schema migration on the initialising thread's connection.
        conn = self._get_conn()
        self._run_migrations(conn)

        self.cleanup_incomplete_uploads()
        self.recover_interrupted_deletions()
        self.prune_ghost_remotes()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self):
        """
        Returns the SQLite connection for the current thread, creating and
        configuring it on first access.  Each thread owns exactly one
        connection; the connection is closed when the thread exits.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=True,   # Correctly restrict to owning thread
                timeout=30                # Mirrors busy_timeout for Python-level waits
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = conn
        return conn

    @property
    def conn(self):
        """
        Backward-compatibility shim: code that accesses self.conn directly
        gets the thread-local connection transparently.
        """
        return self._get_conn()

    # ------------------------------------------------------------------
    # Schema migration runner
    # ------------------------------------------------------------------

    def _run_migrations(self, conn):
        """
        Applies all pending schema migrations sequentially and atomically.
        Each migration step is wrapped in its own transaction.  On failure
        the transaction is rolled back and the error is re-raised, leaving
        user_version unchanged so the next start retries.
        """
        cur = conn.execute("PRAGMA user_version")
        current_version = cur.fetchone()[0]

        migrations = [
            self._migrate_v0_to_v1,
            self._migrate_v1_to_v2,
            self._migrate_v2_to_v3,
        ]

        for step_index, migration_fn in enumerate(migrations):
            target_version = step_index + 1
            if current_version >= target_version:
                continue  # Already applied
            try:
                conn.execute("BEGIN")
                migration_fn(conn)
                conn.execute(f"PRAGMA user_version = {target_version}")
                conn.execute("COMMIT")
                current_version = target_version
            except Exception as exc:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise RuntimeError(
                    f"[DB MIGRATION] Failed upgrading schema from v{current_version} "
                    f"to v{target_version}: {exc}"
                ) from exc

    def _migrate_v0_to_v1(self, conn):
        """
        Initial full schema creation (v0 → v1).
        All CREATE TABLE IF NOT EXISTS plus any ALTER TABLE
        migrations needed to handle existing databases created before
        schema versioning was introduced.
        """
        # Table 1: Connected Rclone accounts
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cloud_accounts (
                account_name TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                usable_capacity_bytes INTEGER NOT NULL,
                used_bytes INTEGER DEFAULT 0,
                reliability_tier TEXT NOT NULL,
                priority INTEGER DEFAULT 1,
                status TEXT DEFAULT 'CONNECTED',
                provider_used_bytes INTEGER,
                provider_total_bytes INTEGER,
                last_sync_time TEXT
            )
        """)
        cols = {c[1] for c in conn.execute("PRAGMA table_info(cloud_accounts)").fetchall()}
        if "priority" not in cols:
            conn.execute("ALTER TABLE cloud_accounts ADD COLUMN priority INTEGER DEFAULT 1")
        if "status" not in cols:
            conn.execute("ALTER TABLE cloud_accounts ADD COLUMN status TEXT DEFAULT 'CONNECTED'")
        if "provider_used_bytes" not in cols:
            conn.execute("ALTER TABLE cloud_accounts ADD COLUMN provider_used_bytes INTEGER")
        if "provider_total_bytes" not in cols:
            conn.execute("ALTER TABLE cloud_accounts ADD COLUMN provider_total_bytes INTEGER")
        if "last_sync_time" not in cols:
            conn.execute("ALTER TABLE cloud_accounts ADD COLUMN last_sync_time TEXT")

        # Table 2: Virtual Folders
        conn.execute("""
            CREATE TABLE IF NOT EXISTS virtual_folders (
                folder_id TEXT PRIMARY KEY,
                folder_name TEXT NOT NULL,
                parent_folder_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_folder_id) REFERENCES virtual_folders(folder_id) ON DELETE CASCADE
            )
        """)

        # Table 3: Virtual Files
        conn.execute("""
            CREATE TABLE IF NOT EXISTS virtual_files (
                file_id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                total_size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                folder_id TEXT,
                container_id TEXT,
                is_container INTEGER DEFAULT 0,
                relative_path TEXT,
                deletion_status TEXT DEFAULT 'active',
                upload_status TEXT DEFAULT 'completed',
                file_hash TEXT,
                hash_algorithm TEXT DEFAULT 'SHA-256',
                integrity_status TEXT DEFAULT 'unverified',
                FOREIGN KEY(folder_id) REFERENCES virtual_folders(folder_id) ON DELETE SET NULL
            )
        """)
        vf_cols = {c[1] for c in conn.execute("PRAGMA table_info(virtual_files)").fetchall()}
        for col, defn in [
            ("folder_id",       "ALTER TABLE virtual_files ADD COLUMN folder_id TEXT"),
            ("container_id",    "ALTER TABLE virtual_files ADD COLUMN container_id TEXT"),
            ("is_container",    "ALTER TABLE virtual_files ADD COLUMN is_container INTEGER DEFAULT 0"),
            ("relative_path",   "ALTER TABLE virtual_files ADD COLUMN relative_path TEXT"),
            ("deletion_status", "ALTER TABLE virtual_files ADD COLUMN deletion_status TEXT DEFAULT 'active'"),
            ("upload_status",   "ALTER TABLE virtual_files ADD COLUMN upload_status TEXT DEFAULT 'completed'"),
            ("file_hash",       "ALTER TABLE virtual_files ADD COLUMN file_hash TEXT"),
            ("hash_algorithm",  "ALTER TABLE virtual_files ADD COLUMN hash_algorithm TEXT DEFAULT 'SHA-256'"),
            ("integrity_status","ALTER TABLE virtual_files ADD COLUMN integrity_status TEXT DEFAULT 'unverified'"),
        ]:
            if col not in vf_cols:
                conn.execute(defn)

        # Table 4: File chunks & parity blocks
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_chunks (
                chunk_id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                account_name TEXT NOT NULL,
                part_number INTEGER NOT NULL,
                chunk_size_bytes INTEGER DEFAULT 0,
                encrypted_size_bytes INTEGER DEFAULT 0,
                is_parity INTEGER DEFAULT 0,
                ciphertext_hash TEXT,
                FOREIGN KEY(file_id) REFERENCES virtual_files(file_id) ON DELETE CASCADE,
                FOREIGN KEY(account_name) REFERENCES cloud_accounts(account_name)
            )
        """)
        fc_cols = {c[1] for c in conn.execute("PRAGMA table_info(file_chunks)").fetchall()}
        for col, defn in [
            ("chunk_size_bytes",     "ALTER TABLE file_chunks ADD COLUMN chunk_size_bytes INTEGER DEFAULT 0"),
            ("encrypted_size_bytes", "ALTER TABLE file_chunks ADD COLUMN encrypted_size_bytes INTEGER DEFAULT 0"),
            ("is_parity",            "ALTER TABLE file_chunks ADD COLUMN is_parity INTEGER DEFAULT 0"),
            ("ciphertext_hash",      "ALTER TABLE file_chunks ADD COLUMN ciphertext_hash TEXT"),
        ]:
            if col not in fc_cols:
                conn.execute(defn)

        # Table 5: Deletion jobs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deletion_jobs (
                job_id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                total_chunks INTEGER NOT NULL,
                deleted_chunks INTEGER DEFAULT 0,
                failed_chunks INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Table 6: Upload journal
        conn.execute("""
            CREATE TABLE IF NOT EXISTS upload_journal (
                op_id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                total_size_bytes INTEGER NOT NULL,
                target_tier TEXT DEFAULT 'STABLE',
                target_folder_id TEXT,
                enable_parity INTEGER DEFAULT 1,
                total_expected_chunks INTEGER NOT NULL,
                data_chunks_count INTEGER NOT NULL,
                is_container INTEGER DEFAULT 0,
                relative_path TEXT,
                file_hash TEXT,
                hash_algorithm TEXT DEFAULT 'SHA-256',
                status TEXT CHECK(status IN ('preparing','uploading','uploading_parity','verifying','committing','completed','rolling_back','rolled_back','failed')),
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        uj_cols = {c[1] for c in conn.execute("PRAGMA table_info(upload_journal)").fetchall()}
        for col, defn in [
            ("file_hash",      "ALTER TABLE upload_journal ADD COLUMN file_hash TEXT"),
            ("hash_algorithm", "ALTER TABLE upload_journal ADD COLUMN hash_algorithm TEXT DEFAULT 'SHA-256'"),
        ]:
            if col not in uj_cols:
                conn.execute(defn)

        # Table 7: Upload journal chunks
        conn.execute("""
            CREATE TABLE IF NOT EXISTS upload_journal_chunks (
                op_id TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                account_name TEXT NOT NULL,
                part_number INTEGER NOT NULL,
                chunk_size_bytes INTEGER NOT NULL,
                encrypted_size_bytes INTEGER DEFAULT 0,
                is_parity INTEGER DEFAULT 0,
                ciphertext_hash TEXT,
                status TEXT CHECK(status IN ('pending','uploading','uploaded','committed','rolled_back','failed')),
                uploaded_at TEXT,
                error_message TEXT,
                PRIMARY KEY (op_id, chunk_id),
                FOREIGN KEY(op_id) REFERENCES upload_journal(op_id) ON DELETE CASCADE
            )
        """)
        ujc_cols = {c[1] for c in conn.execute("PRAGMA table_info(upload_journal_chunks)").fetchall()}
        if "ciphertext_hash" not in ujc_cols:
            conn.execute("ALTER TABLE upload_journal_chunks ADD COLUMN ciphertext_hash TEXT")
        if "encrypted_size_bytes" not in ujc_cols:
            conn.execute("ALTER TABLE upload_journal_chunks ADD COLUMN encrypted_size_bytes INTEGER DEFAULT 0")

        # Table 8: Folder upload journal
        conn.execute("""
            CREATE TABLE IF NOT EXISTS folder_upload_journal (
                folder_op_id TEXT PRIMARY KEY,
                root_folder_name TEXT NOT NULL,
                parent_folder_id TEXT,
                created_root_folder_id TEXT,
                container_id TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                status TEXT CHECK(status IN ('preparing','archiving','uploading','verifying','committing','committed','rolling_back','rolled_back','failed')),
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Indexes for query performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_file_chunks_file_id ON file_chunks(file_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_file_chunks_account ON file_chunks(account_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_virtual_files_folder ON virtual_files(folder_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_upload_journal_status ON upload_journal(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deletion_jobs_status ON deletion_jobs(status)")

    def _migrate_v1_to_v2(self, conn):
        """
        v1 → v2: Add schema_migrations audit log table for future traceability.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL,
                description TEXT
            )
        """)
        now = datetime.utcnow().isoformat()
        conn.execute("""
            INSERT OR IGNORE INTO schema_migrations (version, applied_at, description)
            VALUES (1, ?, 'Initial full schema + indexes')
        """, (now,))
        conn.execute("""
            INSERT OR IGNORE INTO schema_migrations (version, applied_at, description)
            VALUES (2, ?, 'Added schema_migrations audit table')
        """, (now,))

    def _migrate_v2_to_v3(self, conn):
        """
        v2 → v3: Add encrypted_size_bytes to file_chunks & upload_journal_chunks,
        add provider quota tracking columns to cloud_accounts,
        and backfill encrypted_size_bytes for pre-v3 chunks.
        Defensively checks for table presence to support legacy minimal databases.
        """
        # Ensure schema_migrations table exists (from v2)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL,
                description TEXT
            )
        """)

        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        # 1. Update file_chunks if present
        if "file_chunks" in tables:
            fc_cols = {c[1] for c in conn.execute("PRAGMA table_info(file_chunks)").fetchall()}
            if "encrypted_size_bytes" not in fc_cols:
                conn.execute("ALTER TABLE file_chunks ADD COLUMN encrypted_size_bytes INTEGER DEFAULT 0")
            conn.execute("""
                UPDATE file_chunks
                SET encrypted_size_bytes = chunk_size_bytes + 28
                WHERE encrypted_size_bytes IS NULL OR encrypted_size_bytes = 0
            """)

        # 2. Update upload_journal_chunks if present
        if "upload_journal_chunks" in tables:
            ujc_cols = {c[1] for c in conn.execute("PRAGMA table_info(upload_journal_chunks)").fetchall()}
            if "encrypted_size_bytes" not in ujc_cols:
                conn.execute("ALTER TABLE upload_journal_chunks ADD COLUMN encrypted_size_bytes INTEGER DEFAULT 0")
            conn.execute("""
                UPDATE upload_journal_chunks
                SET encrypted_size_bytes = chunk_size_bytes + 28
                WHERE encrypted_size_bytes IS NULL OR encrypted_size_bytes = 0
            """)

        # 3. Update cloud_accounts if present
        if "cloud_accounts" in tables:
            acc_cols = {c[1] for c in conn.execute("PRAGMA table_info(cloud_accounts)").fetchall()}
            if "provider_used_bytes" not in acc_cols:
                conn.execute("ALTER TABLE cloud_accounts ADD COLUMN provider_used_bytes INTEGER")
            if "provider_total_bytes" not in acc_cols:
                conn.execute("ALTER TABLE cloud_accounts ADD COLUMN provider_total_bytes INTEGER")
            if "last_sync_time" not in acc_cols:
                conn.execute("ALTER TABLE cloud_accounts ADD COLUMN last_sync_time TEXT")

            if "file_chunks" in tables:
                conn.execute("""
                    UPDATE cloud_accounts
                    SET used_bytes = COALESCE(
                        (SELECT SUM(CASE 
                            WHEN encrypted_size_bytes IS NOT NULL AND encrypted_size_bytes > 0 
                            THEN encrypted_size_bytes 
                            ELSE chunk_size_bytes + 28 
                         END) FROM file_chunks WHERE file_chunks.account_name = cloud_accounts.account_name),
                        0
                    )
                """)

        now = datetime.utcnow().isoformat()
        conn.execute("""
            INSERT OR IGNORE INTO schema_migrations (version, applied_at, description)
            VALUES (3, ?, 'Accurate encrypted storage accounting and provider quota sync')
        """, (now,))

    # ------------------------------------------------------------------
    # Database backup / restore
    # ------------------------------------------------------------------

    def backup_database(self, backup_path):
        """
        Creates a consistent hot backup of the live database using SQLite's
        built-in Online Backup API (sqlite3.Connection.backup).
        The backup file is validated before returning.

        Returns the backup_path on success; raises on failure.
        """
        backup_path = str(backup_path)
        if os.path.exists(backup_path) and os.path.samefile(backup_path, self.db_path):
            raise ValueError("Backup path must differ from the live database path.")

        conn = self._get_conn()
        backup_conn = None
        try:
            backup_conn = sqlite3.connect(backup_path)
            with self._write_lock:
                conn.backup(backup_conn)
        finally:
            if backup_conn:
                backup_conn.close()

        # Validate the backup is a readable, non-corrupt SQLite file
        self._validate_database_file(backup_path)
        return backup_path

    def restore_database(self, backup_path):
        """
        Restores the live database from a backup file.

        Safety contract:
        - The backup file is validated BEFORE anything is overwritten.
        - Cannot restore from the live database path itself.
        - If validation fails the live database is untouched.
        - The existing live database is preserved as <db_path>.pre_restore
          before overwriting.
        - Stale WAL and SHM files from previous live database are cleaned up.

        Raises ValueError or RuntimeError if the restore cannot proceed safely.
        """
        backup_path = str(backup_path)
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        if os.path.exists(self.db_path) and os.path.samefile(backup_path, self.db_path):
            raise ValueError("Cannot restore database from itself.")

        # Validate backup before touching the live database
        self._validate_database_file(backup_path)

        # Flush any pending WAL writes on live database before snapshotting
        try:
            conn = self._get_conn()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass

        # Safety snapshot of the live database
        pre_restore_path = self.db_path + ".pre_restore"
        try:
            shutil.copy2(self.db_path, pre_restore_path)
        except Exception as exc:
            raise RuntimeError(f"Cannot snapshot live database before restore: {exc}") from exc

        # Close thread-local connection so we can replace the file
        self._close_thread_connection()

        # Remove stale WAL / SHM files
        for ext in ["-wal", "-shm"]:
            wal_file = self.db_path + ext
            if os.path.exists(wal_file):
                try:
                    os.remove(wal_file)
                except Exception:
                    pass

        try:
            shutil.copy2(backup_path, self.db_path)
        except Exception as exc:
            # Attempt to roll back to pre-restore snapshot
            try:
                shutil.copy2(pre_restore_path, self.db_path)
            except Exception:
                pass
            raise RuntimeError(f"Database restore failed: {exc}") from exc

        # Re-open connection and run migrations on restored database
        conn = self._get_conn()
        self._run_migrations(conn)

    @staticmethod
    def _validate_database_file(path):
        """
        Validates that a file is a readable, non-corrupt SQLite database.
        Raises RuntimeError if the integrity check fails.
        """
        if not os.path.exists(path) or os.path.getsize(path) < 100:
            raise RuntimeError(f"Database file is missing or too small to be valid: {path}")
        try:
            test_conn = sqlite3.connect(path)
            result = test_conn.execute("PRAGMA integrity_check").fetchone()
            test_conn.close()
            if result[0].lower() != "ok":
                raise RuntimeError(f"SQLite integrity check failed: {result[0]}")
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Database file is corrupt or not a SQLite database: {exc}") from exc

    def _close_thread_connection(self):
        """Closes and discards the calling thread's connection."""
        conn = getattr(self._local, "conn", None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def close(self):
        """Closes the calling thread's SQLite connection."""
        self._close_thread_connection()

    def prune_ghost_remotes(self):
        """
        Scans registered cloud_accounts in SQLite against rclone.conf.
        If an account does NOT exist in rclone.conf and has 0 chunks, it is an
        accidental registration (e.g. accidentally added OneDrive_2) and is safely pruned.
        Returns list of pruned account names. Accounts holding stored chunks or marked
        DISCONNECTED are strictly preserved.
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
        cur.execute("SELECT account_name, status FROM cloud_accounts")
        registered = [dict(r) for r in cur.fetchall()]

        pruned = []
        for acc_info in registered:
            acc = acc_info["account_name"]
            if acc not in valid_sections:
                stats = self.get_account_chunks_count(acc)
                if stats["count"] == 0 and acc_info.get("status") != "DISCONNECTED":
                    with self.conn:
                        cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (acc,))
                    pruned.append(acc)
        if pruned:
            print(f"[ACCOUNT SANITIZER] Pruned {len(pruned)} accidental / ghost remote(s): {', '.join(pruned)}")
        return pruned

    def _rclone_delete_remote_chunk(self, account_name, chunk_id, op_id="delete_cleanup"):
        """
        Executes 'rclone deletefile' for a specific remote chunk with timeout and verification.
        Returns (success: bool, error_message: str).
        """
        cmd = [RCLONE_BIN, "deletefile", f"{account_name}:CloudPool_Vault/{chunk_id}.enc"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ProcessManager.register_process(proc, op_id=op_id, description=f"deletefile {chunk_id}")
            try:
                stdout, stderr = proc.communicate(timeout=15)
                returncode = proc.returncode
                err = stderr.decode("utf-8", errors="ignore").strip() if stderr else ""
            finally:
                ProcessManager.unregister_process(proc, op_id=op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
            return (returncode == 0, err)
        except Exception as ex:
            return (False, str(ex))

    def create_upload_journal_entry(self, op_id, file_id, file_name, total_size_bytes,
                                    target_tier="STABLE", target_folder_id=None,
                                    enable_parity=1, total_expected_chunks=1,
                                    data_chunks_count=1, is_container=0, relative_path=None,
                                    file_hash=None, hash_algorithm="SHA-256"):
        """Creates a new upload journal entry in 'preparing' state."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO upload_journal (
                    op_id, file_id, file_name, total_size_bytes,
                    target_tier, target_folder_id, enable_parity,
                    total_expected_chunks, data_chunks_count,
                    is_container, relative_path, file_hash, hash_algorithm, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'preparing', ?, ?)
            """, (
                op_id, file_id, file_name, total_size_bytes,
                target_tier, target_folder_id, enable_parity,
                total_expected_chunks, data_chunks_count,
                is_container, relative_path, file_hash, hash_algorithm, now, now
            ))

    def update_upload_journal_status(self, op_id, status, error_message=None):
        """Updates the lifecycle status and timestamp of an upload journal entry."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE upload_journal
                SET status = ?,
                    error_message = COALESCE(?, error_message),
                    updated_at = ?
                WHERE op_id = ?
            """, (status, error_message, now, op_id))

    def update_upload_journal_parity(self, op_id, enable_parity=0):
        """Updates enable_parity and total_expected_chunks in upload_journal if parity is adjusted."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE upload_journal
                SET enable_parity = ?,
                    total_expected_chunks = data_chunks_count + ?,
                    updated_at = ?
                WHERE op_id = ?
            """, (enable_parity, enable_parity, now, op_id))

    def record_journal_chunk(self, op_id, chunk_id, account_name, part_number,
                             chunk_size_bytes, is_parity=0, status="uploading",
                             ciphertext_hash=None, encrypted_size_bytes=None):
        """Records a chunk in upload_journal_chunks prior to or during transfer."""
        now = datetime.utcnow().isoformat()
        if encrypted_size_bytes is None:
            encrypted_size_bytes = (chunk_size_bytes + 28) if chunk_size_bytes is not None else 0
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO upload_journal_chunks (
                    op_id, chunk_id, account_name, part_number,
                    chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash, status, uploaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(op_id, chunk_id) DO UPDATE SET
                    status = excluded.status,
                    account_name = excluded.account_name,
                    chunk_size_bytes = excluded.chunk_size_bytes,
                    encrypted_size_bytes = excluded.encrypted_size_bytes,
                    ciphertext_hash = COALESCE(excluded.ciphertext_hash, upload_journal_chunks.ciphertext_hash),
                    uploaded_at = excluded.uploaded_at
            """, (op_id, chunk_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash, status, now))

    def update_virtual_file_integrity(self, file_id, status, file_hash=None):
        """Updates integrity verification status and optional hash for a virtual file."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE virtual_files
                SET integrity_status = ?,
                    file_hash = COALESCE(?, file_hash)
                WHERE file_id = ?
            """, (status, file_hash, file_id))

    def update_journal_chunk_status(self, op_id, chunk_id, status, error_message=None):
        """Updates status of a chunk in upload_journal_chunks (e.g. uploaded, failed, rolled_back)."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE upload_journal_chunks
                SET status = ?,
                    error_message = COALESCE(?, error_message),
                    uploaded_at = CASE WHEN ? = 'uploaded' THEN ? ELSE uploaded_at END
                WHERE op_id = ? AND chunk_id = ?
            """, (status, error_message, status, now, op_id, chunk_id))

    def get_upload_journal_entry(self, op_id):
        """Fetches an upload journal record by op_id."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM upload_journal WHERE op_id = ?", (op_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_upload_journal_chunks(self, op_id, status_filter=None):
        """Fetches chunks tracked under an upload journal entry."""
        cur = self.conn.cursor()
        if status_filter:
            cur.execute("SELECT * FROM upload_journal_chunks WHERE op_id = ? AND status = ? ORDER BY part_number ASC", (op_id, status_filter))
        else:
            cur.execute("SELECT * FROM upload_journal_chunks WHERE op_id = ? ORDER BY part_number ASC", (op_id,))
        return [dict(r) for r in cur.fetchall()]

    def get_upload_journal_chunk(self, op_id, chunk_id):
        """Fetches a specific chunk record from upload_journal_chunks."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM upload_journal_chunks WHERE op_id = ? AND chunk_id = ?", (op_id, chunk_id))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_resumable_upload_jobs(self):
        """Returns incomplete upload jobs that have at least one uploaded chunk and can be resumed."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT uj.*, COUNT(ujc.chunk_id) AS uploaded_chunks_count
            FROM upload_journal uj
            JOIN upload_journal_chunks ujc ON uj.op_id = ujc.op_id
            WHERE uj.status NOT IN ('completed', 'rolled_back')
              AND ujc.status = 'uploaded'
            GROUP BY uj.op_id
            HAVING uploaded_chunks_count > 0
            ORDER BY uj.created_at ASC
        """)
        return [dict(r) for r in cur.fetchall()]

    def mark_upload_interrupted(self, op_id, error_message=None):
        """Marks an in-flight upload as 'failed' (interrupted/resumable) instead of rolling back immediately."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE upload_journal
                SET status = 'failed',
                    error_message = COALESCE(?, error_message),
                    updated_at = ?
                WHERE op_id = ? AND status NOT IN ('completed', 'rolled_back')
            """, (error_message, now, op_id))

    def get_incomplete_upload_jobs(self):
        """Returns all upload jobs that did not complete normally or are pending recovery."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM upload_journal WHERE status NOT IN ('completed', 'rolled_back') ORDER BY created_at ASC")
        return [dict(r) for r in cur.fetchall()]

    def reconcile_storage_counters(self):
        """
        Recalculates cloud_accounts.used_bytes strictly based on active chunks in file_chunks.
        Guarantees storage accounting is synchronized and prevents negative/drifted counters.
        Accounts for encrypted chunk size including 28-byte AES-GCM nonce + tag overhead.
        """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE cloud_accounts 
                SET used_bytes = COALESCE(
                    (SELECT SUM(CASE 
                        WHEN encrypted_size_bytes IS NOT NULL AND encrypted_size_bytes > 0 
                        THEN encrypted_size_bytes 
                        ELSE chunk_size_bytes + 28 
                     END) FROM file_chunks WHERE file_chunks.account_name = cloud_accounts.account_name),
                    0
                )
            """)

    def rollback_upload_journal(self, op_id):
        """
        Safely rolls back an incomplete upload:
        - Determines all remote chunks that were successfully uploaded or in-flight.
        - Checks whether objects belong to any completed uploads before deletion (safe conservative rule).
        - Executes remote Rclone wipe for each chunk belonging to this incomplete operation.
        - Records failed cleanup operations for future retry if an account is offline.
        - Removes partial database records for this file.
        - Reconciles storage quotas.
        """
        journal = self.get_upload_journal_entry(op_id)
        if not journal:
            return {"op_id": op_id, "status": "not_found", "chunks_wiped": 0, "chunks_failed": 0}

        file_id = journal["file_id"]
        file_name = journal["file_name"]
        now = datetime.utcnow().isoformat()

        # Update status to rolling_back
        self.update_upload_journal_status(op_id, "rolling_back")

        # Retrieve all chunks tracked under this operation
        chunks = self.get_upload_journal_chunks(op_id)
        wiped_count = 0
        failed_count = 0
        errors = []

        cur = self.conn.cursor()

        for ch in chunks:
            chunk_id = ch["chunk_id"]
            acc = ch["account_name"]
            c_status = ch["status"]

            # Only wipe if chunk was uploaded, uploading, or failed
            if c_status not in ("uploaded", "uploading", "failed"):
                continue

            # Safe ownership verification: Check if this chunk is claimed by an active, completed file
            cur.execute("""
                SELECT vf.file_id 
                FROM file_chunks fc 
                JOIN virtual_files vf ON fc.file_id = vf.file_id
                WHERE fc.chunk_id = ? 
                  AND vf.file_id != ?
                  AND (vf.upload_status = 'completed' OR vf.upload_status IS NULL)
                  AND (vf.deletion_status = 'active' OR vf.deletion_status IS NULL)
            """, (chunk_id, file_id))
            if cur.fetchone():
                print(f"[RECOVERY SAFETY] Chunk '{chunk_id}' is shared/claimed by a completed file. Preserving.")
                continue

            # Delete remote object from cloud
            success, err_msg = self._rclone_delete_remote_chunk(acc, chunk_id)
            if success:
                self.update_journal_chunk_status(op_id, chunk_id, "rolled_back")
                wiped_count += 1
            else:
                self.update_journal_chunk_status(op_id, chunk_id, "failed", error_message=err_msg)
                failed_count += 1
                errors.append(f"{acc}:{chunk_id} ({err_msg})")

        # Database cleanup
        with self.conn:
            cur = self.conn.cursor()
            # Clean partial file_chunks for this aborted file_id
            cur.execute("DELETE FROM file_chunks WHERE file_id = ?", (file_id,))
            
            # If all chunks safely cleaned, remove virtual_files record
            if failed_count == 0:
                cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
                cur.execute("UPDATE upload_journal SET status = 'rolled_back', error_message = NULL, updated_at = ? WHERE op_id = ?", (now, op_id))
                final_status = "rolled_back"
            else:
                # Mark as failed with detailed error for future retry
                err_str = f"Partial rollback: {failed_count} chunk(s) could not be wiped: {'; '.join(errors)}"
                cur.execute("UPDATE virtual_files SET upload_status = 'failed' WHERE file_id = ?", (file_id,))
                cur.execute("UPDATE upload_journal SET status = 'failed', error_message = ?, updated_at = ? WHERE op_id = ?", (err_str, now, op_id))
                final_status = "failed"

        # Reconcile storage counters
        self.reconcile_storage_counters()

        return {
            "op_id": op_id,
            "file_id": file_id,
            "status": final_status,
            "chunks_wiped": wiped_count,
            "chunks_failed": failed_count,
            "errors": errors
        }

    def cleanup_incomplete_uploads(self):
        """
        Robust Startup Crash Recovery & Orphan Remote Object Prevention:
        1. Detects incomplete upload jobs from persistent upload_journal.
        2. Determines remote chunks uploaded for aborted operations.
        3. Checks if metadata is committed. If an upload reached 'committing' and has all chunks, finalizes it.
        4. Safely rolls back incomplete jobs and deletes remote chunks via Rclone.
        5. Preserves valid completed files and objects with uncertain ownership.
        6. Records failed cleanup operations for future retry.
        7. Reconciles cloud storage quota counters against active file chunks.
        8. Produces structured recovery log.
        """
        recovery_log = []
        incomplete_jobs = self.get_incomplete_upload_jobs()
        committed_count = 0
        rolled_back_count = 0
        total_chunks_wiped = 0
        total_failures = 0

        cur = self.conn.cursor()

        for job in incomplete_jobs:
            op_id = job["op_id"]
            file_id = job["file_id"]
            file_name = job["file_name"]
            status = job["status"]
            data_chunks_count = job["data_chunks_count"]
            has_parity = job["enable_parity"]
            expected_chunks = data_chunks_count + (1 if has_parity else 0)

            # Check if this job reached committing and all chunks actually exist
            if status == "committing":
                cur.execute("SELECT COUNT(*) AS cnt FROM file_chunks WHERE file_id = ?", (file_id,))
                chunk_cnt_row = cur.fetchone()
                existing_chunks = chunk_cnt_row["cnt"] if chunk_cnt_row else 0

                cur.execute("SELECT file_id FROM virtual_files WHERE file_id = ?", (file_id,))
                vf_exists = cur.fetchone() is not None

                if existing_chunks >= expected_chunks and vf_exists:
                    # File actually finished uploading before crash! Safe resume/commit
                    now = datetime.utcnow().isoformat()
                    with self.conn:
                        cur.execute("UPDATE virtual_files SET upload_status = 'completed' WHERE file_id = ?", (file_id,))
                        cur.execute("UPDATE upload_journal SET status = 'completed', updated_at = ? WHERE op_id = ?", (now, op_id))
                        cur.execute("UPDATE upload_journal_chunks SET status = 'committed' WHERE op_id = ?", (op_id,))
                    committed_count += 1
                    msg = f"[CRASH RECOVERY] Finalized and committed completed upload for '{file_name}' (op_id={op_id})."
                    print(msg)
                    recovery_log.append(msg)
                    continue

            # Otherwise, roll back this incomplete operation safely
            msg = f"[CRASH RECOVERY] Interrupted upload detected for '{file_name}' (op_id={op_id}, state={status}). Rolling back..."
            print(msg)
            recovery_log.append(msg)

            res = self.rollback_upload_journal(op_id)
            total_chunks_wiped += res.get("chunks_wiped", 0)
            total_failures += res.get("chunks_failed", 0)
            if res.get("status") == "rolled_back":
                rolled_back_count += 1
                msg = f"[CRASH RECOVERY] Successfully rolled back op '{op_id}' ({res.get('chunks_wiped')} remote chunks wiped)."
                recovery_log.append(msg)
            else:
                msg = f"[CRASH RECOVERY] Rollback incomplete for op '{op_id}': {res.get('chunks_failed')} chunk(s) queued for retry."
                recovery_log.append(msg)

        # Check folder_upload_journal for uncommitted folder uploads
        cur.execute("SELECT * FROM folder_upload_journal WHERE status NOT IN ('committed', 'rolled_back')")
        incomplete_folders = cur.fetchall()
        for fjob in incomplete_folders:
            f_op_id = fjob["folder_op_id"]
            root_name = fjob["root_folder_name"]
            container_id = fjob["container_id"]
            created_fid = fjob["created_root_folder_id"]
            f_status = fjob["status"]
            msg = f"[CRASH RECOVERY] Interrupted folder upload detected for '{root_name}' (op_id={f_op_id}, state={f_status}). Rolling back..."
            print(msg)
            recovery_log.append(msg)

            # Find matching container op in upload_journal if any
            cur.execute("SELECT op_id FROM upload_journal WHERE file_id = ?", (container_id,))
            c_op_row = cur.fetchone()
            if c_op_row:
                res = self.rollback_upload_journal(c_op_row["op_id"])
                total_chunks_wiped += res.get("chunks_wiped", 0)
                total_failures += res.get("chunks_failed", 0)

            # Clean any ghost virtual folders or files
            with self.conn:
                if created_fid:
                    self.delete_virtual_folder_record(created_fid)
                cur.execute("DELETE FROM virtual_files WHERE container_id = ?", (container_id,))
                now = datetime.utcnow().isoformat()
                cur.execute("UPDATE folder_upload_journal SET status = 'rolled_back', updated_at = ? WHERE folder_op_id = ?", (now, f_op_id))
            rolled_back_count += 1

        # Legacy fallback check: clean broken virtual_files not covered by upload_journal
        cur.execute("""
            SELECT file_id, file_name, total_size_bytes 
            FROM virtual_files 
            WHERE ((container_id IS NULL OR container_id = '') OR is_container = 1)
              AND file_id NOT IN (SELECT file_id FROM upload_journal WHERE status = 'completed')
        """)
        legacy_files = cur.fetchall()
        CHUNK_SIZE = 20 * 1024 * 1024
        legacy_cleaned = 0

        for f in legacy_files:
            file_id = f["file_id"]
            tot_size = f["total_size_bytes"]
            expected_data_chunks = max(1, (tot_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if tot_size > 0 else 1

            cur.execute("SELECT COUNT(*) as cnt FROM file_chunks WHERE file_id = ? AND is_parity = 0", (file_id,))
            cnt_row = cur.fetchone()
            actual_data_chunks = cnt_row["cnt"] if cnt_row else 0

            if actual_data_chunks < expected_data_chunks:
                msg = f"[CRASH RECOVERY] Legacy broken upload '{f['file_name']}' detected ({actual_data_chunks}/{expected_data_chunks} chunks). Purging remote chunks..."
                print(msg)
                recovery_log.append(msg)
                cur.execute("SELECT chunk_id, account_name FROM file_chunks WHERE file_id = ?", (file_id,))
                for ch in cur.fetchall():
                    self._rclone_delete_remote_chunk(ch["account_name"], ch["chunk_id"])
                    total_chunks_wiped += 1

                with self.conn:
                    cur.execute("DELETE FROM file_chunks WHERE file_id = ?", (file_id,))
                    cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
                legacy_cleaned += 1

        # Reconcile storage counters
        self.reconcile_storage_counters()

        summary = {
            "incomplete_jobs_found": len(incomplete_jobs) + legacy_cleaned,
            "jobs_committed": committed_count,
            "jobs_rolled_back": rolled_back_count + legacy_cleaned,
            "chunks_wiped": total_chunks_wiped,
            "cleanup_failures": total_failures,
            "log": recovery_log
        }
        if len(incomplete_jobs) > 0 or legacy_cleaned > 0:
            print(f"[CRASH RECOVERY] Summary: {summary['jobs_rolled_back']} rolled back, {summary['jobs_committed']} committed, {summary['chunks_wiped']} remote chunks wiped, {summary['cleanup_failures']} retries queued.")
        return summary

    def create_folder_upload_journal_entry(self, folder_op_id, root_folder_name, parent_folder_id,
                                           container_id, total_files, total_bytes):
        """Registers a folder upload operation in 'preparing' state."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO folder_upload_journal (
                    folder_op_id, root_folder_name, parent_folder_id,
                    container_id, total_files, total_bytes, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'preparing', ?, ?)
            """, (
                folder_op_id, root_folder_name, parent_folder_id,
                container_id, total_files, total_bytes, now, now
            ))

    def update_folder_upload_journal_status(self, folder_op_id, status, created_root_folder_id=None, error_message=None):
        """Updates the status and optional metadata of a folder upload operation."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE folder_upload_journal
                SET status = ?,
                    created_root_folder_id = COALESCE(?, created_root_folder_id),
                    error_message = COALESCE(?, error_message),
                    updated_at = ?
                WHERE folder_op_id = ?
            """, (status, created_root_folder_id, error_message, now, folder_op_id))

    def get_folder_upload_journal_entry(self, folder_op_id):
        """Fetches a single folder upload journal record by ID."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM folder_upload_journal WHERE folder_op_id = ?", (folder_op_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def commit_folder_upload_atomic(self, folder_op_id, root_folder_id, root_folder_name,
                                    parent_folder_id, dir_list, file_list, container_id):
        """
        Atomically commits root folder, subdirectories, and all files in a single SQLite transaction:
        - If any step fails, SQLite automatically rolls back.
        - Marks folder_upload_journal as 'committed'.
        """
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()

            # 1. Insert root folder (if not already created)
            cur.execute("""
                INSERT OR IGNORE INTO virtual_folders (folder_id, folder_name, parent_folder_id, created_at)
                VALUES (?, ?, ?, ?)
            """, (root_folder_id, root_folder_name, parent_folder_id, now))

            # 2. Insert subfolders maintaining hierarchy
            # Sort dir_list by path depth to guarantee parent folders are inserted first
            vfolder_map = {"": root_folder_id}
            sorted_dirs = sorted(dir_list, key=lambda d: len(d.split('/')))
            for rel_dir in sorted_dirs:
                if not rel_dir or rel_dir == ".":
                    continue
                parts = rel_dir.split('/')
                parent_rel = "/".join(parts[:-1])
                p_id = vfolder_map.get(parent_rel, root_folder_id)
                sub_folder_id = str(uuid.uuid4())
                vfolder_map[rel_dir] = sub_folder_id

                cur.execute("""
                    INSERT INTO virtual_folders (folder_id, folder_name, parent_folder_id, created_at)
                    VALUES (?, ?, ?, ?)
                """, (sub_folder_id, parts[-1], p_id, now))

            # 3. Insert individual files pointing to this container
            for f in file_list:
                rel = f["rel_path"].replace('\\', '/')
                fdir = "/".join(rel.split('/')[:-1])
                target_f_id = vfolder_map.get(fdir, root_folder_id)
                file_uuid = str(uuid.uuid4())
                f_hash = f.get("file_hash")
                cur.execute("""
                    INSERT INTO virtual_files (
                        file_id, file_name, total_size_bytes, uploaded_at,
                        folder_id, container_id, is_container, relative_path, upload_status,
                        file_hash, hash_algorithm, integrity_status
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 'completed', ?, 'SHA-256', ?)
                """, (
                    file_uuid, f["name"], f["size"], now,
                    target_f_id, container_id, rel,
                    f_hash, "verified" if f_hash else "unverified"
                ))

            # 4. Mark journal as committed
            cur.execute("""
                UPDATE folder_upload_journal
                SET status = 'committed',
                    created_root_folder_id = ?,
                    updated_at = ?
                WHERE folder_op_id = ?
            """, (root_folder_id, now, folder_op_id))

    def rollback_folder_upload(self, folder_op_id, container_id=None):
        """Rolls back an incomplete or cancelled folder upload."""
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM folder_upload_journal WHERE folder_op_id = ?", (folder_op_id,))
        fjob = cur.fetchone()

        target_container_id = container_id or (fjob["container_id"] if fjob else None)
        created_root_id = fjob["created_root_folder_id"] if fjob else None

        # 1. Rollback remote chunks via container upload journal
        if target_container_id:
            cur.execute("SELECT op_id FROM upload_journal WHERE file_id = ?", (target_container_id,))
            c_op = cur.fetchone()
            if c_op:
                self.rollback_upload_journal(c_op["op_id"])

        # 2. Clean up any partial database entries
        with self.conn:
            if created_root_id:
                self.delete_virtual_folder_record(created_root_id)
            if target_container_id:
                cur.execute("DELETE FROM virtual_files WHERE container_id = ? OR file_id = ?", (target_container_id, target_container_id))
            cur.execute("""
                UPDATE folder_upload_journal 
                SET status = 'rolled_back', updated_at = ? 
                WHERE folder_op_id = ?
            """, (now, folder_op_id))

    def create_deletion_job(self, file_id, file_name, total_chunks):
        """Creates a persistent deletion job record in SQLite with atomic status update."""
        job_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO deletion_jobs (job_id, file_id, file_name, total_chunks, deleted_chunks, failed_chunks, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, 0, 'deleting', ?, ?)
            """, (job_id, file_id, file_name, total_chunks, now, now))
            cur.execute("UPDATE virtual_files SET deletion_status = 'deleting' WHERE file_id = ?", (file_id,))
        return job_id

    def update_deletion_job(self, job_id, status, deleted_chunks=None, failed_chunks=None, error_message=None):
        """Updates persistent deletion job status, chunk counters, and error details."""
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE deletion_jobs
                SET status = ?,
                    deleted_chunks = COALESCE(?, deleted_chunks),
                    failed_chunks = COALESCE(?, failed_chunks),
                    error_message = COALESCE(?, error_message),
                    updated_at = ?
                WHERE job_id = ?
            """, (status, deleted_chunks, failed_chunks, error_message, now, job_id))

    def get_deletion_job(self, job_id):
        """Fetches a persistent deletion job record by job_id."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM deletion_jobs WHERE job_id = ?", (job_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_file_deletion_jobs(self, file_id):
        """Fetches all deletion jobs associated with a file_id."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM deletion_jobs WHERE file_id = ? ORDER BY created_at DESC", (file_id,))
        return [dict(r) for r in cur.fetchall()]

    def delete_chunk_record_atomic(self, file_id, chunk_id, account_name, chunk_size_bytes, encrypted_size_bytes=None):
        """
        Atomically decrements account quota and removes chunk record from SQLite.
        Guarantees quota accounting is updated ONLY after confirmed remote wipe.
        Prevents double-deletion and negative storage counters via MAX(0, ...).
        Correctly deducts encrypted chunk size (including 28-byte nonce/tag overhead).
        """
        if not encrypted_size_bytes:
            cur = self.conn.cursor()
            cur.execute("SELECT encrypted_size_bytes, chunk_size_bytes FROM file_chunks WHERE chunk_id = ?", (chunk_id,))
            row = cur.fetchone()
            if row and row["encrypted_size_bytes"]:
                deduct_bytes = row["encrypted_size_bytes"]
            elif row and row["chunk_size_bytes"]:
                deduct_bytes = row["chunk_size_bytes"] + 28
            else:
                deduct_bytes = (chunk_size_bytes or 0) + 28
        else:
            deduct_bytes = encrypted_size_bytes

        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE cloud_accounts 
                SET used_bytes = MAX(0, used_bytes - ?) 
                WHERE account_name = ?
            """, (deduct_bytes, account_name))
            cur.execute("DELETE FROM file_chunks WHERE chunk_id = ?", (chunk_id,))

    def finalize_file_deletion(self, file_id, job_id=None):
        """
        Atomically purges the virtual_files row and marks the deletion job as completed.
        Invoked ONLY after all remote chunks have been confirmed wiped.
        """
        now = datetime.utcnow().isoformat()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
            if job_id:
                cur.execute("""
                    UPDATE deletion_jobs 
                    SET status = 'completed', updated_at = ? 
                    WHERE job_id = ?
                """, (now, job_id))

    def set_file_deletion_status(self, file_id, status):
        """Updates deletion_status on virtual_files ('active', 'deleting', 'partially_deleted', 'failed')."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("UPDATE virtual_files SET deletion_status = ? WHERE file_id = ?", (status, file_id))

    def recover_interrupted_deletions(self):
        """
        Scans for deletion jobs interrupted by crash, restart, or power loss while 'deleting'.
        Marks them as 'partially_deleted' or 'failed' based on surviving chunks so they can be retried.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT job_id, file_id, file_name, deleted_chunks FROM deletion_jobs WHERE status = 'deleting'")
        stuck_jobs = [dict(r) for r in cur.fetchall()]
        recovered_count = 0
        now = datetime.utcnow().isoformat()
        for job in stuck_jobs:
            fid = job["file_id"]
            cur.execute("SELECT COUNT(*) FROM file_chunks WHERE file_id = ?", (fid,))
            cnt_row = cur.fetchone()
            rem_chunks = cnt_row[0] if cnt_row else 0
            new_status = "partially_deleted" if job["deleted_chunks"] > 0 else "failed"
            with self.conn:
                cur.execute("""
                    UPDATE deletion_jobs 
                    SET status = ?, failed_chunks = ?, error_message = 'Interrupted by application restart', updated_at = ?
                    WHERE job_id = ?
                """, (new_status, rem_chunks, now, job["job_id"]))
                cur.execute("UPDATE virtual_files SET deletion_status = ? WHERE file_id = ?", (new_status, fid))
            recovered_count += 1
        if recovered_count > 0:
            print(f"[CRASH RECOVERY] Recovered {recovered_count} interrupted deletion job(s).")
        return recovered_count

    def register_account(self, account_name, provider, raw_gb, buffer_gb, tier, priority=1, status="CONNECTED"):
        """Registers or updates an account, enforcing buffers, allocation priority, and connection status."""
        GB = 1024 * 1024 * 1024
        usable_bytes = int((raw_gb - buffer_gb) * GB)
        
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO cloud_accounts 
                (account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority, status)
                VALUES (?, ?, ?, 0, ?, ?, ?)
                ON CONFLICT(account_name) DO UPDATE SET
                    usable_capacity_bytes = excluded.usable_capacity_bytes,
                    reliability_tier = excluded.reliability_tier,
                    priority = excluded.priority,
                    status = excluded.status
            """, (account_name, provider, usable_bytes, tier, priority, status))

    def get_account(self, account_name):
        """Fetches a single registered cloud account record with quota and sync details."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority,
                   COALESCE(status, 'CONNECTED') AS status,
                   (usable_capacity_bytes - used_bytes) AS free_bytes,
                   provider_used_bytes, provider_total_bytes, last_sync_time
            FROM cloud_accounts 
            WHERE account_name = ?
        """, (account_name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_accounts(self, active_only=False):
        """Returns all registered cloud accounts sorted by allocation priority, then remaining free space."""
        cur = self.conn.cursor()
        filter_sql = "WHERE status IS NULL OR status = 'CONNECTED'" if active_only else ""
        cur.execute(f"""
            SELECT account_name, provider, usable_capacity_bytes, used_bytes, reliability_tier, priority,
                   COALESCE(status, 'CONNECTED') AS status,
                   (usable_capacity_bytes - used_bytes) AS free_bytes,
                   provider_used_bytes, provider_total_bytes, last_sync_time
            FROM cloud_accounts 
            {filter_sql}
            ORDER BY priority ASC, (usable_capacity_bytes - used_bytes) DESC
        """)
        return [dict(row) for row in cur.fetchall()]

    def get_account_references(self, account_name):
        """
        Traces all references in file_chunks to account_name.
        Returns a dictionary with chunk count, total bytes stored, unique file count, and file names.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT fc.chunk_id, fc.file_id, fc.chunk_size_bytes, fc.is_parity, vf.file_name
            FROM file_chunks fc
            LEFT JOIN virtual_files vf ON fc.file_id = vf.file_id
            WHERE fc.account_name = ?
        """, (account_name,))
        rows = cur.fetchall()
        
        file_ids = set()
        file_names = set()
        total_bytes = 0
        for r in rows:
            total_bytes += (r["chunk_size_bytes"] or 0)
            if r["file_id"]:
                file_ids.add(r["file_id"])
            if r["file_name"]:
                file_names.add(r["file_name"])
            elif r["file_id"]:
                file_names.add(f"FileID:{r['file_id'][:8]}")

        return {
            "chunks_count": len(rows),
            "chunks_bytes": total_bytes,
            "file_count": len(file_ids),
            "file_names": sorted(list(file_names))
        }

    def unregister_account(self, account_name):
        """
        Safely removes an empty cloud remote registration from SQLite.
        Strictly prevents deletion if any chunks or files reference this account,
        enforcing database integrity and foreign key constraints.
        Uses an atomic transaction with rollback on failure.
        """
        # 1. Verify account exists
        cur = self.conn.cursor()
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (account_name,))
        if not cur.fetchone():
            raise ValueError(f"Account '{account_name}' is not registered in CloudPool.")

        # 2. Trace all references to this account
        refs = self.get_account_references(account_name)
        if refs["chunks_count"] > 0:
            raise ValueError(
                f"Cannot unregister remote '{account_name}': Remote still contains {refs['chunks_count']} "
                f"stored chunk(s) ({format_bytes(refs['chunks_bytes'])}) belonging to {refs['file_count']} file(s). "
                f"Destructive unregistration is prohibited to prevent data loss. "
                f"Safely disconnect the account instead to preserve chunk metadata."
            )

        # 3. Atomic deletion within transaction
        with self.conn:
            cur.execute("DELETE FROM cloud_accounts WHERE account_name = ?", (account_name,))
        return True

    def disconnect_account(self, account_name):
        """
        Safely disconnects a cloud remote without deleting its storage metadata or chunks.
        Marks status as 'DISCONNECTED' so it is excluded from future chunk upload routing,
        while strictly preserving all chunk records, encryption keys, and recovery metadata.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT account_name, status FROM cloud_accounts WHERE account_name = ?", (account_name,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Account '{account_name}' is not registered in CloudPool.")

        with self.conn:
            cur.execute("UPDATE cloud_accounts SET status = 'DISCONNECTED' WHERE account_name = ?", (account_name,))
        return True

    def reconnect_account(self, account_name):
        """
        Re-enables a DISCONNECTED account, restoring its status to 'CONNECTED'
        and allowing it to participate in storage pool upload routing again.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT account_name FROM cloud_accounts WHERE account_name = ?", (account_name,))
        if not cur.fetchone():
            raise ValueError(f"Account '{account_name}' is not registered in CloudPool.")

        with self.conn:
            cur.execute("UPDATE cloud_accounts SET status = 'CONNECTED' WHERE account_name = ?", (account_name,))
        return True

    def get_account_chunks_count(self, account_name):
        """Returns the number of chunks, plaintext bytes, and encrypted bytes stored on a remote."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT COUNT(*), 
                   COALESCE(SUM(chunk_size_bytes), 0),
                   COALESCE(SUM(CASE 
                       WHEN encrypted_size_bytes IS NOT NULL AND encrypted_size_bytes > 0 
                       THEN encrypted_size_bytes 
                       ELSE chunk_size_bytes + 28 
                   END), 0)
            FROM file_chunks 
            WHERE account_name = ?
        """, (account_name,))
        row = cur.fetchone()
        return {"count": row[0], "bytes": row[1], "encrypted_bytes": row[2]}

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
                       COALESCE(vf.deletion_status, 'active') AS deletion_status,
                       COALESCE(fc_dir.chunk_count, fc_cnt.chunk_count, 1) AS chunk_count,
                       COALESCE(fc_dir.has_parity, fc_cnt.has_parity, 1) AS has_parity
                FROM virtual_files vf
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_dir ON vf.file_id = fc_dir.file_id
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_cnt ON vf.container_id = fc_cnt.file_id
                WHERE (vf.is_container IS NULL OR vf.is_container = 0)
                  AND (vf.folder_id IS NULL OR vf.folder_id = '')
                  AND (vf.upload_status IS NULL OR vf.upload_status = 'completed')
                ORDER BY vf.uploaded_at DESC
            """)
        else:
            cur.execute("""
                SELECT vf.file_id, vf.file_name, vf.total_size_bytes, vf.uploaded_at, vf.folder_id,
                       vf.container_id, vf.relative_path,
                       COALESCE(vf.deletion_status, 'active') AS deletion_status,
                       COALESCE(fc_dir.chunk_count, fc_cnt.chunk_count, 1) AS chunk_count,
                       COALESCE(fc_dir.has_parity, fc_cnt.has_parity, 1) AS has_parity
                FROM virtual_files vf
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_dir ON vf.file_id = fc_dir.file_id
                LEFT JOIN (SELECT file_id, COUNT(chunk_id) AS chunk_count, MAX(is_parity) AS has_parity FROM file_chunks GROUP BY file_id) fc_cnt ON vf.container_id = fc_cnt.file_id
                WHERE (vf.is_container IS NULL OR vf.is_container = 0)
                  AND vf.folder_id = ?
                  AND (vf.upload_status IS NULL OR vf.upload_status = 'completed')
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
        """Returns aggregated pool statistics with detailed storage accounting breakdown."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN status IS NULL OR status = 'CONNECTED' THEN usable_capacity_bytes ELSE 0 END), 0) AS total_usable,
                COALESCE(SUM(used_bytes), 0) AS total_used,
                COUNT(account_name) AS account_count,
                COALESCE(SUM(CASE WHEN status IS NULL OR status = 'CONNECTED' THEN 1 ELSE 0 END), 0) AS connected_count,
                COALESCE(SUM(CASE WHEN status = 'DISCONNECTED' THEN 1 ELSE 0 END), 0) AS disconnected_count,
                COALESCE(SUM(CASE WHEN status IS NULL OR status = 'CONNECTED' THEN provider_used_bytes ELSE 0 END), 0) AS provider_reported_used,
                COALESCE(SUM(CASE WHEN status IS NULL OR status = 'CONNECTED' THEN provider_total_bytes ELSE 0 END), 0) AS provider_reported_total
            FROM cloud_accounts
        """)
        row = cur.fetchone()

        cur.execute("SELECT COUNT(file_id) AS file_count FROM virtual_files WHERE is_container IS NULL OR is_container = 0")
        file_row = cur.fetchone()

        cur.execute("SELECT COUNT(folder_id) AS folder_count FROM virtual_folders")
        folder_row = cur.fetchone()

        # Detailed byte breakdowns from virtual_files and file_chunks
        cur.execute("""
            SELECT COALESCE(SUM(total_size_bytes), 0) 
            FROM virtual_files 
            WHERE (is_container IS NULL OR is_container = 0)
              AND (upload_status IS NULL OR upload_status = 'completed')
        """)
        logical_bytes = cur.fetchone()[0]

        cur.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN is_parity = 0 THEN chunk_size_bytes ELSE 0 END), 0) AS data_bytes,
                COALESCE(SUM(CASE WHEN is_parity = 1 THEN chunk_size_bytes ELSE 0 END), 0) AS parity_bytes,
                COALESCE(SUM(CASE WHEN is_parity = 0 THEN encrypted_size_bytes ELSE 0 END), 0) AS enc_data_bytes,
                COALESCE(SUM(CASE WHEN is_parity = 1 THEN encrypted_size_bytes ELSE 0 END), 0) AS enc_parity_bytes,
                COUNT(chunk_id) AS total_chunks
            FROM file_chunks
        """)
        chunk_row = cur.fetchone()
        data_bytes = chunk_row["data_bytes"]
        parity_bytes = chunk_row["parity_bytes"]
        total_chunks = chunk_row["total_chunks"]

        # Overhead = total remote used bytes minus sum of plaintext data bytes
        total_used = row["total_used"]
        overhead_bytes = max(0, total_used - data_bytes)

        return {
            "total_usable": row["total_usable"],
            "total_used": total_used,
            "free_bytes": max(0, row["total_usable"] - total_used),
            "account_count": row["account_count"],
            "connected_count": row["connected_count"],
            "disconnected_count": row["disconnected_count"],
            "file_count": file_row["file_count"],
            "folder_count": folder_row["folder_count"] if folder_row else 0,
            # Granular Storage Accounting Metrics (TASK 14)
            "logical_bytes": logical_bytes,
            "data_bytes": data_bytes,
            "parity_bytes": parity_bytes,
            "overhead_bytes": overhead_bytes,
            "total_chunks": total_chunks,
            "provider_reported_used": row["provider_reported_used"],
            "provider_reported_total": row["provider_reported_total"]
        }

    def sync_provider_quota(self, account_name=None, timeout=15):
        """
        Queries cloud provider directly via 'rclone about <remote>: --json'
        to retrieve authoritative remote storage quota and usage.
        Updates provider_used_bytes, provider_total_bytes, and last_sync_time.
        Gracefully falls back if provider does not support 'about' or is offline.
        
        Returns a dict mapping account_name to its sync result:
        {
            account_name: {
                "status": "synced" | "unsupported" | "offline" | "error",
                "provider_total": int or None,
                "provider_used": int or None,
                "error": str or None
            }
        }
        """
        if account_name:
            acc = self.get_account(account_name)
            target_accounts = [acc] if acc else []
        else:
            target_accounts = self.get_accounts(active_only=True)

        results = {}
        for acc in target_accounts:
            name = acc["account_name"]
            if not self.is_remote_in_rclone_config(name):
                results[name] = {
                    "status": "offline",
                    "provider_total": None,
                    "provider_used": None,
                    "error": f"Remote '{name}' not found in rclone.conf"
                }
                continue

            cmd = [RCLONE_BIN, "about", f"{name}:", "--json"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if res.returncode == 0:
                    try:
                        data = json.loads(res.stdout) if res.stdout.strip() else {}
                        total = data.get("total")
                        used = data.get("used")
                        now = datetime.utcnow().isoformat()
                        if total is not None or used is not None:
                            with self.conn:
                                cur = self.conn.cursor()
                                cur.execute("""
                                    UPDATE cloud_accounts
                                    SET provider_total_bytes = ?,
                                        provider_used_bytes = ?,
                                        last_sync_time = ?
                                    WHERE account_name = ?
                                """, (total, used, now, name))
                            results[name] = {
                                "status": "synced",
                                "provider_total": total,
                                "provider_used": used,
                                "error": None
                            }
                        else:
                            results[name] = {
                                "status": "unsupported",
                                "provider_total": None,
                                "provider_used": None,
                                "error": "Provider returned empty quota metrics"
                            }
                    except json.JSONDecodeError as jde:
                        results[name] = {
                            "status": "error",
                            "provider_total": None,
                            "provider_used": None,
                            "error": f"Invalid JSON response: {jde}"
                        }
                else:
                    stderr = (res.stderr or "").strip()
                    lower_err = stderr.lower()
                    if "not supported" in lower_err:
                        status = "unsupported"
                    elif any(w in lower_err for w in ["timeout", "deadline", "connection", "offline", "unreachable"]):
                        status = "offline"
                    else:
                        status = "error"
                    results[name] = {
                        "status": status,
                        "provider_total": None,
                        "provider_used": None,
                        "error": stderr or f"Rclone exited with code {res.returncode}"
                    }
            except subprocess.TimeoutExpired:
                results[name] = {
                    "status": "offline",
                    "provider_total": None,
                    "provider_used": None,
                    "error": f"Remote '{name}' timed out after {timeout}s"
                }
            except Exception as ex:
                results[name] = {
                    "status": "error",
                    "provider_total": None,
                    "provider_used": None,
                    "error": str(ex)
                }

        return results

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
