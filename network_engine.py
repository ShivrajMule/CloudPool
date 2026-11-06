import os
import io
import uuid
import time
import shutil
import random
import json
import hashlib
import subprocess
import tarfile
import tempfile
from core_engine import (
    CryptoEngine,
    DatabaseEngine,
    RAID5Engine,
    MetadataEngine,
    ProcessManager,
    SafeTarExtractor,
    ArchiveSecurityError,
    PathTraversalError,
    DiskSpaceError,
    ArchiveBombError,
    DuplicateArchiveEntryError,
    ParityPlacementError,
    FileIntegrityError,
    IntegrityEngine,
    format_bytes,
    VAULT_DIR,
    APP_DIR,
    RCLONE_BIN
)

MB = 1024 * 1024
CHUNK_SIZE = 20 * MB  # 20 MB chunks to safely bypass limits


class UploadErrorCategory:
    TRANSIENT = "TRANSIENT"
    PERMANENT_REMOTE = "PERMANENT_REMOTE"
    PERMANENT_FATAL = "PERMANENT_FATAL"


class UploadErrorType:
    AUTHENTICATION = "authentication"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_TIMEOUT = "network_timeout"
    CONNECTION_RESET = "connection_reset"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    QUOTA_EXCEEDED = "quota_exceeded"
    MISSING_REMOTE = "missing_remote"
    INVALID_PATH = "invalid_path"
    CORRUPTED_UPLOAD = "corrupted_upload"
    USER_CANCELLED = "user_cancelled"
    UNKNOWN = "unknown"


class UploadErrorClassifier:
    """
    Intelligently classifies rclone subprocess and network errors.
    Enforces the rule: never blindly retry permanent errors (auth, quota, missing remotes),
    while retrying transient interruptions (network timeout, socket reset, 5xx/429 throttling)
    with exponential backoff and jitter.
    """
    @classmethod
    def classify(cls, error_message: str) -> tuple:
        """Returns (UploadErrorType, UploadErrorCategory)."""
        if not error_message:
            return (UploadErrorType.UNKNOWN, UploadErrorCategory.TRANSIENT)

        err = str(error_message).lower()

        # 1. User Cancellation
        if "transfer cancelled by user" in err or "cancelled by user" in err or "canceled by user" in err:
            return (UploadErrorType.USER_CANCELLED, UploadErrorCategory.PERMANENT_FATAL)

        # 2. Authentication & Credentials (Permanent on this remote)
        if any(p in err for p in [
            "401", "unauthorized", "invalid_grant", "token expired",
            "oauth", "credentials", "login failed", "authentication failure",
            "token refresh failed", "invalid credentials"
        ]):
            return (UploadErrorType.AUTHENTICATION, UploadErrorCategory.PERMANENT_REMOTE)

        # 3. Permissions & Access Control (Permanent on this remote)
        if any(p in err for p in [
            "403", "forbidden", "permission denied", "access denied", "accessdenied"
        ]):
            return (UploadErrorType.PERMISSION_DENIED, UploadErrorCategory.PERMANENT_REMOTE)

        # 4. Storage Quota Exceeded (Permanent on this remote)
        if any(p in err for p in [
            "quota exceeded", "insufficient storage", "storage limit",
            "disk full", "userratelimitexceeded", "storage quota",
            "quota_exceeded", "out of space"
        ]):
            return (UploadErrorType.QUOTA_EXCEEDED, UploadErrorCategory.PERMANENT_REMOTE)

        # 5. Missing / Invalid Remote (Permanent on this remote)
        if any(p in err for p in [
            "not found in rclone.conf", "unknown remote", "remote not found",
            "failed to create file system", "invalid remote"
        ]):
            return (UploadErrorType.MISSING_REMOTE, UploadErrorCategory.PERMANENT_REMOTE)

        # 6. Invalid Path (Permanent Fatal)
        if any(p in err for p in [
            "invalid path", "illegal path", "filename too long", "name too long"
        ]):
            return (UploadErrorType.INVALID_PATH, UploadErrorCategory.PERMANENT_FATAL)

        # 7. Corrupted Upload / Hash Mismatch (Transient: can retry upload)
        if any(p in err for p in [
            "hash mismatch", "checksum mismatch", "corrupted upload", "bad chunk"
        ]):
            return (UploadErrorType.CORRUPTED_UPLOAD, UploadErrorCategory.TRANSIENT)

        # 8. Provider Temporarily Unavailable / Rate Limited / Gateway Timeout (Transient)
        if any(p in err for p in [
            "500", "502", "503", "504", "429", "gateway timeout", "too many requests", "rate limit",
            "slow down", "temporarily unavailable", "backend unavailable", "service unavailable"
        ]):
            return (UploadErrorType.PROVIDER_UNAVAILABLE, UploadErrorCategory.TRANSIENT)

        # 9. Network Timeout (Transient)
        if any(p in err for p in [
            "timeout", "timed out", "deadline exceeded", "i/o timeout", "client.timeout"
        ]):
            return (UploadErrorType.NETWORK_TIMEOUT, UploadErrorCategory.TRANSIENT)

        # 10. Connection Reset / Broken Pipe (Transient)
        if any(p in err for p in [
            "connection reset", "broken pipe", "connection refused", "network is unreachable",
            "wsarecv", "wsasend", "unexpected eof", "tls handshake timeout",
            "no route to host", "connection closed", "temporary failure in name resolution"
        ]):
            return (UploadErrorType.CONNECTION_RESET, UploadErrorCategory.TRANSIENT)

        # Default fallback: treat unidentified errors as transient up to max retries
        return (UploadErrorType.UNKNOWN, UploadErrorCategory.TRANSIENT)

    @classmethod
    def is_transient(cls, error_message: str) -> bool:
        _, cat = cls.classify(error_message)
        return cat == UploadErrorCategory.TRANSIENT

    @classmethod
    def is_permanent_remote(cls, error_message: str) -> bool:
        _, cat = cls.classify(error_message)
        return cat == UploadErrorCategory.PERMANENT_REMOTE


class UploadRetryPolicy:
    """
    Configurable Exponential Backoff with Uniform Random Jitter.
    Avoids thundering-herd spikes against cloud APIs and rclone endpoints.
    """
    def __init__(self, max_retries=3, initial_backoff=1.0, backoff_multiplier=2.0, max_backoff=30.0, jitter_ratio=0.25):
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.backoff_multiplier = backoff_multiplier
        self.max_backoff = max_backoff
        self.jitter_ratio = jitter_ratio

    def calculate_backoff(self, attempt: int) -> float:
        """
        Calculates exponential backoff delay in seconds for 0-indexed attempt (attempt 0 is 1st retry).
        Formula: min(max_backoff, initial_backoff * multiplier^attempt) + jitter
        """
        base = min(self.max_backoff, self.initial_backoff * (self.backoff_multiplier ** attempt))
        delta = random.uniform(-self.jitter_ratio * base, self.jitter_ratio * base)
        return max(0.01, round(base + delta, 3))


class NetworkEngine:
    """
    High-Performance In-Memory Pipeline:
    - 20MB chunks streamed directly through virtual RAM buffer (0 SSD writes).
    - Multi-core CPU parallel encryption via ProcessPoolExecutor (bypassing Python GIL).
    - Direct Memory-to-Cloud streaming using 'rclone rcat' and 'rclone cat'.
    - Hard kill-switch with instant ProcessManager termination and zero background persistence.
    """
    def __init__(self, db=None, crypto=None, retry_policy=None):
        self.db = db or DatabaseEngine()
        self.crypto = crypto or CryptoEngine()
        self.retry_policy = retry_policy or UploadRetryPolicy()
        self.cancel_requested = False

    def _sleep_with_cancel_check(self, delay: float):
        """Sleeps in small slices, checking cancel_requested frequently for responsive cancellation."""
        start = time.time()
        while time.time() - start < delay:
            if self.cancel_requested:
                raise Exception("Transfer cancelled by user.")
            time.sleep(min(0.05, max(0.0, delay - (time.time() - start))))

    def _verify_remote_chunk(self, account_name, chunk_id, expected_size=None, timeout=15):
        """
        Verifies whether chunk_id exists on account_name:CloudPool_Vault/{chunk_id}.enc.
        Returns (exists: bool, size: int or None).
        """
        remote_path = f"{account_name}:CloudPool_Vault/{chunk_id}.enc"
        cmd = [RCLONE_BIN, "size", remote_path, "--json"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=timeout)
            if proc.returncode == 0:
                try:
                    data = json.loads(stdout)
                    cnt = data.get("count", 0)
                    bytes_cnt = data.get("bytes", 0)
                    if cnt > 0:
                        if expected_size is not None and bytes_cnt > 0 and bytes_cnt != expected_size:
                            return (False, bytes_cnt)
                        return (True, bytes_cnt)
                except Exception:
                    return (False, None)
            return (False, None)
        except Exception:
            return (False, None)

    def cancel_transfer(self, op_id=None):
        """Signals active upload or download streams to terminate immediately and kills specific or all child processes."""
        self.cancel_requested = True
        if op_id:
            ProcessManager.cancel_operation(op_id)
        else:
            ProcessManager.kill_all_processes()

    def _notify_progress(self, callback, step, current, total, percent, account="", message="", **kwargs):
        """Safely invokes a progress callback with rich metrics if provided."""
        if not callback:
            return
        payload = {
            "step": step,
            "current": current,
            "total": total,
            "percent": percent,
            "account": account,
            "message": message
        }
        payload.update(kwargs)
        try:
            callback(**payload)
        except TypeError:
            try:
                callback(payload)
            except Exception:
                pass
        except Exception:
            pass

    def _get_eligible_account(self, required_bytes, tier, exclude_accounts=None):
        """
        Finds the lowest priority number (highest urgency) account with enough free space.
        If tier is None, searches across all tiers.
        Strictly ensures the account exists in rclone.conf and honors exclude_accounts.
        """
        if exclude_accounts is None:
            exclude_accounts = set()
        else:
            exclude_accounts = set(exclude_accounts)

        cur = self.db.conn.cursor()
        tier_filter = "reliability_tier = ?" if tier is not None else "1=1"
        tier_param = [tier] if tier is not None else []

        if exclude_accounts:
            placeholders = ",".join("?" for _ in exclude_accounts)
            query = f"""
                SELECT account_name, usable_capacity_bytes, used_bytes, priority 
                FROM cloud_accounts 
                WHERE {tier_filter}
                  AND (status IS NULL OR status = 'CONNECTED')
                  AND (usable_capacity_bytes - used_bytes) >= ?
                  AND account_name NOT IN ({placeholders})
                ORDER BY priority ASC, (usable_capacity_bytes - used_bytes) DESC
            """
            params = tier_param + [required_bytes] + list(exclude_accounts)
            cur.execute(query, tuple(params))
            for row in cur.fetchall():
                acc = dict(row)
                if self.db.is_remote_in_rclone_config(acc["account_name"]):
                    return acc
            return None
        else:
            query = f"""
                SELECT account_name, usable_capacity_bytes, used_bytes, priority 
                FROM cloud_accounts 
                WHERE {tier_filter}
                  AND (status IS NULL OR status = 'CONNECTED')
                  AND (usable_capacity_bytes - used_bytes) >= ?
                ORDER BY priority ASC, (usable_capacity_bytes - used_bytes) DESC
            """
            params = tier_param + [required_bytes]
            cur.execute(query, tuple(params))
            for row in cur.fetchall():
                acc = dict(row)
                if self.db.is_remote_in_rclone_config(acc["account_name"]):
                    return acc
            return None

    def _rollback_failed_upload(self, file_id, op_id=None):
        """Cleanly wipes any partial remote chunks and removes SQLite records for an aborted upload."""
        if op_id:
            return self.db.rollback_upload_journal(op_id)

        cur = self.db.conn.cursor()
        cur.execute("SELECT op_id FROM upload_journal WHERE file_id = ? AND status != 'completed' ORDER BY created_at DESC", (file_id,))
        row = cur.fetchone()
        if row:
            return self.db.rollback_upload_journal(row["op_id"])

        # Fallback for unjournaled legacy operations
        cur.execute("SELECT chunk_id, account_name, chunk_size_bytes FROM file_chunks WHERE file_id = ?", (file_id,))
        chunks = cur.fetchall()
        for ch in chunks:
            self.db._rclone_delete_remote_chunk(ch["account_name"], ch["chunk_id"])
        with self.db.conn:
            cur.execute("DELETE FROM file_chunks WHERE file_id = ?", (file_id,))
            cur.execute("DELETE FROM virtual_files WHERE file_id = ?", (file_id,))
        self.db.reconcile_storage_counters()

        # Clean local vault for any leftover files if any existed
        if os.path.exists(VAULT_DIR):
            for fn in os.listdir(VAULT_DIR):
                if fn.startswith(file_id[:8]):
                    try:
                        os.remove(os.path.join(VAULT_DIR, fn))
                    except Exception:
                        pass

    def upload_stream(self, stream_obj, total_size, file_name, file_id=None, target_tier="STABLE", target_folder_id=None,
                      progress_callback=None, enable_parity=True, batch_completed_bytes=0, batch_total_bytes=0,
                      file_index=1, total_files=1, batch_start_time=None, defer_metadata_sync=False,
                      is_container=0, relative_path=None, strict_parity=True, allow_unprotected_fallback=False,
                      file_hash=None, hash_algorithm="SHA-256", resume_op_id=None, retry_policy=None,
                      auto_rollback=True):
        """
        High-Performance In-Memory RAM Pipeline with Resumable Uploads & Intelligent Retry (TASK 13):
        - Stream-slices data into 20MB chunks directly from memory/stream (0 SSD temporary files).
        - Exponential backoff with uniform random jitter for transient failures (timeouts, socket resets, 5xx).
        - Immediate failover for permanent errors (quota exceeded, 401 auth, 403 forbidden, missing remotes).
        - Avoids duplicate remote object creation: reuses verified surviving chunks during resume.
        - Rolling Bitwise XOR Parity Accumulator computed in real time on the fly via NumPy.
        - Direct Memory-to-Cloud streaming via 'rclone rcat' stdin pipe with explicit EOF signal.
        - stdout=subprocess.DEVNULL to prevent pipe buffer deadlocks.
        - ProcessManager tracks child PIDs for instant cancellation and zero background persistence.
        - End-to-end cryptographic SHA-256 integrity verification for original file and all chunk ciphertexts.
        """
        if self.cancel_requested:
            raise Exception("Transfer cancelled by user.")

        if target_folder_id in ("", "root", "ROOT", "None"):
            target_folder_id = None

        active_retry_policy = retry_policy or self.retry_policy

        if resume_op_id:
            op_id = resume_op_id
            journal = self.db.get_upload_journal_entry(op_id)
            if not journal:
                raise ValueError(f"Cannot resume upload: Operation ID '{op_id}' not found in upload_journal.")
            file_id = journal["file_id"]
            file_name = journal["file_name"]
            total_size = journal["total_size_bytes"]
            target_tier = journal["target_tier"]
            target_folder_id = journal["target_folder_id"]
            enable_parity = bool(journal["enable_parity"])
            data_chunk_count = journal["data_chunks_count"]
            total_chunks = journal["total_expected_chunks"]
            file_hash = journal["file_hash"] or file_hash
            hash_algorithm = journal.get("hash_algorithm") or hash_algorithm
            existing_journal_chunks = {c["chunk_id"]: c for c in self.db.get_upload_journal_chunks(op_id)}
            self.db.update_upload_journal_status(op_id, "uploading")
        else:
            existing_journal_chunks = {}
            file_id = file_id or str(uuid.uuid4())
            op_id = f"op_{uuid.uuid4().hex[:12]}"
            data_chunk_count = max(1, (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if total_size > 0 else 1
            total_chunks = data_chunk_count + (1 if enable_parity else 0)

            # 0. Register operation in persistent upload journal (State: 'preparing')
            self.db.create_upload_journal_entry(
                op_id=op_id,
                file_id=file_id,
                file_name=file_name,
                total_size_bytes=total_size,
                target_tier=target_tier,
                target_folder_id=target_folder_id,
                enable_parity=1 if enable_parity else 0,
                total_expected_chunks=total_chunks,
                data_chunks_count=data_chunk_count,
                is_container=is_container,
                relative_path=relative_path,
                file_hash=file_hash,
                hash_algorithm=hash_algorithm
            )

        if batch_total_bytes <= 0:
            batch_total_bytes = total_size
        if batch_start_time is None:
            batch_start_time = time.time()

        init_pct = round((batch_completed_bytes / max(1, batch_total_bytes)) * 100, 1)
        self._notify_progress(
            progress_callback,
            step="initializing",
            current=0,
            total=total_chunks,
            percent=init_pct,
            account="",
            file_name=file_name,
            file_index=file_index,
            total_files=total_files,
            completed_bytes=batch_completed_bytes,
            total_bytes=batch_total_bytes,
            remaining_bytes=max(0, batch_total_bytes - batch_completed_bytes),
            speed_bps=0.0,
            eta_seconds=0,
            message=f"{'Resuming' if resume_op_id else 'Registering'} '{file_name}' ({data_chunk_count} data chunks + {'1 RAID-5 parity' if enable_parity else 'no parity'})..."
        )

        # 1. Register or update virtual file in SQLite (with container metadata and integrity tracking)
        cur = self.db.conn.cursor()
        cur.execute("""
            INSERT INTO virtual_files (
                file_id, file_name, total_size_bytes, uploaded_at, folder_id,
                container_id, is_container, relative_path, upload_status,
                file_hash, hash_algorithm, integrity_status
            )
            VALUES (?, ?, ?, datetime('now'), ?, NULL, ?, ?, 'uploading', ?, ?, 'unverified')
            ON CONFLICT(file_id) DO UPDATE SET
                upload_status = 'uploading',
                file_hash = COALESCE(excluded.file_hash, virtual_files.file_hash)
        """, (file_id, file_name, total_size, target_folder_id, is_container, relative_path, file_hash, hash_algorithm))
        self.db.conn.commit()

        # Update journal to 'uploading'
        self.db.update_upload_journal_status(op_id, "uploading")

        part_number = 1
        used_accounts = set()
        failed_remotes_for_file = set()
        rolling_parity = None
        plaintext_hasher = hashlib.sha256()
        post_pct = init_pct
        post_done_bytes = batch_completed_bytes
        post_rem_bytes = max(0, batch_total_bytes - post_done_bytes)
        post_speed = 0.0
        post_eta = 0

        try:
            while True:
                if self.cancel_requested:
                    raise Exception("Transfer cancelled by user.")

                raw_chunk = stream_obj.read(CHUNK_SIZE)
                if not raw_chunk:
                    if total_size == 0 and part_number == 1:
                        raw_chunk = b""
                    else:
                        break

                actual_len = len(raw_chunk)
                plaintext_hasher.update(raw_chunk)

                # Rolling bitwise XOR parity computation on the fly (microsecond NumPy XOR)
                if enable_parity:
                    if rolling_parity is None:
                        rolling_parity = bytearray(raw_chunk)
                    else:
                        if len(rolling_parity) < actual_len:
                            rolling_parity.extend(b"\x00" * (actual_len - len(rolling_parity)))
                        try:
                            import numpy as np
                            arr_p = np.frombuffer(rolling_parity, dtype=np.uint8, count=actual_len)
                            arr_c = np.frombuffer(raw_chunk, dtype=np.uint8, count=actual_len)
                            arr_p ^= arr_c
                        except Exception:
                            for i in range(actual_len):
                                rolling_parity[i] ^= raw_chunk[i]

                # Instant AES-256-GCM encryption of this single chunk in RAM
                encrypted_chunk = self.crypto.encrypt_data(raw_chunk)
                cipher_hash = IntegrityEngine.compute_bytes_sha256(encrypted_chunk)
                del raw_chunk  # Immediately free raw chunk from RAM

                chunk_id = f"{file_id[:8]}_part{part_number:04d}"
                chunk_uploaded = False
                failed_remotes_for_chunk = set()

                cur_chunk_done_bytes = (part_number - 1) * CHUNK_SIZE
                overall_done_bytes = batch_completed_bytes + cur_chunk_done_bytes
                rem_bytes = max(0, batch_total_bytes - overall_done_bytes)
                elapsed_s = max(0.1, time.time() - batch_start_time)
                current_speed = overall_done_bytes / elapsed_s
                eta_s = int(rem_bytes / max(1.0, current_speed)) if current_speed > 1024 else 0
                calc_pct = min(99.9, round((overall_done_bytes / max(1, batch_total_bytes)) * 100, 1))

                # Check if chunk was already uploaded and is verified on remote (Resume Optimization)
                if chunk_id in existing_journal_chunks:
                    ex_chunk = existing_journal_chunks[chunk_id]
                    if ex_chunk.get("status") in ("uploaded", "committed"):
                        ex_acc = ex_chunk["account_name"]
                        exists, _ = self._verify_remote_chunk(ex_acc, chunk_id, expected_size=len(encrypted_chunk))
                        if exists:
                            chunk_uploaded = True
                            used_accounts.add(ex_acc)
                            print(f"[RESUME] Reusing verified remote chunk {chunk_id} on {ex_acc} (skipping re-upload)")
                            self._notify_progress(
                                progress_callback,
                                step="chunk_reused",
                                current=part_number,
                                total=total_chunks,
                                percent=calc_pct,
                                account=ex_acc,
                                file_name=file_name,
                                file_index=file_index,
                                total_files=total_files,
                                completed_bytes=overall_done_bytes + actual_len,
                                total_bytes=batch_total_bytes,
                                remaining_bytes=max(0, rem_bytes - actual_len),
                                speed_bps=current_speed,
                                eta_seconds=eta_s,
                                message=f"Chunk {part_number}/{total_chunks} verified on {ex_acc}. Reusing remote object."
                            )
                            enc_len = len(encrypted_chunk)
                            cur.execute("""
                                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash)
                                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                                ON CONFLICT(chunk_id) DO UPDATE SET
                                    account_name = excluded.account_name,
                                    chunk_size_bytes = excluded.chunk_size_bytes,
                                    encrypted_size_bytes = excluded.encrypted_size_bytes,
                                    ciphertext_hash = excluded.ciphertext_hash
                            """, (chunk_id, file_id, ex_acc, part_number, actual_len, enc_len, cipher_hash))
                            self.db.conn.commit()

                while not chunk_uploaded:
                    excluded = failed_remotes_for_chunk.union(failed_remotes_for_file)
                    needed_remote_bytes = actual_len + 28
                    account = self._get_eligible_account(needed_remote_bytes, target_tier, exclude_accounts=excluded)
                    if not account and failed_remotes_for_file:
                        account = self._get_eligible_account(needed_remote_bytes, target_tier, exclude_accounts=failed_remotes_for_chunk)

                    if not account:
                        raise Exception(
                            f"All available {target_tier} cloud accounts failed or are full. "
                            f"Could not upload chunk {part_number}/{total_chunks}."
                        )

                    account_name = account["account_name"]
                    enc_len = len(encrypted_chunk)

                    # Persist chunk intent in upload journal before network stream
                    self.db.record_journal_chunk(
                        op_id=op_id,
                        chunk_id=chunk_id,
                        account_name=account_name,
                        part_number=part_number,
                        chunk_size_bytes=actual_len,
                        encrypted_size_bytes=enc_len,
                        is_parity=0,
                        status="uploading",
                        ciphertext_hash=cipher_hash
                    )

                    # Retry Loop on THIS account with Exponential Backoff & Jitter
                    for attempt in range(active_retry_policy.max_retries + 1):
                        if self.cancel_requested:
                            ProcessManager.cancel_operation(op_id)
                            raise Exception("Transfer cancelled by user.")

                        self._notify_progress(
                            progress_callback,
                            step="uploading",
                            current=part_number,
                            total=total_chunks,
                            percent=calc_pct,
                            account=account_name,
                            file_name=file_name,
                            file_index=file_index,
                            total_files=total_files,
                            completed_bytes=overall_done_bytes,
                            total_bytes=batch_total_bytes,
                            remaining_bytes=rem_bytes,
                            speed_bps=current_speed,
                            eta_seconds=eta_s,
                            message=f"Streaming '{file_name}' chunk {part_number}/{total_chunks} from RAM to {account_name}..."
                        )

                        # Direct stream from RAM via rclone rcat stdin
                        command = [RCLONE_BIN, "rcat", f"{account_name}:CloudPool_Vault/{chunk_id}.enc"]
                        try:
                            proc = subprocess.Popen(
                                command,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE
                            )
                            ProcessManager.register_process(proc, op_id=op_id, description=f"rcat chunk {chunk_id}")
                            try:
                                STREAM_BLOCK = 256 * 1024
                                chunk_sent = 0
                                enc_len = len(encrypted_chunk)
                                last_notify_time = 0

                                while chunk_sent < enc_len:
                                    if self.cancel_requested:
                                        ProcessManager.cancel_operation(op_id)
                                        raise Exception("Transfer cancelled by user.")

                                    block = encrypted_chunk[chunk_sent:chunk_sent + STREAM_BLOCK]
                                    proc.stdin.write(block)
                                    proc.stdin.flush()
                                    chunk_sent += len(block)

                                    now = time.time()
                                    if now - last_notify_time >= 0.25 or chunk_sent >= enc_len:
                                        last_notify_time = now
                                        live_done_bytes = batch_completed_bytes + (part_number - 1) * CHUNK_SIZE + int((chunk_sent / max(1, enc_len)) * actual_len)
                                        live_rem_bytes = max(0, batch_total_bytes - live_done_bytes)
                                        live_elapsed_s = max(0.1, now - batch_start_time)
                                        live_speed = live_done_bytes / live_elapsed_s
                                        live_eta = int(live_rem_bytes / max(1.0, live_speed)) if live_speed > 1024 else 0
                                        live_pct = min(99.9, round((live_done_bytes / max(1, batch_total_bytes)) * 100, 1))
                                        chunk_pct = min(100.0, round((chunk_sent / max(1, enc_len)) * 100, 1))

                                        self._notify_progress(
                                            progress_callback,
                                            step="uploading",
                                            current=part_number,
                                            total=total_chunks,
                                            percent=live_pct,
                                            chunk_percent=chunk_pct,
                                            chunk_sent=chunk_sent,
                                            chunk_total=enc_len,
                                            account=account_name,
                                            file_name=file_name,
                                            file_index=file_index,
                                            total_files=total_files,
                                            completed_bytes=live_done_bytes,
                                            total_bytes=batch_total_bytes,
                                            remaining_bytes=live_rem_bytes,
                                            speed_bps=live_speed,
                                            eta_seconds=live_eta,
                                            message=f"Streaming '{file_name}' to {account_name} ({live_pct:.1f}% • {format_bytes(live_done_bytes)}/{format_bytes(batch_total_bytes)})..."
                                        )

                                # Explicit EOF: flush and forcefully close stdin pipe immediately
                                proc.stdin.flush()
                                proc.stdin.close()

                                # Wait for cloud server finalize with realistic 600s timeout
                                stdout, stderr = proc.communicate(timeout=600)
                                returncode = proc.returncode
                            finally:
                                ProcessManager.unregister_process(proc, op_id=op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
                        except FileNotFoundError:
                            raise Exception(f"Rclone binary not found at '{RCLONE_BIN}'. Ensure rclone.exe is present.")
                        except Exception as ex:
                            if self.cancel_requested:
                                raise ex
                            returncode = 1
                            stderr = str(ex).encode()

                        if self.cancel_requested:
                            raise Exception("Transfer cancelled by user.")

                        if returncode == 0:
                            chunk_uploaded = True
                            used_accounts.add(account_name)
                            self.db.update_journal_chunk_status(op_id, chunk_id, "uploaded")

                            enc_len = len(encrypted_chunk)
                            cur.execute("""
                                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash)
                                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                                ON CONFLICT(chunk_id) DO UPDATE SET
                                    account_name = excluded.account_name,
                                    chunk_size_bytes = excluded.chunk_size_bytes,
                                    encrypted_size_bytes = excluded.encrypted_size_bytes,
                                    ciphertext_hash = excluded.ciphertext_hash
                            """, (chunk_id, file_id, account_name, part_number, actual_len, enc_len, cipher_hash))

                            cur.execute("""
                                UPDATE cloud_accounts 
                                SET used_bytes = used_bytes + ? 
                                WHERE account_name = ?
                            """, (enc_len, account_name))
                            self.db.conn.commit()
                            break  # Chunk upload succeeded! Exit retry loop

                        # Failure handling & Error Classification
                        err_msg = stderr.decode("utf-8", errors="ignore").strip() if hasattr(stderr, "decode") else str(stderr)
                        err_type, err_cat = UploadErrorClassifier.classify(err_msg)

                        if err_cat == UploadErrorCategory.PERMANENT_FATAL:
                            self.db.update_journal_chunk_status(op_id, chunk_id, "failed", error_message=err_msg)
                            raise Exception(f"Fatal transfer failure for chunk {part_number}: {err_msg}")

                        elif err_cat == UploadErrorCategory.PERMANENT_REMOTE:
                            # Permanent failure on this remote: do not retry; failover immediately!
                            print(f"[PERMANENT REMOTE ERROR] Remote '{account_name}' rejected upload: {err_type} ({err_msg}). Failing over immediately.")
                            self.db.update_journal_chunk_status(op_id, chunk_id, "failed", error_message=err_msg)
                            failed_remotes_for_chunk.add(account_name)
                            failed_remotes_for_file.add(account_name)
                            self._notify_progress(
                                progress_callback,
                                step="failover_immediate",
                                current=part_number,
                                total=total_chunks,
                                percent=calc_pct,
                                account=account_name,
                                file_name=file_name,
                                file_index=file_index,
                                total_files=total_files,
                                completed_bytes=overall_done_bytes,
                                total_bytes=batch_total_bytes,
                                remaining_bytes=rem_bytes,
                                speed_bps=current_speed,
                                eta_seconds=eta_s,
                                message=f"Remote '{account_name}' failed permanently ({err_type}). Switching to alternative remote..."
                            )
                            break  # Break retry loop to select new account

                        else:
                            # TRANSIENT failure: retry on the SAME remote with exponential backoff & jitter
                            if attempt < active_retry_policy.max_retries:
                                delay = active_retry_policy.calculate_backoff(attempt)
                                print(f"[RETRY] Transient failure on '{account_name}' ({err_type}): {err_msg}. Retrying in {delay:.2f}s (attempt {attempt+1}/{active_retry_policy.max_retries})...")
                                self._notify_progress(
                                    progress_callback,
                                    step="retry_backoff",
                                    current=part_number,
                                    total=total_chunks,
                                    percent=calc_pct,
                                    account=account_name,
                                    file_name=file_name,
                                    file_index=file_index,
                                    total_files=total_files,
                                    completed_bytes=overall_done_bytes,
                                    total_bytes=batch_total_bytes,
                                    remaining_bytes=rem_bytes,
                                    speed_bps=current_speed,
                                    eta_seconds=eta_s,
                                    attempt=attempt + 1,
                                    max_retries=active_retry_policy.max_retries,
                                    backoff_delay=delay,
                                    message=f"Network glitch on '{account_name}' ({err_type}). Retrying in {delay:.1f}s (attempt {attempt+1}/{active_retry_policy.max_retries})..."
                                )
                                self._sleep_with_cancel_check(delay)
                            else:
                                print(f"[RETRY EXHAUSTED] Max retries ({active_retry_policy.max_retries}) exhausted on '{account_name}'. Failing over to alternative remote...")
                                self.db.update_journal_chunk_status(op_id, chunk_id, "failed", error_message=err_msg)
                                failed_remotes_for_chunk.add(account_name)
                                failed_remotes_for_file.add(account_name)
                                self._notify_progress(
                                    progress_callback,
                                    step="failover_retry",
                                    current=part_number,
                                    total=total_chunks,
                                    percent=calc_pct,
                                    account=account_name,
                                    file_name=file_name,
                                    file_index=file_index,
                                    total_files=total_files,
                                    completed_bytes=overall_done_bytes,
                                    total_bytes=batch_total_bytes,
                                    remaining_bytes=rem_bytes,
                                    speed_bps=current_speed,
                                    eta_seconds=eta_s,
                                    message=f"Remote '{account_name}' failed after {active_retry_policy.max_retries} retries. Falling back to alternative remote..."
                                )
                                break

                    # End of retry loop for account_name

                del encrypted_chunk  # Immediately free encrypted chunk from RAM

                post_done_bytes = batch_completed_bytes + (part_number - 1) * CHUNK_SIZE + actual_len
                post_rem_bytes = max(0, batch_total_bytes - post_done_bytes)
                post_elapsed_s = max(0.1, time.time() - batch_start_time)
                post_speed = post_done_bytes / post_elapsed_s
                post_eta = int(post_rem_bytes / max(1.0, post_speed)) if post_speed > 1024 else 0
                post_pct = min(100.0, round((post_done_bytes / max(1, batch_total_bytes)) * 100, 1))

                self._notify_progress(
                    progress_callback,
                    step="chunk_done",
                    current=part_number,
                    total=total_chunks,
                    percent=post_pct,
                    account=account_name if not chunk_uploaded else list(used_accounts)[-1],
                    file_name=file_name,
                    file_index=file_index,
                    total_files=total_files,
                    completed_bytes=post_done_bytes,
                    total_bytes=batch_total_bytes,
                    remaining_bytes=post_rem_bytes,
                    speed_bps=post_speed,
                    eta_seconds=post_eta,
                    message=f"Chunk {part_number}/{total_chunks} streamed & secured."
                )

                part_number += 1
                if total_size == 0:
                    break

            # Verify or finalize end-to-end original file hash
            computed_file_hash = plaintext_hasher.hexdigest()
            if file_hash:
                if not IntegrityEngine.verify_hash(computed_file_hash, file_hash):
                    raise FileIntegrityError(f"Original file hash mismatch during upload: expected {file_hash}, got {computed_file_hash}")
            else:
                file_hash = computed_file_hash

            # -------------------------------------------------------------
            # Instant RAID-5 XOR Parity Upload (Already fully computed in RAM!)
            # -------------------------------------------------------------
            if enable_parity and rolling_parity is not None:
                self.db.update_upload_journal_status(op_id, "uploading_parity")
                parity_num = total_chunks
                parity_bytes = bytes(rolling_parity)
                del rolling_parity  # Free rolling parity accumulator
                parity_len = len(parity_bytes)
                parity_chunk_id = f"{file_id[:8]}_parity"

                encrypted_parity = self.crypto.encrypt_data(parity_bytes)
                parity_cipher_hash = IntegrityEngine.compute_bytes_sha256(encrypted_parity)
                del parity_bytes

                parity_uploaded = False
                failed_parity_remotes = set()

                # Check if parity was already verified/uploaded in existing journal (Resume)
                if parity_chunk_id in existing_journal_chunks:
                    ex_par = existing_journal_chunks[parity_chunk_id]
                    if ex_par.get("status") in ("uploaded", "committed"):
                        ex_p_acc = ex_par["account_name"]
                        exists, _ = self._verify_remote_chunk(ex_p_acc, parity_chunk_id, expected_size=len(encrypted_parity))
                        if exists:
                            parity_uploaded = True
                            used_accounts.add(ex_p_acc)
                            print(f"[RESUME] Reusing verified parity chunk {parity_chunk_id} on {ex_p_acc}")
                            par_total = len(encrypted_parity)
                            cur.execute("""
                                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash)
                                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                                ON CONFLICT(chunk_id) DO UPDATE SET
                                    account_name = excluded.account_name,
                                    chunk_size_bytes = excluded.chunk_size_bytes,
                                    encrypted_size_bytes = excluded.encrypted_size_bytes,
                                    ciphertext_hash = excluded.ciphertext_hash
                            """, (parity_chunk_id, file_id, ex_p_acc, 9999, parity_len, par_total, parity_cipher_hash))
                            self.db.conn.commit()

                while not parity_uploaded:
                    if self.cancel_requested:
                        raise Exception("Transfer cancelled by user.")

                    excluded_p = used_accounts.union(failed_parity_remotes).union(failed_remotes_for_file)
                    needed_parity_remote_bytes = parity_len + 28
                    parity_acc_info = self._get_eligible_account(needed_parity_remote_bytes, target_tier, exclude_accounts=excluded_p)
                    if not parity_acc_info:
                        # Attempt placement on any independent connected account across other tiers
                        parity_acc_info = self._get_eligible_account(needed_parity_remote_bytes, None, exclude_accounts=excluded_p)

                    if not parity_acc_info:
                        err_msg = (
                            f"RAID-5 failure-domain isolation violated: No independent cloud remote available for parity block. "
                            f"All available accounts ({', '.join(sorted(used_accounts))}) already hold data chunks for this file."
                        )
                        if strict_parity or not allow_unprotected_fallback:
                            raise ParityPlacementError(err_msg)
                        else:
                            print(f"[PARITY WARNING] {err_msg} Storing file unprotected without parity.")
                            enable_parity = False
                            total_chunks = data_chunk_count
                            self.db.update_upload_journal_parity(op_id, enable_parity=0)
                            break

                    parity_account = parity_acc_info["account_name"]
                    par_total = len(encrypted_parity)
                    self.db.record_journal_chunk(
                        op_id=op_id,
                        chunk_id=parity_chunk_id,
                        account_name=parity_account,
                        part_number=9999,
                        chunk_size_bytes=parity_len,
                        encrypted_size_bytes=par_total,
                        is_parity=1,
                        status="uploading",
                        ciphertext_hash=parity_cipher_hash
                    )

                    # Retry Loop on parity account
                    for p_attempt in range(active_retry_policy.max_retries + 1):
                        if self.cancel_requested:
                            ProcessManager.cancel_operation(op_id)
                            raise Exception("Transfer cancelled by user.")

                        self._notify_progress(
                            progress_callback,
                            step="parity_uploading",
                            current=parity_num,
                            total=total_chunks,
                            percent=post_pct,
                            account=parity_account,
                            file_name=file_name,
                            file_index=file_index,
                            total_files=total_files,
                            completed_bytes=post_done_bytes,
                            total_bytes=batch_total_bytes,
                            remaining_bytes=post_rem_bytes,
                            speed_bps=post_speed,
                            eta_seconds=post_eta,
                            message=f"Streaming RAID-5 Parity block directly to {parity_account}..."
                        )

                        command = [RCLONE_BIN, "rcat", f"{parity_account}:CloudPool_Vault/{parity_chunk_id}.enc"]
                        try:
                            proc = subprocess.Popen(
                                command,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE
                            )
                            ProcessManager.register_process(proc, op_id=op_id, description=f"rcat parity {parity_chunk_id}")
                            try:
                                STREAM_BLOCK = 256 * 1024
                                par_sent = 0
                                par_total = len(encrypted_parity)
                                last_par_notify = 0

                                while par_sent < par_total:
                                    if self.cancel_requested:
                                        ProcessManager.cancel_operation(op_id)
                                        raise Exception("Transfer cancelled by user.")

                                    block = encrypted_parity[par_sent:par_sent + STREAM_BLOCK]
                                    proc.stdin.write(block)
                                    proc.stdin.flush()
                                    par_sent += len(block)

                                    now = time.time()
                                    if now - last_par_notify >= 0.25 or par_sent >= par_total:
                                        last_par_notify = now
                                        par_pct = int((par_sent / max(1, par_total)) * 100)
                                        self._notify_progress(
                                            progress_callback,
                                            step="parity_uploading",
                                            current=parity_num,
                                            total=total_chunks,
                                            percent=min(99.9, post_pct),
                                            chunk_percent=par_pct,
                                            chunk_sent=par_sent,
                                            chunk_total=par_total,
                                            account=parity_account,
                                            file_name=file_name,
                                            file_index=file_index,
                                            total_files=total_files,
                                            completed_bytes=post_done_bytes,
                                            total_bytes=batch_total_bytes,
                                            remaining_bytes=post_rem_bytes,
                                            speed_bps=post_speed,
                                            eta_seconds=post_eta,
                                            message=f"Streaming RAID-5 Parity to {parity_account} ({par_pct}%)..."
                                        )

                                proc.stdin.flush()
                                proc.stdin.close()
                                stdout, stderr = proc.communicate(timeout=600)
                                returncode = proc.returncode
                            finally:
                                ProcessManager.unregister_process(proc, op_id=op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
                        except Exception as ex:
                            if self.cancel_requested:
                                raise ex
                            returncode = 1
                            stderr = str(ex).encode()

                        if self.cancel_requested:
                            raise Exception("Transfer cancelled by user.")

                        if returncode == 0:
                            parity_uploaded = True
                            self.db.update_journal_chunk_status(op_id, parity_chunk_id, "uploaded")
                            par_total = len(encrypted_parity)
                            cur.execute("""
                                INSERT INTO file_chunks (chunk_id, file_id, account_name, part_number, chunk_size_bytes, encrypted_size_bytes, is_parity, ciphertext_hash)
                                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                                ON CONFLICT(chunk_id) DO UPDATE SET
                                    account_name = excluded.account_name,
                                    chunk_size_bytes = excluded.chunk_size_bytes,
                                    encrypted_size_bytes = excluded.encrypted_size_bytes,
                                    ciphertext_hash = excluded.ciphertext_hash
                            """, (parity_chunk_id, file_id, parity_account, 9999, parity_len, par_total, parity_cipher_hash))

                            cur.execute("""
                                UPDATE cloud_accounts 
                                SET used_bytes = used_bytes + ? 
                                WHERE account_name = ?
                            """, (par_total, parity_account))
                            self.db.conn.commit()

                            self._notify_progress(
                                progress_callback,
                                step="parity_done",
                                current=parity_num,
                                total=total_chunks,
                                percent=post_pct,
                                account=parity_account,
                                file_name=file_name,
                                file_index=file_index,
                                total_files=total_files,
                                completed_bytes=post_done_bytes,
                                total_bytes=batch_total_bytes,
                                remaining_bytes=post_rem_bytes,
                                speed_bps=post_speed,
                                eta_seconds=post_eta,
                                message=f"RAID-5 Parity block streamed & secured on {parity_account}."
                            )
                            break
                        else:
                            p_err_msg = stderr.decode("utf-8", errors="ignore").strip() if hasattr(stderr, "decode") else str(stderr)
                            p_type, p_cat = UploadErrorClassifier.classify(p_err_msg)

                            if p_cat == UploadErrorCategory.PERMANENT_REMOTE:
                                print(f"[PERMANENT REMOTE ERROR] Parity on '{parity_account}' rejected: {p_type}. Failover immediately.")
                                self.db.update_journal_chunk_status(op_id, parity_chunk_id, "failed", error_message=p_err_msg)
                                failed_parity_remotes.add(parity_account)
                                break
                            else:
                                if p_attempt < active_retry_policy.max_retries:
                                    delay = active_retry_policy.calculate_backoff(p_attempt)
                                    print(f"[RETRY] Parity transient failure on '{parity_account}' ({p_type}): {p_err_msg}. Retrying in {delay:.2f}s...")
                                    self._sleep_with_cancel_check(delay)
                                else:
                                    print(f"[FAILOVER WARNING] Parity retries exhausted on {parity_account}. Falling back...")
                                    self.db.update_journal_chunk_status(op_id, parity_chunk_id, "failed", error_message=p_err_msg)
                                    failed_parity_remotes.add(parity_account)
                                    break

                del encrypted_parity

            # -------------------------------------------------------------
            # Stage 4: Verifying
            # -------------------------------------------------------------
            self.db.update_upload_journal_status(op_id, "verifying")
            up_chunks = self.db.get_upload_journal_chunks(op_id, status_filter="uploaded")
            if len(up_chunks) < total_chunks:
                raise Exception(f"Upload verification failed: expected {total_chunks} chunks, verified {len(up_chunks)}.")

            # -------------------------------------------------------------
            # Stage 5: Committing
            # -------------------------------------------------------------
            self.db.update_upload_journal_status(op_id, "committing")
            with self.db.conn:
                cur = self.db.conn.cursor()
                cur.execute("""
                    UPDATE virtual_files 
                    SET upload_status = 'completed', 
                        integrity_status = 'verified', 
                        file_hash = COALESCE(?, file_hash) 
                    WHERE file_id = ?
                """, (file_hash, file_id))
                cur.execute("UPDATE upload_journal SET file_hash = COALESCE(?, file_hash) WHERE op_id = ?", (file_hash, op_id))
                cur.execute("UPDATE upload_journal_chunks SET status = 'committed' WHERE op_id = ?", (op_id,))

            # -------------------------------------------------------------
            # Stage 6: Completed
            # -------------------------------------------------------------
            self.db.update_upload_journal_status(op_id, "completed")

        except Exception as e:
            if auto_rollback:
                print(f"[UPLOAD FAILED - INITIATING ATOMIC ROLLBACK] File ID {file_id} (Op {op_id}): {e}")
                try:
                    self._rollback_failed_upload(file_id, op_id=op_id)
                except Exception as rb_err:
                    print(f"[ROLLBACK ERROR] {rb_err}")
            else:
                print(f"[UPLOAD INTERRUPTED - PRESERVING FOR RESUME] File ID {file_id} (Op {op_id}): {e}")
                try:
                    self.db.update_upload_journal_status(op_id, "failed", error_message=str(e))
                except Exception:
                    pass
            raise e

        # Automated Metadata Mirroring (deferred during batch uploads)
        if not defer_metadata_sync:
            try:
                synced_remotes = MetadataEngine.sync_metadata_to_cloud(self.db)
                if synced_remotes:
                    print(f"[METADATA] Encrypted database mirrored to: {', '.join(synced_remotes)}")
            except Exception as e:
                print(f"[METADATA WARNING] Automated metadata sync skipped: {e}")

        self._notify_progress(
            progress_callback,
            step="complete",
            current=total_chunks,
            total=total_chunks,
            percent=100.0,
            account="",
            message=f"Success! '{file_name}' secured with AES-256-GCM + RAID-5 Parity."
        )
        return file_id

    def upload_file(self, filepath, target_tier="STABLE", target_folder_id=None, progress_callback=None, enable_parity=True,
                    batch_completed_bytes=0, batch_total_bytes=0, file_index=1, total_files=1, batch_start_time=None, defer_metadata_sync=False,
                    strict_parity=True, allow_unprotected_fallback=False, resume_op_id=None, retry_policy=None, auto_rollback=True):
        """Streams a local file through the in-memory chunking, encryption, and rolling-parity pipeline."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        file_size = os.path.getsize(filepath)
        file_name = os.path.basename(filepath)
        file_hash = IntegrityEngine.compute_stream_sha256(filepath)
        with open(filepath, "rb") as f:
            return self.upload_stream(
                stream_obj=f,
                total_size=file_size,
                file_name=file_name,
                target_tier=target_tier,
                target_folder_id=target_folder_id,
                progress_callback=progress_callback,
                enable_parity=enable_parity,
                batch_completed_bytes=batch_completed_bytes,
                batch_total_bytes=batch_total_bytes,
                file_index=file_index,
                total_files=total_files,
                batch_start_time=batch_start_time,
                defer_metadata_sync=defer_metadata_sync,
                strict_parity=strict_parity,
                allow_unprotected_fallback=allow_unprotected_fallback,
                file_hash=file_hash,
                hash_algorithm="SHA-256",
                resume_op_id=resume_op_id,
                retry_policy=retry_policy,
                auto_rollback=auto_rollback
            )

    def resume_upload(self, op_id, filepath, progress_callback=None, retry_policy=None, auto_rollback=False):
        """
        Resumes an interrupted or failed upload from the persistent upload journal:
        1. Validates that op_id exists in upload_journal and has surviving chunks.
        2. Inspects upload_journal_chunks to find already uploaded chunks.
        3. Verifies each uploaded chunk on the cloud remote.
        4. Re-opens filepath, verifies total size and plaintext integrity.
        5. Computes parity and hashes across the entire file while uploading ONLY the missing/failed chunks.
        6. Avoids duplicate remote chunk creation.
        7. Commits the resumed file into virtual_files and finalizes the upload journal.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Local file '{filepath}' not found for resume.")

        file_size = os.path.getsize(filepath)
        journal = self.db.get_upload_journal_entry(op_id)
        if not journal:
            raise ValueError(f"Cannot resume upload: Operation ID '{op_id}' not found in upload_journal.")

        if journal["total_size_bytes"] != file_size:
            raise ValueError(
                f"Source file size changed since initial upload (expected {journal['total_size_bytes']} bytes, found {file_size} bytes). Cannot resume."
            )

        with open(filepath, "rb") as f:
            return self.upload_stream(
                stream_obj=f,
                total_size=file_size,
                file_name=journal["file_name"],
                file_id=journal["file_id"],
                target_tier=journal["target_tier"],
                target_folder_id=journal["target_folder_id"],
                progress_callback=progress_callback,
                enable_parity=bool(journal["enable_parity"]),
                is_container=journal.get("is_container", 0),
                relative_path=journal.get("relative_path"),
                resume_op_id=op_id,
                retry_policy=retry_policy,
                auto_rollback=auto_rollback
            )

    def _download_chunks_to_file(self, file_id, dest_file_path, progress_callback=None):
        """
        Low-Memory Streaming Download Pipeline (TASK 10):
        - Spools directly to dest_file_path on disk with bounded RAM (<= 40MB total peak).
        - Incremental decryption: each 20MB chunk is decrypted and immediately written to disk.
        - Rolling XOR Parity accumulator: maintains an in-memory XOR buffer of at most 1 chunk size (20MB)
          to reconstruct any missing chunk without buffering the entire file.
        - Preserves chunk ordering via random-access seeking (f_out.seek(offset)).
        - Verifies ciphertext SHA-256 before decryption.
        - Avoids any full-file in-memory buffering or duplicate byte copies.
        """
        cur = self.db.conn.cursor()
        cur.execute("SELECT file_name, total_size_bytes FROM virtual_files WHERE file_id = ?", (file_id,))
        file_row = cur.fetchone()
        file_name = file_row["file_name"] if file_row else file_id
        total_size_bytes = file_row["total_size_bytes"] if file_row else None

        # Fetch data chunks with ciphertext hashes for integrity validation
        cur.execute("""
            SELECT chunk_id, account_name, part_number, chunk_size_bytes, ciphertext_hash 
            FROM file_chunks 
            WHERE file_id = ? AND is_parity = 0
            ORDER BY part_number ASC
        """, (file_id,))
        data_chunks = cur.fetchall()
        if not data_chunks:
            raise Exception(f"No data chunks found for file ID {file_id}.")

        # Fetch parity chunk if available
        cur.execute("""
            SELECT chunk_id, account_name, part_number, chunk_size_bytes, ciphertext_hash 
            FROM file_chunks 
            WHERE file_id = ? AND is_parity = 1
        """, (file_id,))
        parity_chunk_row = cur.fetchone()

        total_data_chunks = len(data_chunks)
        missing_chunks = []
        rolling_xor = None  # Single-chunk XOR accumulator (at most 20MB RAM)
        dl_op_id = f"dl_{file_id[:8]}_{uuid.uuid4().hex[:6]}"

        dest_dir = os.path.dirname(os.path.abspath(dest_file_path))
        os.makedirs(dest_dir, exist_ok=True)

        f_out = open(dest_file_path, "wb+")
        try:
            for idx, chunk in enumerate(data_chunks, start=1):
                if self.cancel_requested:
                    ProcessManager.cancel_operation(dl_op_id)
                    raise Exception("Download cancelled by user.")

                chunk_id = chunk["chunk_id"]
                account_name = chunk["account_name"]
                part_number = chunk["part_number"]
                chunk_size = chunk["chunk_size_bytes"]
                expected_cipher_hash = chunk["ciphertext_hash"] if "ciphertext_hash" in chunk.keys() else None

                pct = round(((idx - 0.5) / total_data_chunks) * 100, 1)
                self._notify_progress(
                    progress_callback,
                    step="downloading",
                    current=idx,
                    total=total_data_chunks,
                    percent=pct,
                    account=account_name,
                    message=f"Streaming chunk {idx}/{total_data_chunks} from {account_name} directly to storage..."
                )
                if self.cancel_requested:
                    ProcessManager.cancel_operation(dl_op_id)
                    raise Exception("Download cancelled by user.")

                cmd = [RCLONE_BIN, "cat", f"{account_name}:CloudPool_Vault/{chunk_id}.enc"]
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    ProcessManager.register_process(proc, op_id=dl_op_id, description=f"cat chunk {chunk_id}")
                    try:
                        enc_data, stderr = proc.communicate(timeout=600)
                        returncode = proc.returncode
                    finally:
                        ProcessManager.unregister_process(proc, op_id=dl_op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
                except Exception:
                    returncode = 1
                    enc_data = b""

                if self.cancel_requested:
                    ProcessManager.cancel_operation(dl_op_id)
                    raise Exception("Download cancelled by user.")

                if returncode == 0 and enc_data:
                    # Pre-decryption ciphertext integrity verification
                    if expected_cipher_hash:
                        actual_cipher_hash = IntegrityEngine.compute_bytes_sha256(enc_data)
                        if not IntegrityEngine.verify_hash(actual_cipher_hash, expected_cipher_hash):
                            print(f"[INTEGRITY CORRUPTION] Ciphertext SHA-256 mismatch for chunk {chunk_id} on {account_name} (expected {expected_cipher_hash}, got {actual_cipher_hash}).")
                            missing_chunks.append((part_number, chunk_id, account_name, chunk_size))
                            continue
                    try:
                        plain_data = self.crypto.decrypt_data(enc_data)
                        del enc_data  # Free ciphertext buffer immediately

                        # Accumulate surviving chunk into bounded rolling XOR parity accumulator if parity exists
                        if parity_chunk_row:
                            if rolling_xor is None:
                                rolling_xor = bytearray(plain_data)
                            else:
                                if len(rolling_xor) < len(plain_data):
                                    rolling_xor.extend(b"\x00" * (len(plain_data) - len(rolling_xor)))
                                try:
                                    import numpy as np
                                    arr_xor = np.frombuffer(rolling_xor, dtype=np.uint8, count=len(plain_data))
                                    arr_p = np.frombuffer(plain_data, dtype=np.uint8, count=len(plain_data))
                                    arr_xor ^= arr_p
                                except Exception:
                                    for i in range(len(plain_data)):
                                        rolling_xor[i] ^= plain_data[i]

                        # Write decrypted plaintext directly to file on disk at chunk offset
                        offset = (part_number - 1) * CHUNK_SIZE
                        f_out.seek(offset)
                        f_out.write(plain_data)
                        del plain_data  # Free plaintext buffer immediately

                    except Exception as dec_err:
                        print(f"[DECRYPT ERROR] Decryption failed for chunk {chunk_id}: {dec_err}")
                        missing_chunks.append((part_number, chunk_id, account_name, chunk_size))
                else:
                    missing_chunks.append((part_number, chunk_id, account_name, chunk_size))

            # RAID-5 XOR Recovery if exactly 1 chunk is missing
            if len(missing_chunks) == 1 and parity_chunk_row:
                failed_part, failed_chunk_id, failed_acc, expected_len = missing_chunks[0]
                parity_id = parity_chunk_row["chunk_id"]
                parity_acc = parity_chunk_row["account_name"]
                expected_parity_cipher_hash = parity_chunk_row["ciphertext_hash"] if "ciphertext_hash" in parity_chunk_row.keys() else None

                self._notify_progress(
                    progress_callback,
                    step="raid5_healing",
                    current=failed_part,
                    total=total_data_chunks,
                    percent=85.0,
                    account=parity_acc,
                    message=f"⚠️ {failed_acc} unreachable for Chunk {failed_part}. Streaming RAID-5 XOR Recovery from {parity_acc}..."
                )

                cmd = [RCLONE_BIN, "cat", f"{parity_acc}:CloudPool_Vault/{parity_id}.enc"]
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    ProcessManager.register_process(proc, op_id=dl_op_id, description=f"cat parity {parity_id}")
                    try:
                        parity_enc_data, stderr = proc.communicate(timeout=600)
                        returncode = proc.returncode
                    finally:
                        ProcessManager.unregister_process(proc, op_id=dl_op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
                except Exception:
                    returncode = 1
                    parity_enc_data = b""

                if returncode == 0 and parity_enc_data:
                    parity_valid = True
                    if expected_parity_cipher_hash:
                        actual_par_hash = IntegrityEngine.compute_bytes_sha256(parity_enc_data)
                        if not IntegrityEngine.verify_hash(actual_par_hash, expected_parity_cipher_hash):
                            print(f"[INTEGRITY ERROR] Parity ciphertext corrupted on remote '{parity_acc}' (expected {expected_parity_cipher_hash}, got {actual_par_hash})")
                            parity_valid = False

                    if parity_valid:
                        try:
                            decrypted_parity = self.crypto.decrypt_data(parity_enc_data)
                            del parity_enc_data

                            target_len = expected_len if expected_len is not None else len(decrypted_parity)
                            if rolling_xor is not None:
                                recovered_full = RAID5Engine.compute_parity([bytes(rolling_xor), decrypted_parity])
                                del rolling_xor
                            else:
                                recovered_full = decrypted_parity

                            recovered_bytes = recovered_full[:target_len]
                            del decrypted_parity

                            # Write reconstructed chunk directly into target file at missing position
                            recovered_offset = (failed_part - 1) * CHUNK_SIZE
                            f_out.seek(recovered_offset)
                            f_out.write(recovered_bytes)
                            del recovered_bytes

                            missing_chunks.clear()

                            self._notify_progress(
                                progress_callback,
                                step="raid5_success",
                                current=failed_part,
                                total=total_data_chunks,
                                percent=95.0,
                                account=parity_acc,
                                message=f"✅ In-Memory RAID-5 Recovery Successful! Chunk {failed_part} reconstructed with 0 data loss."
                            )
                        except Exception as par_err:
                            print(f"[RAID-5 RECOVERY ERROR] Failed to recover chunk {failed_part} using parity: {par_err}")
                    else:
                        print(f"[RAID-5 RECOVERY ERROR] Parity block unavailable or corrupted on {parity_acc}. Cannot reconstruct chunk {failed_part}.")

            if missing_chunks:
                failed_accounts = ", ".join(f"Chunk {m[0]} ({m[2]})" for m in missing_chunks)
                if len(missing_chunks) > 1:
                    raise Exception(
                        f"Failed to restore file '{file_name}': Unrecoverable data loss. "
                        f"Multiple data chunks missing ({failed_accounts}). Single-parity RAID-5 protection exceeded."
                    )
                else:
                    raise Exception(
                        f"Failed to restore file '{file_name}': Unrecoverable data loss. "
                        f"{failed_accounts} missing or parity block unavailable/corrupted."
                    )

            # Ensure exact target file size if known
            if total_size_bytes is not None:
                f_out.flush()
                f_out.truncate(total_size_bytes)
            f_out.flush()

        except Exception as e:
            ProcessManager.cancel_operation(dl_op_id)
            f_out.close()
            if os.path.exists(dest_file_path):
                try:
                    os.remove(dest_file_path)
                except Exception:
                    pass
            raise e
        finally:
            if not f_out.closed:
                f_out.close()

        return dest_file_path

    def _download_chunks_to_bytes(self, file_id, progress_callback=None):
        """Compatibility wrapper that downloads to a temporary file and returns a BytesIO object."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".cp_bytes")
        temp_path = temp_file.name
        temp_file.close()
        try:
            self._download_chunks_to_file(file_id, temp_path, progress_callback=progress_callback)
            with open(temp_path, "rb") as f:
                data = f.read()
            return io.BytesIO(data)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def download_file(self, file_id, restore_folder="Restored_Files", progress_callback=None):
        """
        Low-Memory Streaming Download with Cryptographic Integrity Verification (TASK 10):
        Downloads chunks directly to a temporary file on disk, decrypts incrementally,
        and renames atomically to final_path upon verified SHA-256 check.
        Never loads entire files into memory; operates with bounded <= 40MB RAM.
        """
        os.makedirs(restore_folder, exist_ok=True)
        cur = self.db.conn.cursor()
        cur.execute("""
            SELECT file_name, container_id, relative_path, file_hash, hash_algorithm, integrity_status 
            FROM virtual_files WHERE file_id = ?
        """, (file_id,))
        file_row = cur.fetchone()
        if not file_row:
            raise Exception(f"File ID {file_id} not found in database.")

        file_name = file_row["file_name"]
        container_id = file_row["container_id"]
        rel_path = file_row["relative_path"]
        expected_hash = file_row["file_hash"] if "file_hash" in file_row.keys() else None

        # Case A: File is packaged inside a Virtual Archive container
        if container_id and rel_path:
            # Check container hash if recorded
            cur.execute("SELECT file_hash FROM virtual_files WHERE file_id = ?", (container_id,))
            c_row = cur.fetchone()
            expected_container_hash = c_row["file_hash"] if c_row and "file_hash" in c_row.keys() else None

            temp_container = tempfile.NamedTemporaryFile(delete=False, suffix=".cpv")
            temp_container_path = temp_container.name
            temp_container.close()

            final_path = os.path.join(restore_folder, file_name)
            tmp_path = final_path + f".cp_restore_{uuid.uuid4().hex[:8]}"

            try:
                self._download_chunks_to_file(container_id, temp_container_path, progress_callback=progress_callback)
                if expected_container_hash:
                    actual_c_hash = IntegrityEngine.compute_stream_sha256(temp_container_path)
                    if not IntegrityEngine.verify_hash(actual_c_hash, expected_container_hash):
                        raise FileIntegrityError(f"Container archive corrupted: expected SHA-256 {expected_container_hash}, got {actual_c_hash}")

                with tarfile.open(name=temp_container_path, mode="r") as tar:
                    SafeTarExtractor.extract_single_file(tar, rel_path, tmp_path, overwrite=True)

                # Verify extracted file integrity
                if expected_hash:
                    actual_hash = IntegrityEngine.compute_stream_sha256(tmp_path)
                    if not IntegrityEngine.verify_hash(actual_hash, expected_hash):
                        raise FileIntegrityError(
                            f"Integrity verification failed for restored file '{file_name}': "
                            f"expected {expected_hash}, got {actual_hash}. Corrupted file discarded."
                        )
                    os.replace(tmp_path, final_path)
                    self.db.update_virtual_file_integrity(file_id, "verified")
                else:
                    os.replace(tmp_path, final_path)
                    self.db.update_virtual_file_integrity(file_id, "legacy_unverified")
                    print(f"[INTEGRITY WARNING] Restored legacy file '{file_name}' without recorded SHA-256 hash.")

                self._notify_progress(
                    progress_callback,
                    step="complete",
                    current=100,
                    total=100,
                    percent=100.0,
                    account="",
                    message=f"Success! '{file_name}' extracted from virtual archive and verified at: {final_path}"
                )
                return final_path

            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                if os.path.exists(temp_container_path):
                    try:
                        os.remove(temp_container_path)
                    except Exception:
                        pass

        # Case B: Standalone file (Direct disk spooling with zero whole-file memory buffering)
        final_path = os.path.join(restore_folder, file_name)
        tmp_path = final_path + f".cp_restore_{uuid.uuid4().hex[:8]}"

        try:
            self._download_chunks_to_file(file_id, tmp_path, progress_callback=progress_callback)

            # End-to-end verification of restored file via streaming SHA-256 (64KB chunks)
            if expected_hash:
                actual_hash = IntegrityEngine.compute_stream_sha256(tmp_path)
                if not IntegrityEngine.verify_hash(actual_hash, expected_hash):
                    raise FileIntegrityError(
                        f"Integrity verification failed for restored file '{file_name}': "
                        f"expected {expected_hash}, got {actual_hash}. Corrupted file discarded."
                    )
                os.replace(tmp_path, final_path)
                self.db.update_virtual_file_integrity(file_id, "verified")
            else:
                os.replace(tmp_path, final_path)
                self.db.update_virtual_file_integrity(file_id, "legacy_unverified")
                print(f"[INTEGRITY WARNING] Restored legacy file '{file_name}' without recorded SHA-256 hash.")

            self._notify_progress(
                progress_callback,
                step="complete",
                current=100,
                total=100,
                percent=100.0,
                account="",
                message=f"Success! File fully restored and verified at: {final_path}"
            )
            return final_path

        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def download_folder(self, folder_id, restore_folder="Restored_Files", progress_callback=None):
        """
        Fast Virtual Archive Folder Download with End-to-End Cryptographic Verification & Bounded RAM:
        If folder was uploaded as a virtual archive, spools container chunks to a temporary file on disk,
        verifies container integrity, and untars all enclosed files and subdirectories directly into restore_folder.
        Verifies individual extracted files against recorded hashes.
        Cleans up temporary container file reliably.
        """
        os.makedirs(restore_folder, exist_ok=True)
        container = self.db.get_folder_container(folder_id)
        if container:
            container_id = container["file_id"]
            folder = self.db.get_folder(folder_id)
            folder_name = folder["folder_name"] if folder else "Folder"

            # Check container hash if recorded
            cur = self.db.conn.cursor()
            cur.execute("SELECT file_hash FROM virtual_files WHERE file_id = ?", (container_id,))
            c_row = cur.fetchone()
            expected_c_hash = c_row["file_hash"] if c_row and "file_hash" in c_row.keys() else None

            self._notify_progress(
                progress_callback,
                step="download_container",
                current=0,
                total=100,
                percent=10.0,
                account="",
                message=f"⚡ Fast Download: Streaming virtual archive container for '{folder_name}'..."
            )

            temp_container = tempfile.NamedTemporaryFile(delete=False, suffix=".cpv")
            temp_container_path = temp_container.name
            temp_container.close()

            try:
                self._download_chunks_to_file(container_id, temp_container_path, progress_callback=progress_callback)

                if expected_c_hash:
                    actual_c_hash = IntegrityEngine.compute_stream_sha256(temp_container_path)
                    if not IntegrityEngine.verify_hash(actual_c_hash, expected_c_hash):
                        raise FileIntegrityError(f"Container archive corrupted for folder '{folder_name}': expected {expected_c_hash}, got {actual_c_hash}")

                dest_target = os.path.join(restore_folder, folder_name)
                with tarfile.open(name=temp_container_path, mode="r") as tar:
                    SafeTarExtractor.extract_archive(tar, dest_target, overwrite=True)

                # Verify individual extracted files against recorded hashes
                cur.execute("SELECT file_name, relative_path, file_hash FROM virtual_files WHERE container_id = ?", (container_id,))
                contained_files = cur.fetchall()
                for cf in contained_files:
                    if cf["file_hash"]:
                        cf_path = os.path.join(dest_target, cf["relative_path"])
                        if os.path.exists(cf_path):
                            actual_cf_hash = IntegrityEngine.compute_stream_sha256(cf_path)
                            if not IntegrityEngine.verify_hash(actual_cf_hash, cf["file_hash"]):
                                raise FileIntegrityError(f"Integrity check failed for extracted file '{cf['relative_path']}' in folder '{folder_name}'")

                self._notify_progress(
                    progress_callback,
                    step="complete",
                    current=100,
                    total=100,
                    percent=100.0,
                    account="",
                    message=f"Success! Folder '{folder_name}' and all contents restored and verified at: {dest_target}"
                )
                return dest_target

            finally:
                if os.path.exists(temp_container_path):
                    try:
                        os.remove(temp_container_path)
                    except Exception:
                        pass

        # Fallback for folders uploaded without container
        files = self.db.get_descendant_files(folder_id)
        total = len(files)
        for idx, fl in enumerate(files, 1):
            if self.cancel_requested:
                raise Exception("Download cancelled by user.")
            self.download_file(fl["file_id"], restore_folder=restore_folder, progress_callback=progress_callback)
        return restore_folder
        files = self.db.get_descendant_files(folder_id)
        total = len(files)
        for idx, fl in enumerate(files, 1):
            if self.cancel_requested:
                raise Exception("Download cancelled by user.")
            self.download_file(fl["file_id"], restore_folder=restore_folder, progress_callback=progress_callback)
        return restore_folder

    def delete_file(self, file_id, progress_callback=None, job_id=None):
        """
        Transaction-Safe & Reliable Multi-Cloud File Deletion:
        1. Retrieves and validates all chunk metadata for file_id.
        2. Creates or resumes a persistent deletion_job in SQLite.
        3. Executes remote chunk deletion via Rclone, strictly verifying exit code 0.
        4. Atomically decrements account quota and removes chunk record ONLY after confirmed deletion.
        5. Preserves all metadata for failed or unreachable chunks.
        6. Sets status to 'completed', 'partially_deleted', or 'failed' with detailed error tracking.
        7. Safe and idempotent on retry.
        """
        cur = self.db.conn.cursor()

        # 1. Fetch virtual file metadata
        cur.execute("SELECT file_name, is_container, container_id, deletion_status FROM virtual_files WHERE file_id = ?", (file_id,))
        file_row = cur.fetchone()

        if not file_row:
            # Check if this file was already deleted in a prior job (idempotent repeated request)
            jobs = self.db.get_file_deletion_jobs(file_id)
            if jobs and any(j["status"] == "completed" for j in jobs):
                return {
                    "status": "completed",
                    "file_id": file_id,
                    "file_name": jobs[0]["file_name"],
                    "deleted_chunks": 0,
                    "failed_chunks": 0,
                    "message": "File already deleted."
                }
            raise FileNotFoundError(f"File ID '{file_id}' not found in database.")

        file_name = file_row["file_name"]

        # 2. Fetch all remaining chunks for this file
        cur.execute("""
            SELECT chunk_id, account_name, chunk_size_bytes, encrypted_size_bytes, is_parity 
            FROM file_chunks 
            WHERE file_id = ?
            ORDER BY part_number ASC
        """, (file_id,))
        chunks = [dict(c) for c in cur.fetchall()]
        total_remaining = len(chunks)

        # 3. Create or resume persistent deletion job
        if not job_id:
            job_id = self.db.create_deletion_job(file_id, file_name, total_chunks=total_remaining)
        else:
            self.db.update_deletion_job(job_id, status="deleting")
            self.db.set_file_deletion_status(file_id, "deleting")

        # Handle zero-byte files (or files with 0 chunks)
        if total_remaining == 0:
            self.db.finalize_file_deletion(file_id, job_id)
            self._notify_progress(
                progress_callback,
                step="delete_complete",
                current=0,
                total=0,
                percent=100.0,
                account="",
                message=f"Successfully wiped zero-byte file '{file_name}'."
            )
            return {
                "status": "completed",
                "file_id": file_id,
                "file_name": file_name,
                "deleted_chunks": 0,
                "failed_chunks": 0,
                "job_id": job_id
            }

        self._notify_progress(
            progress_callback,
            step="deleting_start",
            current=0,
            total=total_remaining,
            percent=0.0,
            account="",
            message=f"Starting reliable deletion of '{file_name}' ({total_remaining} remote chunks)..."
        )

        successful_chunks = 0
        failed_chunks = []

        for idx, chunk in enumerate(chunks, start=1):
            if self.cancel_requested:
                break

            chunk_id = chunk["chunk_id"]
            account_name = chunk["account_name"]
            chunk_bytes = chunk["chunk_size_bytes"] or CHUNK_SIZE
            chunk_path = f"{account_name}:CloudPool_Vault/{chunk_id}.enc"
            pct = round(((idx - 1) / total_remaining) * 100, 1)

            self._notify_progress(
                progress_callback,
                step="deleting_chunk",
                current=idx,
                total=total_remaining,
                percent=pct,
                account=account_name,
                message=f"Deleting chunk {idx}/{total_remaining} from {account_name}..."
            )

            # Pre-flight check: is account online / configured?
            if not self.db.is_remote_in_rclone_config(account_name):
                err_msg = f"Remote account '{account_name}' is offline or missing in rclone.conf"
                print(f"[DELETE ERROR] {err_msg} for chunk {chunk_id}")
                failed_chunks.append({
                    "chunk_id": chunk_id,
                    "account": account_name,
                    "error": err_msg
                })
                continue

            # Execute Rclone deletefile with timeout and strict returncode verification
            del_op_id = f"del_{job_id}"
            cmd = [RCLONE_BIN, "deletefile", chunk_path]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                ProcessManager.register_process(proc, op_id=del_op_id, description=f"deletefile {chunk_id}")
                try:
                    stdout, stderr = proc.communicate(timeout=30)
                    returncode = proc.returncode
                finally:
                    ProcessManager.unregister_process(proc, op_id=del_op_id, exit_code=proc.returncode if hasattr(proc, "returncode") else None)
            except subprocess.TimeoutExpired:
                ProcessManager.terminate_process(proc)
                returncode = 1
                stderr = "Remote deletion timed out after 30 seconds."
            except Exception as ex:
                returncode = 1
                stderr = str(ex)

            if returncode == 0:
                # CONFIRMED REMOTE WIPE: Atomically update quota and remove chunk from SQLite
                try:
                    enc_bytes = chunk.get("encrypted_size_bytes")
                    self.db.delete_chunk_record_atomic(file_id, chunk_id, account_name, chunk_bytes, encrypted_size_bytes=enc_bytes)
                    successful_chunks += 1
                    self.db.update_deletion_job(job_id, status="deleting", deleted_chunks=successful_chunks)
                except Exception as db_err:
                    print(f"[DELETE DB ERROR] Failed to record chunk deletion in DB: {db_err}")
                    failed_chunks.append({
                        "chunk_id": chunk_id,
                        "account": account_name,
                        "error": f"Database commit error: {db_err}"
                    })
            else:
                err_msg = stderr.strip().split("\n")[-1] if stderr else f"Rclone exited with code {returncode}"
                print(f"[DELETE FAILED] Remote {account_name} rejected delete for {chunk_id}: {err_msg}")
                failed_chunks.append({
                    "chunk_id": chunk_id,
                    "account": account_name,
                    "error": err_msg
                })

        # 4. Resolve Deletion Lifecycle State
        errors_str = "; ".join(f"[{f['account']}] {f['error']}" for f in failed_chunks) if failed_chunks else None

        if not failed_chunks:
            # 100% COMPLETE SUCCESS
            self.db.finalize_file_deletion(file_id, job_id)
            try:
                MetadataEngine.sync_metadata_to_cloud(self.db)
            except Exception:
                pass

            self._notify_progress(
                progress_callback,
                step="delete_complete",
                current=total_remaining,
                total=total_remaining,
                percent=100.0,
                account="",
                message=f"Successfully wiped '{file_name}' and reclaimed space across cloud pool."
            )
            return {
                "status": "completed",
                "file_id": file_id,
                "file_name": file_name,
                "deleted_chunks": successful_chunks,
                "failed_chunks": 0,
                "job_id": job_id
            }

        elif successful_chunks > 0:
            # PARTIALLY DELETED
            self.db.set_file_deletion_status(file_id, "partially_deleted")
            self.db.update_deletion_job(
                job_id,
                status="partially_deleted",
                deleted_chunks=successful_chunks,
                failed_chunks=len(failed_chunks),
                error_message=errors_str
            )
            self._notify_progress(
                progress_callback,
                step="delete_partial",
                current=successful_chunks,
                total=total_remaining,
                percent=round((successful_chunks / total_remaining) * 100, 1),
                account="",
                message=f"Partially deleted '{file_name}': {successful_chunks} deleted, {len(failed_chunks)} failed."
            )
            return {
                "status": "partially_deleted",
                "file_id": file_id,
                "file_name": file_name,
                "deleted_chunks": successful_chunks,
                "failed_chunks": len(failed_chunks),
                "errors": failed_chunks,
                "error_message": errors_str,
                "job_id": job_id
            }

        else:
            # TOTAL FAILURE
            self.db.set_file_deletion_status(file_id, "failed")
            self.db.update_deletion_job(
                job_id,
                status="failed",
                deleted_chunks=0,
                failed_chunks=len(failed_chunks),
                error_message=errors_str
            )
            self._notify_progress(
                progress_callback,
                step="delete_failed",
                current=0,
                total=total_remaining,
                percent=0.0,
                account="",
                message=f"Deletion failed for '{file_name}': {errors_str}"
            )
            return {
                "status": "failed",
                "file_id": file_id,
                "file_name": file_name,
                "deleted_chunks": 0,
                "failed_chunks": len(failed_chunks),
                "errors": failed_chunks,
                "error_message": errors_str,
                "job_id": job_id
            }

    def upload_folder(self, folder_path, target_tier="STABLE", parent_folder_id=None, progress_callback=None, enable_parity=True,
                      batch_completed_bytes=0, batch_total_bytes=None, file_index=0, total_files=None, batch_start_time=None, defer_metadata_sync=False,
                      on_duplicate="rename", strict_parity=True, allow_unprotected_fallback=False):
        """
        Transactional Virtual Archiving for Folders (TASK 07 Reliability & Consistency):
        - Treats folder upload as a single atomic transaction.
        - Scans and validates source files and directory permissions upfront.
        - Detects if any source file changes or is deleted during archive generation.
        - Bundles directories (including empty directories) and files into an uncompressed .tar stream.
        - Uploads the container with chunk tracking and optional RAID-5 parity.
        - Commits virtual_folders and virtual_files in a single atomic SQLite transaction ONLY after upload succeeds.
        - On any failure or cancellation: zero ghost folder or file records remain; uploaded remote chunks are wiped; temporary archives cleaned up.
        """
        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"Folder not found: {folder_path}")
        if not os.path.isdir(folder_path):
            raise NotADirectoryError(f"Not a valid directory: {folder_path}")
        if not os.access(folder_path, os.R_OK):
            raise PermissionError(f"Folder is not readable (permission denied): {folder_path}")

        base_name = os.path.basename(os.path.normpath(folder_path))
        if not base_name:
            base_name = "Folder"

        if parent_folder_id in ("", "root", "ROOT", "None"):
            parent_folder_id = None

        # Duplicate folder name handling under parent_folder_id
        cur = self.db.conn.cursor()
        cur.execute("""
            SELECT folder_id, folder_name FROM virtual_folders 
            WHERE folder_name = ? AND (parent_folder_id = ? OR (parent_folder_id IS NULL AND ? IS NULL))
        """, (base_name, parent_folder_id, parent_folder_id))
        existing_folder = cur.fetchone()

        if existing_folder:
            if on_duplicate == "reject":
                raise FileExistsError(f"A folder named '{base_name}' already exists in this directory.")
            elif on_duplicate == "replace":
                self.delete_virtual_folder(existing_folder["folder_id"])
            else:
                # Default "rename" (e.g. Folder (1), Folder (2))
                idx = 1
                candidate = f"{base_name} ({idx})"
                while True:
                    cur.execute("""
                        SELECT folder_id FROM virtual_folders 
                        WHERE folder_name = ? AND (parent_folder_id = ? OR (parent_folder_id IS NULL AND ? IS NULL))
                    """, (candidate, parent_folder_id, parent_folder_id))
                    if not cur.fetchone():
                        base_name = candidate
                        break
                    idx += 1
                    candidate = f"{base_name} ({idx})"

        # 1. Pre-scan files, directories, empty directories, and capture source snapshot
        dir_list = []
        file_list = []
        snapshot = {}
        total_raw_bytes = 0

        for root, dirs, files in os.walk(folder_path):
            rel_dir = os.path.relpath(root, folder_path).replace("\\", "/")
            if rel_dir != ".":
                dir_list.append(rel_dir)
            for d in dirs:
                sub_dir_full = os.path.join(root, d)
                if not os.access(sub_dir_full, os.R_OK):
                    raise PermissionError(f"Permission denied accessing subdirectory: {sub_dir_full}")

            for fn in files:
                fp = os.path.join(root, fn)
                if not os.path.isfile(fp):
                    continue
                if not os.access(fp, os.R_OK):
                    raise PermissionError(f"Permission denied reading source file: {fp}")
                st = os.stat(fp)
                rel = os.path.relpath(fp, folder_path).replace("\\", "/")
                sz = st.st_size
                total_raw_bytes += sz
                snapshot[rel] = (sz, st.st_mtime)
                f_hash = IntegrityEngine.compute_stream_sha256(fp)
                file_list.append({
                    "path": fp,
                    "name": fn,
                    "rel_path": rel,
                    "size": sz,
                    "mtime": st.st_mtime,
                    "file_hash": f_hash
                })

        file_count = len(file_list)

        # 2. Check disk space if temporary file will be spooled
        is_temp_file = (total_raw_bytes > 500 * 1024 * 1024)
        if is_temp_file:
            temp_dir = tempfile.gettempdir()
            free_bytes = shutil.disk_usage(temp_dir).free
            needed_bytes = total_raw_bytes + (100 * 1024 * 1024)
            if free_bytes < needed_bytes:
                raise DiskSpaceError(
                    f"Insufficient temporary storage for folder archive: requires {needed_bytes:,} bytes, "
                    f"but only {free_bytes:,} bytes free."
                )

        if batch_start_time is None:
            batch_start_time = time.time()
        if batch_total_bytes is None:
            batch_total_bytes = total_raw_bytes
        if total_files is None:
            total_files = max(1, file_count)

        self._notify_progress(
            progress_callback,
            step="bundling",
            current=0,
            total=max(1, file_count),
            percent=round((batch_completed_bytes / max(1, batch_total_bytes)) * 100, 1),
            account="",
            file_name=base_name,
            file_index=file_index,
            total_files=total_files,
            completed_bytes=batch_completed_bytes,
            total_bytes=batch_total_bytes,
            remaining_bytes=max(0, batch_total_bytes - batch_completed_bytes),
            speed_bps=0.0,
            eta_seconds=0,
            message=f"⚡ Virtual Archiving: Bundling {file_count} files into zero-cold-boot RAM stream..."
        )

        folder_op_id = f"fop_{uuid.uuid4().hex}"
        container_id = str(uuid.uuid4())
        created_root_folder_id = self.db.create_folder(base_name, parent_folder_id=parent_folder_id)

        # Register folder operation in persistent journal (State: 'preparing')
        self.db.create_folder_upload_journal_entry(
            folder_op_id=folder_op_id,
            root_folder_name=base_name,
            parent_folder_id=parent_folder_id,
            container_id=container_id,
            total_files=file_count,
            total_bytes=total_raw_bytes
        )

        # Safe archive generation (State: 'archiving')
        self.db.update_folder_upload_journal_status(folder_op_id, "archiving", created_root_folder_id=created_root_folder_id)

        if is_temp_file:
            tar_stream = tempfile.NamedTemporaryFile(delete=False, suffix=".cpv")
            temp_file_path = tar_stream.name
        else:
            tar_stream = io.BytesIO()
            temp_file_path = None

        try:
            with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                # First: archive all directory entries (including empty directories)
                for rel_dir in dir_list:
                    dir_full = os.path.join(folder_path, rel_dir)
                    if os.path.isdir(dir_full):
                        dst = os.stat(dir_full)
                        ti = tarfile.TarInfo(name=rel_dir)
                        ti.type = tarfile.DIRTYPE
                        ti.mtime = int(dst.st_mtime)
                        tar.addfile(ti)

                # Second: archive all files, strictly verifying no source changes during bundling
                for f in file_list:
                    if self.cancel_requested:
                        raise Exception("Folder upload cancelled by user.")
                    fp = f["path"]
                    rel = f["rel_path"]
                    if not os.path.exists(fp):
                        raise RuntimeError(f"Source file was deleted during archiving: {fp}")
                    curr_st = os.stat(fp)
                    orig_sz, orig_mtime = snapshot[rel]
                    if curr_st.st_size != orig_sz or abs(curr_st.st_mtime - orig_mtime) > 1.0:
                        raise RuntimeError(
                            f"Source file was modified during archiving: {rel} "
                            f"(size {orig_sz}->{curr_st.st_size}, mtime {orig_mtime}->{curr_st.st_mtime})"
                        )
                    ti = tarfile.TarInfo(name=rel)
                    ti.type = tarfile.REGTYPE
                    ti.size = curr_st.st_size
                    ti.mtime = int(curr_st.st_mtime)
                    with open(fp, "rb") as in_f:
                        tar.addfile(ti, in_f)

            if is_temp_file:
                tar_stream.flush()
                archive_size = os.path.getsize(temp_file_path)
                container_hash = IntegrityEngine.compute_stream_sha256(temp_file_path)
                tar_stream.seek(0)
            else:
                archive_size = tar_stream.tell()
                container_hash = IntegrityEngine.compute_stream_sha256(tar_stream)
                tar_stream.seek(0)

            # 3. Stream-slice and upload container directly to cloud pool (State: 'uploading')
            self.db.update_folder_upload_journal_status(folder_op_id, "uploading")
            self.upload_stream(
                stream_obj=tar_stream,
                total_size=archive_size,
                file_name=f"{base_name}.cpv",
                file_id=container_id,
                target_tier=target_tier,
                target_folder_id=created_root_folder_id,
                progress_callback=progress_callback,
                enable_parity=enable_parity,
                batch_completed_bytes=batch_completed_bytes,
                batch_total_bytes=batch_total_bytes,
                file_index=file_index,
                total_files=total_files,
                batch_start_time=batch_start_time,
                defer_metadata_sync=True,
                is_container=1,
                strict_parity=strict_parity,
                allow_unprotected_fallback=allow_unprotected_fallback,
                file_hash=container_hash,
                hash_algorithm="SHA-256"
            )

            # 4. Atomic metadata commit (State: 'committing' -> 'committed')
            self.db.update_folder_upload_journal_status(folder_op_id, "committing")
            self.db.commit_folder_upload_atomic(
                folder_op_id=folder_op_id,
                root_folder_id=created_root_folder_id,
                root_folder_name=base_name,
                parent_folder_id=parent_folder_id,
                dir_list=dir_list,
                file_list=file_list,
                container_id=container_id
            )

            # Trigger metadata sync if requested and not deferred
            if not defer_metadata_sync:
                try:
                    self.sync_metadata_to_clouds()
                except Exception:
                    pass

            return created_root_folder_id

        except Exception as e:
            print(f"[FOLDER UPLOAD ERROR] {e}. Initiating rollback...")
            try:
                self.db.rollback_folder_upload(folder_op_id, container_id=container_id)
            except Exception as rb_err:
                print(f"[FOLDER ROLLBACK ERROR] {rb_err}")
            raise e

        finally:
            if is_temp_file and temp_file_path:
                try:
                    tar_stream.close()
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                except Exception:
                    pass
            else:
                tar_stream.close()

    def delete_virtual_folder(self, folder_id, progress_callback=None):
        """
        Recursively deletes all files in the virtual folder subtree from cloud remotes,
        reclaims storage in SQLite, and cleans up virtual folder records.
        Handles both Virtual Archive containers and standalone file trees.
        """
        folder = self.db.get_folder(folder_id)
        folder_name = folder["folder_name"] if folder else folder_id

        container = self.db.get_folder_container(folder_id)
        if container:
            self._notify_progress(
                progress_callback,
                step="delete_folder_start",
                current=0,
                total=1,
                percent=0.0,
                account="",
                message=f"Starting deletion of virtual archive container for '{folder_name}'..."
            )
            # Delete the single container file (wipes cloud chunks & reclaims space)
            res = self.delete_file(container["file_id"], progress_callback=progress_callback)
            if res.get("status") == "completed":
                cur = self.db.conn.cursor()
                descendants = self.db.get_descendant_folders(folder_id)
                all_ids = [folder_id] + [d["folder_id"] for d in descendants]
                placeholders = ",".join("?" for _ in all_ids)
                with self.db.conn:
                    cur.execute(f"DELETE FROM virtual_files WHERE folder_id IN ({placeholders})", tuple(all_ids))
                self.db.delete_virtual_folder_record(folder_id)

                self._notify_progress(
                    progress_callback,
                    step="delete_folder_complete",
                    current=1,
                    total=1,
                    percent=100.0,
                    account="",
                    message=f"Successfully wiped virtual folder '{folder_name}' and all enclosed data."
                )
                return res
            else:
                return res

        # Standalone files deletion
        files = self.db.get_descendant_files(folder_id)
        total_files = len(files)

        self._notify_progress(
            progress_callback,
            step="delete_folder_start",
            current=0,
            total=max(1, total_files),
            percent=0.0,
            account="",
            message=f"Starting recursive wipe of virtual folder '{folder_name}' ({total_files} files)..."
        )

        deleted_count = 0
        failed_count = 0

        for idx, fl in enumerate(files, 1):
            f_name = fl["file_name"]
            pct = round((idx / total_files) * 100, 1) if total_files > 0 else 100.0
            self._notify_progress(
                progress_callback,
                step="delete_folder_file",
                current=idx,
                total=total_files,
                percent=pct,
                account="",
                message=f"Wiping folder file {idx}/{total_files} ('{f_name}') from cloud pool..."
            )
            f_res = self.delete_file(fl["file_id"], progress_callback=None)
            if f_res.get("status") == "completed":
                deleted_count += 1
            else:
                failed_count += 1

        if failed_count == 0:
            self.db.delete_virtual_folder_record(folder_id)
            try:
                MetadataEngine.sync_metadata_to_cloud(self.db)
            except Exception:
                pass

            self._notify_progress(
                progress_callback,
                step="delete_folder_complete",
                current=total_files,
                total=max(1, total_files),
                percent=100.0,
                account="",
                message=f"Successfully wiped virtual folder '{folder_name}' and all enclosed data."
            )
            return {"status": "completed", "deleted_files": deleted_count, "failed_files": 0}
        else:
            return {"status": "partially_deleted", "deleted_files": deleted_count, "failed_files": failed_count}


if __name__ == "__main__":
    net = NetworkEngine()
    print("NetworkEngine with RAID-5 and Space Reclamation initialized successfully.")
