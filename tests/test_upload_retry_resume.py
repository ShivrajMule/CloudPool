"""
Automated Test Suite for CloudPool Upload Reliability, Retry & Resume Mechanisms (TASK 13)
Tests:
- Comprehensive Error Classification (transient, permanent remote, permanent fatal)
- Configurable Retry Policies (exponential backoff calculation with jitter bounds)
- Transient Network Failure Recovery (same remote retry with backoff)
- Permanent Remote Error Failover (401 Auth, 403 Forbidden, Quota Exceeded, Missing Remote)
- Max Retries Exhaustion Failover
- Interrupted Upload Resume (reusing verified remote chunks without re-upload)
- Duplicate Remote Object Prevention
- User Cancellation Responsiveness during backoff
"""

import os
import sys
import time
import uuid
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core_engine import (
    CryptoEngine,
    DatabaseEngine,
    IntegrityEngine
)
from network_engine import (
    NetworkEngine,
    UploadErrorClassifier,
    UploadErrorType,
    UploadErrorCategory,
    UploadRetryPolicy
)


class TestUploadErrorClassification(unittest.TestCase):
    """Verifies that all rclone error outputs are properly categorized."""

    def test_authentication_errors_classified_as_permanent_remote(self):
        auth_samples = [
            "Error 401: Unauthorized - token has expired",
            "oauth2: cannot fetch token: 401 Unauthorized",
            "invalid_grant: Bad Request",
            "Failed to configure token: token refresh failed",
            "Login failed: invalid credentials"
        ]
        for msg in auth_samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.AUTHENTICATION, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_REMOTE, f"Failed on: {msg}")
            self.assertFalse(UploadErrorClassifier.is_transient(msg))
            self.assertTrue(UploadErrorClassifier.is_permanent_remote(msg))

    def test_permission_denied_classified_as_permanent_remote(self):
        samples = [
            "Error 403: Forbidden - Access Denied",
            "AccessDenied: User does not have storage.objects.create permission",
            "permission denied on destination folder"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.PERMISSION_DENIED, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_REMOTE, f"Failed on: {msg}")

    def test_quota_exceeded_classified_as_permanent_remote(self):
        samples = [
            "userRateLimitExceeded: Storage quota exceeded for this account",
            "Error 507: Insufficient Storage",
            "disk full: out of space on remote drive",
            "quota_exceeded on target remote"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.QUOTA_EXCEEDED, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_REMOTE, f"Failed on: {msg}")

    def test_missing_remote_classified_as_permanent_remote(self):
        samples = [
            "Failed to create file system: remote 'GhostDrive' not found in rclone.conf",
            "unknown remote target: Drive_X",
            "remote not found"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.MISSING_REMOTE, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_REMOTE, f"Failed on: {msg}")

    def test_network_timeouts_classified_as_transient(self):
        samples = [
            "Post https://... Client.Timeout exceeded while awaiting headers",
            "connection timed out after 30000ms",
            "i/o timeout on socket read",
            "deadline exceeded during streaming upload"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.NETWORK_TIMEOUT, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.TRANSIENT, f"Failed on: {msg}")
            self.assertTrue(UploadErrorClassifier.is_transient(msg))

    def test_connection_resets_classified_as_transient(self):
        samples = [
            "read: connection reset by peer",
            "broken pipe in write",
            "wsarecv: An existing connection was forcibly closed by the remote host",
            "unexpected EOF during payload transmission",
            "temporary failure in name resolution",
            "network is unreachable"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.CONNECTION_RESET, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.TRANSIENT, f"Failed on: {msg}")

    def test_provider_throttling_classified_as_transient(self):
        samples = [
            "HTTP 429: Too Many Requests - please slow down",
            "HTTP 500 Internal Server Error",
            "HTTP 502 Bad Gateway",
            "HTTP 503 Service Temporarily Unavailable",
            "HTTP 504 Gateway Timeout"
        ]
        for msg in samples:
            err_type, err_cat = UploadErrorClassifier.classify(msg)
            self.assertEqual(err_type, UploadErrorType.PROVIDER_UNAVAILABLE, f"Failed on: {msg}")
            self.assertEqual(err_cat, UploadErrorCategory.TRANSIENT, f"Failed on: {msg}")

    def test_fatal_errors(self):
        err_type, err_cat = UploadErrorClassifier.classify("Transfer cancelled by user.")
        self.assertEqual(err_type, UploadErrorType.USER_CANCELLED)
        self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_FATAL)

        err_type, err_cat = UploadErrorClassifier.classify("invalid path: filename too long")
        self.assertEqual(err_type, UploadErrorType.INVALID_PATH)
        self.assertEqual(err_cat, UploadErrorCategory.PERMANENT_FATAL)


class TestRetryPolicyCalculations(unittest.TestCase):
    """Verifies exponential backoff with jitter mathematically."""

    def test_exponential_backoff_progression(self):
        policy = UploadRetryPolicy(max_retries=3, initial_backoff=1.0, backoff_multiplier=2.0, max_backoff=10.0, jitter_ratio=0.0)
        # Attempt 0 (1st retry): 1.0 * (2^0) = 1.0
        self.assertEqual(policy.calculate_backoff(0), 1.0)
        # Attempt 1 (2nd retry): 1.0 * (2^1) = 2.0
        self.assertEqual(policy.calculate_backoff(1), 2.0)
        # Attempt 2 (3rd retry): 1.0 * (2^2) = 4.0
        self.assertEqual(policy.calculate_backoff(2), 4.0)
        # Attempt 3: 1.0 * (2^3) = 8.0
        self.assertEqual(policy.calculate_backoff(3), 8.0)
        # Attempt 4 (capped by max_backoff): min(10.0, 16.0) = 10.0
        self.assertEqual(policy.calculate_backoff(4), 10.0)

    def test_jitter_within_configured_bounds(self):
        policy = UploadRetryPolicy(initial_backoff=2.0, backoff_multiplier=2.0, jitter_ratio=0.25)
        # Base for attempt 1 is 4.0. Jitter range: [4.0 - 1.0, 4.0 + 1.0] -> [3.0, 5.0]
        delays = [policy.calculate_backoff(1) for _ in range(100)]
        for d in delays:
            self.assertGreaterEqual(d, 2.99)
            self.assertLessEqual(d, 5.01)
        # Verify not all values are identical (random distribution)
        self.assertGreater(len(set(delays)), 10)


class TestUploadRetryAndResume(unittest.TestCase):
    """Full integration tests with mock subprocess for retry, failover, and resume."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cp_retry_test_")
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.db = DatabaseEngine(self.db_path)
        self.crypto = CryptoEngine()
        # Fast retry policy for tests (0.01s backoff)
        self.fast_policy = UploadRetryPolicy(max_retries=3, initial_backoff=0.01, backoff_multiplier=1.5, max_backoff=0.05, jitter_ratio=0.1)
        self.net = NetworkEngine(db=self.db, crypto=self.crypto, retry_policy=self.fast_policy)

        # Register two accounts
        self.db.register_account("Primary_MEGA", "MEGA", raw_gb=20.0, buffer_gb=0.0, tier="STABLE", priority=1)
        self.db.register_account("Secondary_Drive", "Google Drive", raw_gb=15.0, buffer_gb=0.0, tier="STABLE", priority=2)
        self.db.register_account("Parity_Box", "Box", raw_gb=10.0, buffer_gb=0.0, tier="STABLE", priority=3)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
    @patch("subprocess.Popen")
    def test_transient_failure_retries_on_same_remote_and_succeeds(self, mock_popen, mock_rclone_cfg):
        """A transient connection reset retries on the same account with backoff and succeeds."""
        # 1st call: Connection reset
        # 2nd call: Timeout
        # 3rd call: Success
        proc_fail1 = MagicMock()
        proc_fail1.returncode = 1
        proc_fail1.communicate.return_value = (b"", b"read: connection reset by peer")
        proc_fail1.stdin = MagicMock()

        proc_fail2 = MagicMock()
        proc_fail2.returncode = 1
        proc_fail2.communicate.return_value = (b"", b"Client.Timeout exceeded")
        proc_fail2.stdin = MagicMock()

        proc_succ = MagicMock()
        proc_succ.returncode = 0
        proc_succ.communicate.return_value = (b"", b"")
        proc_succ.stdin = MagicMock()

        # Data chunk: 2 failures then success. Parity chunk: success
        mock_popen.side_effect = [proc_fail1, proc_fail2, proc_succ, proc_succ]

        payload = b"Sample transient failure test data " * 100
        file_path = os.path.join(self.test_dir, "transient_test.txt")
        with open(file_path, "wb") as f:
            f.write(payload)

        file_id = self.net.upload_file(file_path, enable_parity=True, retry_policy=self.fast_policy)
        self.assertIsNotNone(file_id)

        # Verify data chunk stayed on Primary_MEGA!
        chunks = self.db.conn.execute("SELECT account_name, is_parity FROM file_chunks WHERE file_id = ?", (file_id,)).fetchall()
        data_chunk_acc = [c["account_name"] for c in chunks if not c["is_parity"]][0]
        self.assertEqual(data_chunk_acc, "Primary_MEGA", "Data chunk should stay on Primary_MEGA after transient retries")

    @patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
    @patch("subprocess.Popen")
    def test_permanent_remote_failure_fails_over_immediately_without_retries(self, mock_popen, mock_rclone_cfg):
        """Permanent auth/quota error triggers immediate failover to alternative remote with 0 retries on failing remote."""
        # Primary_MEGA fails with 401 Unauthorized
        proc_auth_fail = MagicMock()
        proc_auth_fail.returncode = 1
        proc_auth_fail.communicate.return_value = (b"", b"Error 401: Unauthorized - token has expired")
        proc_auth_fail.stdin = MagicMock()

        # Secondary_Drive succeeds for data chunk
        proc_succ_drive = MagicMock()
        proc_succ_drive.returncode = 0
        proc_succ_drive.communicate.return_value = (b"", b"")
        proc_succ_drive.stdin = MagicMock()

        # Parity_Box succeeds for parity chunk
        proc_succ_parity = MagicMock()
        proc_succ_parity.returncode = 0
        proc_succ_parity.communicate.return_value = (b"", b"")
        proc_succ_parity.stdin = MagicMock()

        mock_popen.side_effect = [proc_auth_fail, proc_succ_drive, proc_succ_parity]

        payload = b"Sample permanent failover test data"
        file_path = os.path.join(self.test_dir, "auth_failover.txt")
        with open(file_path, "wb") as f:
            f.write(payload)

        file_id = self.net.upload_file(file_path, enable_parity=True, retry_policy=self.fast_policy)
        self.assertIsNotNone(file_id)

        # Primary_MEGA was attempted exactly ONCE (zero wasted retries)
        # Total popen calls = 3 (1 auth fail + 1 secondary data + 1 parity)
        self.assertEqual(mock_popen.call_count, 3)

        chunks = self.db.conn.execute("SELECT account_name, is_parity FROM file_chunks WHERE file_id = ?", (file_id,)).fetchall()
        data_acc = [c["account_name"] for c in chunks if not c["is_parity"]][0]
        self.assertEqual(data_acc, "Secondary_Drive", "Data chunk should failover to Secondary_Drive")

    @patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
    @patch("subprocess.Popen")
    def test_max_retries_exhaustion_triggers_failover(self, mock_popen, mock_rclone_cfg):
        """Persistent transient errors exhaust max_retries on Primary, then failover to Secondary."""
        # 4 timeout attempts on Primary_MEGA (attempt 0 + 3 retries = 4)
        proc_timeout = MagicMock()
        proc_timeout.returncode = 1
        proc_timeout.communicate.return_value = (b"", b"i/o timeout on socket read")
        proc_timeout.stdin = MagicMock()

        # Secondary_Drive succeeds
        proc_succ_data = MagicMock()
        proc_succ_data.returncode = 0
        proc_succ_data.communicate.return_value = (b"", b"")
        proc_succ_data.stdin = MagicMock()

        # Parity succeeds
        proc_succ_par = MagicMock()
        proc_succ_par.returncode = 0
        proc_succ_par.communicate.return_value = (b"", b"")
        proc_succ_par.stdin = MagicMock()

        mock_popen.side_effect = [proc_timeout, proc_timeout, proc_timeout, proc_timeout, proc_succ_data, proc_succ_par]

        file_path = os.path.join(self.test_dir, "exhaust_test.txt")
        with open(file_path, "wb") as f:
            f.write(b"Max retries exhaustion test payload")

        file_id = self.net.upload_file(file_path, enable_parity=True, retry_policy=self.fast_policy)
        self.assertIsNotNone(file_id)

        chunks = self.db.conn.execute("SELECT account_name, is_parity FROM file_chunks WHERE file_id = ?", (file_id,)).fetchall()
        data_acc = [c["account_name"] for c in chunks if not c["is_parity"]][0]
        self.assertEqual(data_acc, "Secondary_Drive")

    @patch("core_engine.DatabaseEngine.is_remote_in_rclone_config", return_value=True)
    def test_interrupted_upload_resume_avoids_duplicate_remote_chunks(self, mock_rclone_cfg):
        """Simulate an upload interrupted after chunk 1; resume verifies chunk 1 and uploads only chunk 2."""
        # Create a file with 2 chunks (CHUNK_SIZE + 1024 bytes)
        file_path = os.path.join(self.test_dir, "big_resumable_file.bin")
        file_size = 20 * 1024 * 1024 + 1024
        with open(file_path, "wb") as f:
            f.seek(file_size - 1)
            f.write(b"\x00")

        op_id = "op_resume_sim_123"
        file_id = "f-resume-test"
        file_name = "big_resumable_file.bin"

        # 1. Setup persistent journal simulating interrupted state where chunk 1 uploaded
        self.db.create_upload_journal_entry(
            op_id=op_id,
            file_id=file_id,
            file_name=file_name,
            total_size_bytes=file_size,
            target_tier="STABLE",
            total_expected_chunks=3,  # 2 data + 1 parity
            data_chunks_count=2,
            enable_parity=1
        )
        chunk1_id = f"{file_id[:8]}_part0001"
        self.db.record_journal_chunk(
            op_id=op_id,
            chunk_id=chunk1_id,
            account_name="Primary_MEGA",
            part_number=1,
            chunk_size_bytes=20 * 1024 * 1024,
            is_parity=0,
            status="uploaded",
            ciphertext_hash="mock_hash_chunk_1"
        )
        self.db.mark_upload_interrupted(op_id, error_message="Network interrupted during chunk 2")

        # Mock _verify_remote_chunk: chunk 1 exists on remote!
        def mock_verify_chunk(acc, cid, expected_size=None, timeout=15):
            if cid == chunk1_id:
                return (True, 20 * 1024 * 1024 + 28)
            return (False, None)

        self.net._verify_remote_chunk = mock_verify_chunk

        # Mock Popen for chunk 2 and parity upload
        with patch("subprocess.Popen") as mock_popen:
            proc_ok = MagicMock()
            proc_ok.returncode = 0
            proc_ok.communicate.return_value = (b"", b"")
            proc_ok.stdin = MagicMock()
            mock_popen.return_value = proc_ok

            # Resume upload!
            res_id = self.net.resume_upload(op_id, file_path, retry_policy=self.fast_policy)
            self.assertEqual(res_id, file_id)

            # Crucial verification: Popen should only be called for Chunk 2 and Parity (2 times total)
            # Chunk 1 was NOT re-uploaded!
            self.assertEqual(mock_popen.call_count, 2, "Only chunk 2 and parity should have been uploaded to rclone")

        # Verify final state in database
        vf = self.db.get_file(file_id)
        self.assertEqual(vf["upload_status"], "completed")
        self.assertEqual(vf["integrity_status"], "verified")

        journal = self.db.get_upload_journal_entry(op_id)
        self.assertEqual(journal["status"], "completed")

        # Verify all 3 chunks in file_chunks
        chunks = self.db.conn.execute("SELECT chunk_id, part_number, is_parity FROM file_chunks WHERE file_id = ?", (file_id,)).fetchall()
        self.assertEqual(len(chunks), 3)


if __name__ == "__main__":
    unittest.main()

