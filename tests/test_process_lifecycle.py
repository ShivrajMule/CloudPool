import os
import re
import sys
import time
import subprocess
import unittest
from unittest.mock import MagicMock, patch

# Ensure CloudPool_Project is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core_engine import ProcessManager, ProcessInfo


class TestProcessLifecycle(unittest.TestCase):
    def setUp(self):
        # Reset ProcessManager state before each test
        with ProcessManager._lock:
            ProcessManager._tracked_processes.clear()
            ProcessManager._op_processes.clear()

    def tearDown(self):
        # Clean up any leftover processes
        ProcessManager.kill_all_processes(timeout=2)

    def test_process_info_creation_and_attributes(self):
        dummy_proc = MagicMock()
        dummy_proc.pid = 12345
        info = ProcessInfo(dummy_proc, op_id="test_op", description="test description")
        self.assertEqual(info.pid, 12345)
        self.assertEqual(info.op_id, "test_op")
        self.assertEqual(info.description, "test description")
        self.assertEqual(info.status, "RUNNING")
        self.assertIsNone(info.exit_code)
        self.assertGreater(info.start_time, 0)

    def test_register_and_unregister_process(self):
        dummy_proc = MagicMock()
        dummy_proc.pid = 99999
        dummy_proc.poll.return_value = 0

        info = ProcessManager.register_process(dummy_proc, op_id="upload_1", description="uploading chunk")
        self.assertIsNotNone(info)
        self.assertIn(99999, ProcessManager._tracked_processes)
        self.assertIn("upload_1", ProcessManager._op_processes)
        self.assertIn(99999, ProcessManager._op_processes["upload_1"])

        # Unregister with exit code 0
        ProcessManager.unregister_process(dummy_proc, op_id="upload_1", exit_code=0)
        self.assertNotIn(99999, ProcessManager._tracked_processes)
        self.assertNotIn("upload_1", ProcessManager._op_processes)
        self.assertEqual(info.status, "COMPLETED")
        self.assertEqual(info.exit_code, 0)

    def test_unregister_process_failed_status(self):
        dummy_proc = MagicMock()
        dummy_proc.pid = 88888
        info = ProcessManager.register_process(dummy_proc, op_id="upload_err")
        ProcessManager.unregister_process(dummy_proc, op_id="upload_err", exit_code=1)
        self.assertEqual(info.status, "FAILED")
        self.assertEqual(info.exit_code, 1)

    def test_operation_scoped_cancellation(self):
        """Verify cancelling op_1 terminates only op_1 processes and leaves op_2 running."""
        # Start two actual long-running lightweight background processes
        cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
        proc1 = subprocess.Popen(cmd)
        proc2 = subprocess.Popen(cmd)

        try:
            ProcessManager.register_process(proc1, op_id="op_1", description="Proc 1")
            ProcessManager.register_process(proc2, op_id="op_2", description="Proc 2")

            # Verify both are tracked
            active = ProcessManager.get_active_processes()
            pids = [p["pid"] for p in active]
            self.assertIn(proc1.pid, pids)
            self.assertIn(proc2.pid, pids)

            # Cancel op_1 only
            cancelled = ProcessManager.cancel_operation("op_1")
            self.assertIn(proc1.pid, cancelled)
            self.assertNotIn(proc2.pid, cancelled)

            # proc1 should be terminated
            proc1.wait(timeout=3)
            self.assertIsNotNone(proc1.poll())

            # proc2 should still be alive
            self.assertIsNone(proc2.poll())
            active_after = ProcessManager.get_active_processes()
            pids_after = [p["pid"] for p in active_after]
            self.assertNotIn(proc1.pid, pids_after)
            self.assertIn(proc2.pid, pids_after)

        finally:
            ProcessManager.terminate_process(proc1)
            ProcessManager.terminate_process(proc2)

    def test_terminate_already_terminated_process(self):
        """Terminating an already-dead process should return safely without raising exceptions."""
        proc = subprocess.Popen([sys.executable, "-c", "exit(0)"])
        proc.wait(timeout=3)
        self.assertIsNotNone(proc.poll())

        ProcessManager.register_process(proc, op_id="dead_op")
        rc = ProcessManager.terminate_process(proc)
        self.assertEqual(rc, 0)
        ProcessManager.unregister_process(proc, op_id="dead_op")

    def test_kill_all_processes_only_affects_tracked_pids(self):
        """Verify kill_all_processes iterates registered PIDs and does not run global taskkill."""
        cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
        tracked_proc = subprocess.Popen(cmd)
        untracked_proc = subprocess.Popen(cmd)

        try:
            ProcessManager.register_process(tracked_proc, op_id="global_batch")

            ProcessManager.kill_all_processes(timeout=3)
            tracked_proc.wait(timeout=3)
            self.assertIsNotNone(tracked_proc.poll())

            # untracked_proc should NOT have been killed because CloudPool no longer uses global taskkill
            self.assertIsNone(untracked_proc.poll())
        finally:
            ProcessManager.terminate_process(tracked_proc)
            ProcessManager.terminate_process(untracked_proc)

    def test_no_global_taskkill_rclone_in_codebase(self):
        """Verify that 'taskkill /IM rclone.exe' is never executed anywhere in the codebase."""
        import ast
        project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        for root, _, files in os.walk(project_dir):
            if "venv" in root or ".git" in root or "__pycache__" in root:
                continue
            for fname in files:
                if fname.endswith(".py") and fname != os.path.basename(__file__):
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        tree = ast.parse(f.read(), filename=fpath)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            # Check arguments for list containing 'taskkill' and '/IM'
                            args_str = ast.dump(node).lower()
                            if "taskkill" in args_str and "/im" in args_str:
                                self.fail(f"Global taskkill execution found in {fpath}: {ast.dump(node)}")


if __name__ == "__main__":
    unittest.main()
