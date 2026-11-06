"""
Helper script to automate Microsoft OneDrive remote creation.
Invokes Rclone to configure OneDrive, opens browser for OAuth,
queries Microsoft for the exact drive quota, and registers the account in CloudPool SQLite.
"""
import sys
import os
import json
import subprocess

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from core_engine import DatabaseEngine

RCLONE_BIN = os.path.join(APP_DIR, "rclone.exe")
if not os.path.exists(RCLONE_BIN):
    RCLONE_BIN = "rclone"

def setup_onedrive(remote_name, capacity_gb=None):
    print(f"\n=======================================================")
    print(f"  Setting up Microsoft OneDrive remote: {remote_name}")
    print(f"=======================================================")
    print("Launching Microsoft OAuth authorization in your browser...")
    print("Your web browser will pop open automatically.\n")
    print(">>> In the browser: Log into your Microsoft account and click 'Yes / Accept'. <<<\n")

    cmd = [RCLONE_BIN, "config", "create", remote_name, "onedrive"]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    for line in iter(proc.stdout.readline, ''):
        print(line, end='', flush=True)
        if "Choose a number from below" in line or "Choose drive to access" in line or "Is that okay?" in line or "y/n" in line:
            try:
                proc.stdin.write("1\n")
                proc.stdin.flush()
            except Exception:
                pass

    proc.stdout.close()
    return_code = proc.wait()

    if return_code != 0:
        print(f"\nFailed to configure {remote_name}. Return code: {return_code}")
        sys.exit(return_code)

    print(f"\n[SUCCESS] {remote_name} authenticated and saved to rclone.conf!")

    # Auto-detect exact quota from Microsoft if not explicitly supplied
    detected_gb = capacity_gb
    if not detected_gb or detected_gb <= 0:
        try:
            res = subprocess.run([RCLONE_BIN, "about", f"{remote_name}:", "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                total_bytes = data.get("total")
                if total_bytes:
                    detected_gb = round(total_bytes / (1024**3), 1)
        except Exception:
            pass

    if not detected_gb or detected_gb <= 0:
        detected_gb = 5.0  # Fallback to standard 5.0 GB

    # Register into CloudPool database
    db = DatabaseEngine()
    db.register_account(remote_name, "OneDrive", raw_gb=float(detected_gb), buffer_gb=0.0, tier="STABLE")
    print(f"[DATABASE] {remote_name} registered in CloudPool ({detected_gb} GB usable, 0 MB buffer).")

    summary = db.get_pool_summary()
    total_gb = summary['total_usable'] / (1024**3)
    print(f"[POOL] Total usable virtual pool is now: {total_gb:.1f} GB across {summary['account_count']} remotes.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python add_onedrive_remote.py <RemoteName> [CapacityGB]")
        sys.exit(1)
    target_remote = sys.argv[1]
    cap = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
    setup_onedrive(target_remote, cap)
