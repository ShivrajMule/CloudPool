"""
Helper script to automate Rclone Google Drive remote creation.
Reads client_id and client_secret from [Gmail_1] in rclone.conf,
then commands Rclone to create the specified remote (e.g. Gmail_2),
automatically launching the browser for Google OAuth approval.
Once approved, registers the remote in SQLite with the 500 MB buffer.
"""
import sys
import os
import subprocess
import configparser

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from core_engine import DatabaseEngine

RCLONE_BIN = os.path.join(APP_DIR, "rclone.exe")
if not os.path.exists(RCLONE_BIN):
    RCLONE_BIN = "rclone"

def setup_remote(remote_name):
    conf_path = os.path.expandvars(r"%APPDATA%\rclone\rclone.conf")
    if not os.path.exists(conf_path):
        print(f"Error: rclone.conf not found at {conf_path}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(conf_path)

    if "Gmail_1" not in config:
        print("Error: [Gmail_1] not found in rclone.conf to borrow Client ID & Secret from.")
        sys.exit(1)

    cid = config.get("Gmail_1", "client_id", fallback="")
    sec = config.get("Gmail_1", "client_secret", fallback="")

    if not cid or not sec:
        print("Error: client_id or client_secret missing in [Gmail_1].")
        sys.exit(1)

    print(f"\n=======================================================")
    print(f"  Setting up remote: {remote_name}")
    print(f"=======================================================")
    print("Launching Rclone OAuth browser authorization...")
    print("Your web browser will pop open automatically.\n")
    print(">>> In the browser: Log into/select the account for this remote and grant access. <<<\n")

    cmd = [
        RCLONE_BIN,
        "config",
        "create",
        remote_name,
        "drive",
        f"client_id={cid}",
        f"client_secret={sec}",
        "scope=drive"
    ]

    # Run rclone config create and stream output in real-time
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    for line in iter(proc.stdout.readline, ''):
        print(line, end='', flush=True)

    proc.stdout.close()
    return_code = proc.wait()

    if return_code != 0:
        print(f"\nFailed to configure {remote_name}. Return code: {return_code}")
        sys.exit(return_code)

    print(f"\n[SUCCESS] {remote_name} authenticated and saved to rclone.conf!")
    
    # Automatically register into SQLite database with 500 MB buffer
    db = DatabaseEngine()
    db.register_account(remote_name, "Google Drive", raw_gb=15.0, buffer_gb=0.5, tier="STABLE")
    print(f"[DATABASE] {remote_name} registered in CloudPool (14.5 GB usable, 500 MB buffer reserved).")
    
    summary = db.get_pool_summary()
    total_gb = summary['total_usable'] / (1024**3)
    print(f"[POOL] Total usable virtual pool is now: {total_gb:.1f} GB across {summary['account_count']} remotes.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python add_gmail_remote.py <RemoteName>")
        sys.exit(1)
    target_remote = sys.argv[1]
    setup_remote(target_remote)

