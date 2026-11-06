# CloudPool

CloudPool is a desktop multi-cloud storage aggregator with encrypted chunking,
RAID-5 parity, metadata mirroring, and a Tkinter interface.

## Security

Runtime databases, vault contents, encryption keys, credentials, local binaries,
and secret notes are intentionally excluded from version control. Keep those
files local and never commit them to a public repository.

## Run locally

Install the Python dependencies used by the project, configure the required
rclone remotes, and run:

```powershell
python CloudPoolApp.py
```

## GitHub sync

The repository is configured to push automatically after each local commit.
Create a commit after making changes and the `post-commit` hook will sync it to
the `main` branch on GitHub.
