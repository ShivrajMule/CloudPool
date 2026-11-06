"""
Automated Security and Integrity Test Suite for CloudPool TAR Archive Extraction
Covers TASK 06 Requirements:
- Directory traversal attacks (../, absolute POSIX, Windows drive letters, UNC, ADS colons, null bytes)
- Symlinks / hard links pointing outside the extraction root
- Special file types (devices, FIFOs) rejection
- Archive bomb protection (member count, uncompressed size limit, per-file streaming limit)
- Destination disk space verification and safety margins
- Duplicate filename handling and overwrite policies
- Atomic staging directory isolation and complete cleanup on failure
- Preservation of target integrity (zero files modified outside destination)
"""

import os
import io
import tarfile
import tempfile
import shutil
import unittest
import sys

# Ensure application imports
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TESTS_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core_engine import (
    SafeTarExtractor,
    ArchiveSecurityError,
    PathTraversalError,
    DiskSpaceError,
    ArchiveBombError,
    DuplicateArchiveEntryError
)


def _create_tar_in_memory(members_dict):
    """
    Utility to create an in-memory tarfile from a dictionary:
    members_dict = {
        'filename': {'data': b'...', 'type': tarfile.REGTYPE, 'linkname': ''}
    }
    """
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tar:
        for name, spec in members_dict.items():
            ti = tarfile.TarInfo(name=name)
            entry_type = spec.get('type', tarfile.REGTYPE)
            ti.type = entry_type
            if 'linkname' in spec:
                ti.linkname = spec['linkname']
            
            data = spec.get('data', b'')
            ti.size = len(data)
            ti.mtime = 1700000000
            
            if entry_type == tarfile.DIRTYPE:
                tar.addfile(ti)
            elif entry_type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                tar.addfile(ti, io.BytesIO(data))
            else:
                tar.addfile(ti)
    bio.seek(0)
    return bio


class TestArchiveExtractionSecurity(unittest.TestCase):
    """Rigorous security testing for CloudPool SafeTarExtractor."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cpv_test_archive_")
        self.dest_dir = os.path.join(self.temp_dir, "extracted")
        self.canary_file = os.path.join(self.temp_dir, "canary.txt")
        with open(self.canary_file, "w") as f:
            f.write("CANARY_SAFE")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _assert_canary_intact(self):
        """Verifies that no outside file in temp_dir was overwritten or modified."""
        self.assertTrue(os.path.exists(self.canary_file), "Canary file was deleted by extraction attack!")
        with open(self.canary_file, "r") as f:
            self.assertEqual(f.read(), "CANARY_SAFE", "Canary file was modified by extraction attack!")

    # 1. Directory Traversal Attacks
    def test_parent_traversal_relative(self):
        """Rejects ../ relative traversal attempts."""
        tar_bytes = _create_tar_in_memory({
            "../canary.txt": {"data": b"EVIL_OVERWRITE"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_deep_parent_traversal(self):
        """Rejects nested directory ../ traversal."""
        tar_bytes = _create_tar_in_memory({
            "nested/dir/../../../../canary.txt": {"data": b"EVIL_OVERWRITE"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_posix_absolute_path(self):
        """Rejects absolute POSIX paths."""
        tar_bytes = _create_tar_in_memory({
            "/etc/passwd": {"data": b"root:x:0:0::/root:/bin/bash"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_windows_drive_letter_absolute(self):
        """Rejects Windows drive letters e.g. C:\boot.ini."""
        tar_bytes = _create_tar_in_memory({
            "C:/Windows/System32/evil.dll": {"data": b"MALICIOUS_PAYLOAD"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_windows_drive_relative(self):
        """Rejects Windows drive-relative paths like C:evil.txt."""
        tar_bytes = _create_tar_in_memory({
            "C:evil.txt": {"data": b"MALICIOUS_PAYLOAD"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_unc_network_path(self):
        """Rejects Windows UNC network paths."""
        tar_bytes = _create_tar_in_memory({
            "//192.168.1.1/share/exploit.bat": {"data": b"echo hacked"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_alternate_data_stream_colon(self):
        """Rejects NTFS Alternate Data Streams containing colons."""
        tar_bytes = _create_tar_in_memory({
            "normal.txt:hidden_stream.exe": {"data": b"HIDDEN"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_windows_reserved_device_names(self):
        """Rejects Windows reserved device names (CON, AUX, NUL, COM1, LPT1)."""
        for dev in ["CON", "aux.txt", "nul", "COM1.log", "lpt2"]:
            tar_bytes = _create_tar_in_memory({
                dev: {"data": b"CRASH_WINDOWS"}
            })
            with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
                with self.assertRaises(PathTraversalError, msg=f"Should reject reserved name {dev}"):
                    SafeTarExtractor.extract_archive(tar, self.dest_dir)
            self._assert_canary_intact()

    def test_trailing_dot_and_space(self):
        """Rejects trailing dots and spaces in path components."""
        for name in ["evil_folder./file.txt", "folder /file.txt", "trailing_dot."]:
            tar_bytes = _create_tar_in_memory({
                name: {"data": b"DATA"}
            })
            with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
                with self.assertRaises(PathTraversalError, msg=f"Should reject trailing dot/space {name}"):
                    SafeTarExtractor.extract_archive(tar, self.dest_dir)

    def test_null_byte_injection(self):
        """Rejects null bytes in paths."""
        # 1. Direct path check
        with self.assertRaises(PathTraversalError):
            SafeTarExtractor.validate_path("safe.txt\x00evil.exe")

        # 2. Tar member with null byte injection
        tar_bytes = _create_tar_in_memory({"dummy": {"data": b"DATA"}})
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            tar.getmembers()[0].name = "safe.txt\x00evil.exe"
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)

    # 2. Symlink and Hardlink Security
    def test_symlink_pointing_outside_root(self):
        """Rejects symlinks pointing to paths outside extraction root."""
        tar_bytes = _create_tar_in_memory({
            "evil_symlink": {"type": tarfile.SYMTYPE, "linkname": "../../canary.txt"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_symlink_to_system_directory(self):
        """Rejects symlinks pointing to /etc or C:\Windows."""
        tar_bytes = _create_tar_in_memory({
            "link_etc": {"type": tarfile.SYMTYPE, "linkname": "/etc/passwd"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    def test_hardlink_pointing_outside_root(self):
        """Rejects hardlinks pointing outside the extraction root."""
        tar_bytes = _create_tar_in_memory({
            "evil_hardlink": {"type": tarfile.LNKTYPE, "linkname": "../../canary.txt"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)
        self._assert_canary_intact()

    # 3. Special Device Entries
    def test_special_device_files_rejected(self):
        """Rejects character devices, block devices, and FIFOs."""
        for dev_type, type_name in [(tarfile.CHRTYPE, "char_dev"), (tarfile.BLKTYPE, "block_dev"), (tarfile.FIFOTYPE, "fifo")]:
            tar_bytes = _create_tar_in_memory({
                type_name: {"type": dev_type, "data": b""}
            })
            with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
                with self.assertRaises(ArchiveSecurityError, msg=f"Should reject {type_name}"):
                    SafeTarExtractor.extract_archive(tar, self.dest_dir)

    # 4. Valid Directory Structures
    def test_valid_nested_directory_structure(self):
        """Extracts valid nested directories and files cleanly."""
        tar_bytes = _create_tar_in_memory({
            "docs": {"type": tarfile.DIRTYPE},
            "docs/readme.txt": {"data": b"CloudPool Virtual Archive Readme"},
            "docs/sub/report.csv": {"data": b"id,name,value\n1,alpha,100\n2,beta,200\n"},
            "images/logo.png": {"data": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            out_dir = SafeTarExtractor.extract_archive(tar, self.dest_dir)

        self.assertEqual(out_dir, self.dest_dir)
        self.assertTrue(os.path.isdir(os.path.join(self.dest_dir, "docs", "sub")))
        self.assertTrue(os.path.isfile(os.path.join(self.dest_dir, "docs", "readme.txt")))
        with open(os.path.join(self.dest_dir, "docs", "readme.txt"), "rb") as f:
            self.assertEqual(f.read(), b"CloudPool Virtual Archive Readme")
        with open(os.path.join(self.dest_dir, "docs", "sub", "report.csv"), "rb") as f:
            self.assertIn(b"alpha,100", f.read())
        with open(os.path.join(self.dest_dir, "images", "logo.png"), "rb") as f:
            self.assertTrue(f.read().startswith(b"\x89PNG"))

    # 5. Very Long Filenames
    def test_excessively_long_filename_component(self):
        """Rejects components exceeding 255 characters."""
        long_component = "a" * 256 + ".txt"
        tar_bytes = _create_tar_in_memory({
            f"sub/{long_component}": {"data": b"LONG"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)

    # 6. Duplicate Filenames & Overwrite Policy
    def test_duplicate_filenames_overwrite_false(self):
        """Rejects duplicate member names when overwrite=False."""
        # Manually assemble duplicate entries in tar stream
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as tar:
            ti1 = tarfile.TarInfo(name="file.txt")
            ti1.size = 5
            tar.addfile(ti1, io.BytesIO(b"FIRST"))
            ti2 = tarfile.TarInfo(name="file.txt")
            ti2.size = 6
            tar.addfile(ti2, io.BytesIO(b"SECOND"))
        bio.seek(0)

        with tarfile.open(fileobj=bio, mode="r") as tar:
            with self.assertRaises(DuplicateArchiveEntryError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, overwrite=False)

    def test_duplicate_filenames_overwrite_true(self):
        """Allows duplicate entries when overwrite=True, retaining the final version."""
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as tar:
            ti1 = tarfile.TarInfo(name="file.txt")
            ti1.size = 5
            tar.addfile(ti1, io.BytesIO(b"FIRST"))
            ti2 = tarfile.TarInfo(name="file.txt")
            ti2.size = 6
            tar.addfile(ti2, io.BytesIO(b"SECOND"))
        bio.seek(0)

        with tarfile.open(fileobj=bio, mode="r") as tar:
            SafeTarExtractor.extract_archive(tar, self.dest_dir, overwrite=True)

        out_file = os.path.join(self.dest_dir, "file.txt")
        self.assertTrue(os.path.exists(out_file))
        with open(out_file, "rb") as f:
            self.assertEqual(f.read(), b"SECOND")

    # 7. Existing Destination Files
    def test_existing_destination_file_overwrite_false(self):
        """Raises DuplicateArchiveEntryError if target file already exists and overwrite=False."""
        os.makedirs(self.dest_dir, exist_ok=True)
        existing_file = os.path.join(self.dest_dir, "preexisting.txt")
        with open(existing_file, "w") as f:
            f.write("DO_NOT_TOUCH")

        tar_bytes = _create_tar_in_memory({
            "preexisting.txt": {"data": b"OVERWRITE_ATTEMPT"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(DuplicateArchiveEntryError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, overwrite=False)

        with open(existing_file, "r") as f:
            self.assertEqual(f.read(), "DO_NOT_TOUCH")

    # 8. Archive Bomb Protection
    def test_archive_bomb_file_count_limit(self):
        """Rejects archives exceeding maximum member count."""
        members = {f"file_{i}.txt": {"data": b"x"} for i in range(15)}
        tar_bytes = _create_tar_in_memory(members)
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(ArchiveBombError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, max_file_count=10)

    def test_archive_bomb_total_size_limit(self):
        """Rejects archives exceeding maximum uncompressed size."""
        tar_bytes = _create_tar_in_memory({
            "bigfile1.dat": {"data": b"A" * 500},
            "bigfile2.dat": {"data": b"B" * 600}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(ArchiveBombError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, max_total_size=1000)

    def test_archive_bomb_streaming_file_size_exceeded(self):
        """Rejects files whose stream exceeds declared size or single-file limit."""
        tar_bytes = _create_tar_in_memory({
            "payload.dat": {"data": b"Z" * 2000}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(ArchiveBombError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, max_file_size=1000)

    # 9. Disk Space Verification
    def test_disk_space_insufficient_rejected(self):
        """Raises DiskSpaceError if required space exceeds available disk space."""
        tar_bytes = _create_tar_in_memory({
            "small.txt": {"data": b"data"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            # Request an impossibly huge safety margin to simulate full disk
            huge_margin = 100 * 1024 * 1024 * 1024 * 1024  # 100 TB
            with self.assertRaises(DiskSpaceError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir, disk_margin=huge_margin)

    # 10. Atomic Cleanup on Failure
    def test_atomic_staging_cleanup_on_failure(self):
        """Ensures staging directory is cleaned up when extraction fails halfway."""
        # Archive with one valid file followed by one traversal exploit
        tar_bytes = _create_tar_in_memory({
            "valid.txt": {"data": b"VALID_DATA"},
            "../exploit.txt": {"data": b"ATTACK"}
        })
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_archive(tar, self.dest_dir)

        # Dest dir should NOT contain valid.txt because pre-validation blocked it before extraction
        self.assertFalse(os.path.exists(os.path.join(self.dest_dir, "valid.txt")))

    # 11. Single File Extraction
    def test_extract_single_file_safe(self):
        """Extracts an individual safe member to a designated target file."""
        tar_bytes = _create_tar_in_memory({
            "folder/sub/target.txt": {"data": b"EXTRACTED_SINGLE_FILE_CONTENT"},
            "folder/other.txt": {"data": b"OTHER_CONTENT"}
        })
        out_file = os.path.join(self.temp_dir, "single_output.txt")
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            res_path = SafeTarExtractor.extract_single_file(
                tar,
                "folder/sub/target.txt",
                out_file,
                overwrite=True
            )
        self.assertEqual(res_path, out_file)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "rb") as f:
            self.assertEqual(f.read(), b"EXTRACTED_SINGLE_FILE_CONTENT")

    def test_extract_single_file_traversal_rejected(self):
        """Rejects single file extraction when member path attempts traversal."""
        tar_bytes = _create_tar_in_memory({
            "../canary.txt": {"data": b"OVERWRITE"}
        })
        out_file = os.path.join(self.temp_dir, "output.txt")
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(PathTraversalError):
                SafeTarExtractor.extract_single_file(tar, "../canary.txt", out_file)
        self._assert_canary_intact()

    def test_extract_single_file_not_found(self):
        """Raises FileNotFoundError when requested member is missing."""
        tar_bytes = _create_tar_in_memory({
            "file.txt": {"data": b"content"}
        })
        out_file = os.path.join(self.temp_dir, "output.txt")
        with tarfile.open(fileobj=tar_bytes, mode="r") as tar:
            with self.assertRaises(FileNotFoundError):
                SafeTarExtractor.extract_single_file(tar, "missing.txt", out_file)


if __name__ == "__main__":
    unittest.main()
