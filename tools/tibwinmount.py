#!/usr/bin/env python3
"""
tibwinmount - mount an Acronis True Image .tib backup as a Windows drive letter.

Runs on the WINDOWS side (not WSL). Uses WinFsp + winfspy to expose the NTFS
contents of the .tib as a native Windows drive (e.g. H:).

Prerequisites:
  1. Install WinFsp from https://winfsp.dev (one-time MSI install, requires admin)
  2. pip install winfspy

Usage:
  python tibwinmount.py "E:\\STORAGE (R)_full_b1_s1_v1.tib" "E:\\blocks.idx" H:

Notes:
  - Reuses tibreader.py and ntfsread.py from the Linux side (pure-Python, both
    work cross-platform). Place them in the same dir as this script.
  - First mount may take a few minutes while NTFS path index is built.
"""

import os
import sys
import argparse
import time
import threading
from pathlib import Path

try:
    from winfspy import (
        FileSystem,
        BaseFileSystemOperations,
        NTStatusObjectNameNotFound,
        NTStatusEndOfFile,
        NTStatusAccessDenied,
        NTStatusError,
        FILE_ATTRIBUTE,
        CREATE_FILE_CREATE_OPTIONS,
    )
    from winfspy.plumbing.win32_filetime import filetime_now
    from winfspy.plumbing.security_descriptor import SecurityDescriptor
except ImportError as e:
    print(f"ERROR: winfspy import failed: {e}")
    print("Install via:")
    print("  1. Install WinFsp from https://winfsp.dev (admin MSI)")
    print("  2. pip install winfspy")
    sys.exit(1)


# winfspy 0.8.4 doesn't export NTStatusInvalidParameter — define it from the base.
class NTStatusInvalidParameter(NTStatusError):
    NTSTATUS = 0xC000000D


# Default SDDL: owner=BUILTIN\Administrators, group=BUILTIN\Administrators, DACL allows
# full access for SYSTEM, BUILTIN\Administrators, and Everyone (read-only mount, but
# we don't filter at the SD level — just the operations).
DEFAULT_SDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"

# Make sure we can import sibling modules
THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR))
sys.path.insert(0, str(THIS_DIR.parent))  # tibread/ above

from tibreader import TibReader  # noqa: E402
from ntfsread import NtfsVolume  # noqa: E402


def to_winfiletime(unix_ts: float) -> int:
    """Convert unix epoch seconds to Windows FILETIME (100-ns ticks since 1601-01-01)."""
    if unix_ts <= 0:
        return filetime_now()
    return int((unix_ts + 11644473600) * 10_000_000)


class TibFileSystem(BaseFileSystemOperations):
    """winfspy filesystem backed by NtfsVolume."""

    def __init__(self, vol: NtfsVolume, volume_label: str = "TIBMOUNT"):
        super().__init__()
        self.vol = vol
        self._volume_label = volume_label
        self._volume_size = vol.disk.partition_size if hasattr(vol.disk, 'partition_size') else 0
        self._default_sd = SecurityDescriptor.from_string(DEFAULT_SDDL)

    # ----- volume info ------------------------------------------------------

    def get_volume_info(self):
        return {
            "total_size": self._volume_size,
            "free_size": 0,
            "volume_label": self._volume_label,
        }

    def set_volume_label(self, volume_label):
        raise NTStatusAccessDenied()

    # ----- path helpers -----------------------------------------------------

    @staticmethod
    def _to_ntfs_path(file_name: str) -> str:
        """Convert WinFsp path ('\\foo\\bar') to NTFS path ('foo\\bar')."""
        # Strip leading '\'
        s = file_name.lstrip("\\").lstrip("/")
        # Forward to back slashes
        return s.replace("/", "\\")

    def _file_info(self, entry):
        """Build winfspy file_info dict from an NtfsVolume FileEntry."""
        attrs = FILE_ATTRIBUTE.FILE_ATTRIBUTE_READONLY
        if entry.is_dir:
            attrs |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY
        else:
            attrs |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL

        bt = to_winfiletime(getattr(entry, 'btime', 0) or getattr(entry, 'ctime', 0))
        mt = to_winfiletime(getattr(entry, 'mtime', 0))
        at = to_winfiletime(getattr(entry, 'atime', 0))
        ct = to_winfiletime(getattr(entry, 'ctime', 0))

        return {
            "file_attributes": attrs,
            "allocation_size": entry.size,
            "file_size": 0 if entry.is_dir else entry.size,
            "creation_time": bt,
            "last_access_time": at or mt,
            "last_write_time": mt,
            "change_time": ct or mt,
            "index_number": entry.mft_record,
        }

    def _root_info(self):
        return {
            "file_attributes": FILE_ATTRIBUTE.FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
            "allocation_size": 0,
            "file_size": 0,
            "creation_time": filetime_now(),
            "last_access_time": filetime_now(),
            "last_write_time": filetime_now(),
            "change_time": filetime_now(),
            "index_number": 5,
        }

    # ----- security -----------------------------------------------------------

    def get_security_by_name(self, file_name):
        # Read-only, world-readable
        path = self._to_ntfs_path(file_name)
        if path == "":
            info = self._root_info()
        else:
            try:
                entry = self.vol.stat(path)
            except (FileNotFoundError, KeyError):
                raise NTStatusObjectNameNotFound()
            info = self._file_info(entry)
        return info["file_attributes"], self._default_sd.handle, self._default_sd.size

    def get_security(self, file_context):
        # Called when Windows queries the security descriptor of an opened file
        return self._default_sd.handle, self._default_sd.size

    def set_security(self, file_context, security_information, modification_descriptor):
        raise NTStatusAccessDenied()

    # ----- open / close ----------------------------------------------------

    def open(self, file_name, create_options, granted_access):
        path = self._to_ntfs_path(file_name)
        if path == "":
            # root
            return ("", True)  # (path, is_dir)
        try:
            entry = self.vol.stat(path)
        except (FileNotFoundError, KeyError):
            raise NTStatusObjectNameNotFound()
        return (path, entry.is_dir)

    def close(self, file_context):
        pass

    def cleanup(self, file_context, file_name, flags):
        pass

    # ----- info ------------------------------------------------------------

    def get_file_info(self, file_context):
        path, is_dir = file_context
        if path == "":
            return self._root_info()
        try:
            entry = self.vol.stat(path)
        except (FileNotFoundError, KeyError):
            raise NTStatusObjectNameNotFound()
        return self._file_info(entry)

    # ----- directory listing -----------------------------------------------

    def read_directory(self, file_context, marker):
        path, is_dir = file_context
        if not is_dir:
            raise NTStatusInvalidParameter()
        # Build directory listing
        try:
            entries = self.vol.list_dir(path)
        except (FileNotFoundError, KeyError):
            raise NTStatusObjectNameNotFound()

        # Sort case-insensitively (WinFsp expects sorted)
        entries = sorted(entries, key=lambda e: e.name.lower())

        items = []
        if path != "":
            # Add . and .. for non-root
            items.append(("..", None))
        for e in entries:
            items.append((e.name, e))

        # Apply marker (continuation token)
        if marker is not None:
            # Find the entry after `marker`
            for i, (n, _) in enumerate(items):
                if n == marker:
                    items = items[i + 1:]
                    break

        # Build entries
        result = []
        for name, e in items:
            if e is None:
                # parent
                info = self._root_info()
            else:
                info = self._file_info(e)
            result.append({"file_name": name, **info})
        return result

    def get_dir_info_by_name(self, file_context, file_name):
        path = self._to_ntfs_path(file_context[0] + "\\" + file_name if file_context[0] else file_name)
        try:
            entry = self.vol.stat(path)
        except (FileNotFoundError, KeyError):
            raise NTStatusObjectNameNotFound()
        return {"file_name": file_name, **self._file_info(entry)}

    # ----- read ------------------------------------------------------------

    def read(self, file_context, offset, length):
        path, is_dir = file_context
        if is_dir:
            raise NTStatusInvalidParameter()
        try:
            data = self.vol.read_file(path, offset, length)
        except (FileNotFoundError, KeyError):
            raise NTStatusObjectNameNotFound()
        if not data:
            raise NTStatusEndOfFile()
        return data

    # ----- write disabled --------------------------------------------------

    def write(self, *args, **kwargs):
        raise NTStatusAccessDenied()

    def can_delete(self, *args, **kwargs):
        raise NTStatusAccessDenied()

    def rename(self, *args, **kwargs):
        raise NTStatusAccessDenied()

    def set_basic_info(self, *args, **kwargs):
        raise NTStatusAccessDenied()

    def set_file_size(self, *args, **kwargs):
        raise NTStatusAccessDenied()

    def flush(self, *args, **kwargs):
        pass

    def overwrite(self, *args, **kwargs):
        raise NTStatusAccessDenied()


def main():
    p = argparse.ArgumentParser(description="Mount an Acronis .tib backup as a Windows drive letter.")
    p.add_argument("tib", help='Path to .tib file (e.g. "E:\\STORAGE.tib")')
    p.add_argument("index", help='Path to blocks.idx (built by tibindex.py)')
    p.add_argument("mountpoint", help='Drive letter or path (e.g. "H:")')
    p.add_argument("--label", default="TIBMOUNT", help="Volume label")
    p.add_argument("--cache", type=int, default=128, help="LRU cache size (blocks of 512 KB)")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    print(f"[tibwinmount] Loading index {args.index} ...")
    reader = TibReader(args.tib, args.index, cache_blocks=args.cache)
    print(f"[tibwinmount]   block_count = {reader.block_count:,}")
    print(f"[tibwinmount]   partition_size = {reader.partition_size:,} bytes")

    print("[tibwinmount] Locating actual MFT extent 1 (FILE0 magic scan) ...")
    real_mft_lcn = NtfsVolume.find_mft_lcn(reader)
    print(f"[tibwinmount]   extent 1 at LCN {real_mft_lcn:,}")

    # Locate MFT extent 2 — try the cache file first, fall back to scan
    cache_file = args.index + ".extent2"
    extent2_lcn = None
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                extent2_lcn = int(f.read().strip())
            print(f"[tibwinmount]   extent 2 (cached) at LCN {extent2_lcn:,}")
        except Exception:
            extent2_lcn = None
    if extent2_lcn is None:
        print("[tibwinmount] Locating MFT extent 2 (this may take several minutes) ...")
        # Use a generous search radius since the gap is unpredictable
        extent2_lcn = NtfsVolume.find_mft_extent2(reader, search_radius_clusters=reader.block_count * 128)
        if extent2_lcn is not None:
            print(f"[tibwinmount]   extent 2 at LCN {extent2_lcn:,}")
            try:
                with open(cache_file, "w") as f:
                    f.write(str(extent2_lcn))
            except Exception:
                pass
        else:
            print("[tibwinmount]   extent 2 NOT FOUND — only first 19,200 records will be visible")
    overrides = [(1, extent2_lcn)] if extent2_lcn is not None else []

    # Detect partition-direct index (v10): block_idx == partition_block,
    # no shift map needed.
    partition_direct = os.path.exists(args.index + ".partition_direct") or \
                       reader.block_count >= 5_000_000
    if partition_direct:
        print(f"[tibwinmount] Partition-direct index detected ({reader.block_count:,} entries) — skipping shift map")

    # Auto-load piecewise shift map only for legacy reader-block-indexed builds.
    shift_map = None
    if not partition_direct:
        shift_map_path = args.index + ".shift_map.txt"
        if not os.path.exists(shift_map_path):
            # also try sibling path
            sibling = os.path.join(os.path.dirname(args.index), "shift_map.txt")
            if os.path.exists(sibling):
                shift_map_path = sibling
        if os.path.exists(shift_map_path):
            try:
                shift_map = []
                with open(shift_map_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        thresh, sh = line.split()
                        shift_map.append((int(thresh), int(sh)))
                shift_map.sort()
                print(f"[tibwinmount] Loaded piecewise shift map: {len(shift_map):,} segments from {shift_map_path}")
            except Exception as e:
                print(f"[tibwinmount] WARN: failed to load shift map ({e}); using legacy single shift")
                shift_map = None

    print("[tibwinmount] Bootstrapping NTFS volume + walking MFT ...")
    t0 = time.time()
    vol = NtfsVolume(reader, build_index=True, mft_lcn_override=real_mft_lcn,
                     mft_extent_overrides=overrides,
                     lcn_shift_map=shift_map)
    print(f"[tibwinmount]   loaded {vol.total_files:,} MFT records in {time.time()-t0:.1f}s")
    if shift_map:
        print(f"[tibwinmount]   using piecewise shift map ({len(shift_map):,} segments)")
    else:
        print(f"[tibwinmount]   lcn_shift = {vol.lcn_shift} (single-shift legacy)")

    operations = TibFileSystem(vol, volume_label=args.label)

    fs = FileSystem(
        args.mountpoint,
        operations,
        sector_size=4096,
        sectors_per_allocation_unit=1,
        volume_creation_time=filetime_now(),
        volume_serial_number=0x12345678,
        file_info_timeout=1000,
        case_sensitive_search=False,
        case_preserved_names=True,
        unicode_on_disk=True,
        persistent_acls=False,
        post_cleanup_when_modified_only=True,
        um_file_context_is_user_context2=True,
        file_system_name="NTFS",
        prefix="",
        debug=args.debug,
        reject_irp_prior_to_transact0=True,
    )
    print(f"[tibwinmount] Mounting at {args.mountpoint}")
    print(f"[tibwinmount] Press Ctrl+C to unmount.")
    try:
        fs.start()
        # Block forever
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[tibwinmount] Stopping...")
    finally:
        fs.stop()


if __name__ == "__main__":
    main()
