"""
mount/fuse.py — read-only FUSE mount of a .tib's NTFS volume (Linux).

Requires fusepy:  pip install fusepy

Usage (programmatic):
    from tibread.mount.fuse import fuse_mount
    fuse_mount("backup.tib", "/mnt/tib")

CLI:
    tib mount backup.tib /mnt/tib
"""
from __future__ import annotations

import errno
import os
import stat
import sys
import time

try:
    from fuse import FUSE, Operations, FuseOSError
except ImportError:
    FUSE = None
    Operations = object  # so the class definition below still parses

from ..indexer import open_tib


class _NtfsFS(Operations if FUSE else object):
    """Expose an NtfsVolume's NTFS filesystem read-only via FUSE."""

    use_ns = False

    def __init__(self, vol):
        self.vol = vol
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.mount_time = time.time()
        # Reader handle for statfs
        self.reader = vol.disk

    @staticmethod
    def _to_ntfs(path: str) -> str:
        """Convert a FUSE path (forward-slash, leading /) to NTFS form (backslash, no leading)."""
        if path == "/":
            return ""
        return path.lstrip("/").replace("/", "\\")

    def _root_attr(self):
        return {
            "st_mode": stat.S_IFDIR | 0o555,
            "st_nlink": 2,
            "st_size": 0,
            "st_uid": self.uid,
            "st_gid": self.gid,
            "st_atime": self.mount_time,
            "st_mtime": self.mount_time,
            "st_ctime": self.mount_time,
        }

    def _entry_attr(self, entry):
        if entry.is_dir:
            mode = stat.S_IFDIR | 0o555
            nlink = 2
            size = 0
        else:
            mode = stat.S_IFREG | 0o444
            nlink = 1
            size = entry.size
        return {
            "st_mode": mode,
            "st_nlink": nlink,
            "st_size": size,
            "st_uid": self.uid,
            "st_gid": self.gid,
            "st_atime": getattr(entry, "atime", self.mount_time),
            "st_mtime": getattr(entry, "mtime", self.mount_time),
            "st_ctime": getattr(entry, "ctime", self.mount_time),
        }

    def getattr(self, path, fh=None):
        if path == "/":
            return self._root_attr()
        try:
            entry = self.vol.stat(self._to_ntfs(path))
        except (FileNotFoundError, KeyError):
            raise FuseOSError(errno.ENOENT)
        return self._entry_attr(entry)

    def readdir(self, path, fh):
        try:
            entries = self.vol.list_dir(self._to_ntfs(path))
        except (FileNotFoundError, KeyError):
            raise FuseOSError(errno.ENOENT)
        result = [".", ".."]
        for e in entries:
            if e.name and "\x00" not in e.name:
                # FUSE forbids '/' in names — replace defensively
                result.append(e.name.replace("/", "_"))
        return result

    def open(self, path, flags):
        if (flags & 3) != os.O_RDONLY:
            raise FuseOSError(errno.EACCES)
        try:
            self.vol.stat(self._to_ntfs(path))
        except (FileNotFoundError, KeyError, IsADirectoryError):
            raise FuseOSError(errno.ENOENT)
        return 0

    def release(self, path, fh):
        return 0

    def read(self, path, size, offset, fh):
        try:
            return self.vol.read_file(self._to_ntfs(path), offset, size)
        except (FileNotFoundError, KeyError):
            raise FuseOSError(errno.ENOENT)
        except IsADirectoryError:
            raise FuseOSError(errno.EISDIR)

    def statfs(self, path):
        return {
            "f_bsize": 4096,
            "f_blocks": self.reader.partition_size // 4096,
            "f_bfree": 0,
            "f_bavail": 0,
            "f_files": getattr(self.vol, "total_files", 1),
        }


def fuse_mount(tib_path: str, mountpoint: str, *, foreground: bool = False,
               cache_blocks: int = 128) -> int:
    """Mount the `.tib`'s NTFS volume at `mountpoint`. Returns 0 on success.

    Builds (or reuses) the partition-direct index automatically. The index
    is cached next to the `.tib` as `<tib>.idx`.
    """
    if FUSE is None:
        print("ERROR: fusepy is not installed. Run: pip install fusepy", file=sys.stderr)
        return 1
    if not os.path.exists(mountpoint):
        os.makedirs(mountpoint, exist_ok=True)

    print(f"[tibread] opening {tib_path}...")
    vol = open_tib(tib_path, cache_blocks=cache_blocks, progress=True)
    print(f"[tibread] {vol.total_files:,} files indexed; mounting at {mountpoint}")
    fs = _NtfsFS(vol)
    FUSE(fs, mountpoint, foreground=foreground, ro=True, allow_other=False, nothreads=False)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m tibread.mount.fuse <tib> <mountpoint>")
        sys.exit(2)
    sys.exit(fuse_mount(sys.argv[1], sys.argv[2], foreground=True))
