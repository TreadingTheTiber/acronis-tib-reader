"""
mount/fuse.py — read-only FUSE mount of a `.tib` or `.tibx` NTFS volume (Linux).

Requires fusepy:  pip install fusepy

Usage (programmatic):
    from tibread.mount.fuse import fuse_mount
    fuse_mount("backup.tib", "/mnt/tib")
    fuse_mount("backup.tibx", "/mnt/tibx", partition=0)

CLI:
    tib mount backup.tib  /mnt/tib
    tib mount backup.tibx /mnt/tibx --partition 0
"""
from __future__ import annotations

import errno
import os
import stat
import sys
import time

try:
    from fuse import FUSE, Operations, FuseOSError
except (ImportError, OSError):
    # ImportError: fusepy package missing.
    # OSError: fusepy is installed but libfuse2 isn't on the system.
    # In either case, defer the failure until fuse_mount() is called so
    # the rest of this module remains importable (e.g. for unit tests
    # that exercise routing logic without actually mounting).
    FUSE = None
    Operations = object  # so the class definition below still parses
    FuseOSError = OSError  # placeholder

from ..indexer import open_tib


# Header bytes used to detect a `.tibx` ("QARCH") page-store regardless
# of the file extension. Page 0 begins with the 4-byte page-CRC envelope
# followed by the type byte (0x01 = ARCH) and the magic ASCII "QARCH".
# We sniff for "QARCH" anywhere in the first 16 bytes so we don't have
# to commit to a precise envelope layout here.
_TIBX_MAGIC = b"QARCH"


def is_tibx_file(path: str) -> bool:
    """Return True if *path* looks like a ``.tibx`` archive.

    Detection is by file extension *or* by the ``QARCH`` magic in the
    first 16 bytes of page 0.  Either is sufficient — both make false
    positives extremely unlikely.
    """
    if path.lower().endswith(".tibx"):
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    return _TIBX_MAGIC in head


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


def _open_tibx_volume(tibx_path: str, partition: int):
    """Open a ``.tibx`` archive, choose a partition, and return ``(vol, adapter)``.

    The adapter is returned so the caller can keep it alive (and close
    it) for the lifetime of the FUSE mount.

    ``partition`` is an MBR partition index (0-based).  If the index is
    out of range a ``ValueError`` is raised with the available choices.
    """
    from ..tibx import TibxDiskAdapter
    from ..ntfs import NtfsVolume

    print(f"[tibread] opening {tibx_path} as .tibx archive...")
    # First open a temporary whole-disk adapter just to enumerate the
    # MBR.  This is cheap (256 KiB bootstrap read) and avoids holding
    # two live readers when we know which partition we want.
    with TibxDiskAdapter(tibx_path) as probe:
        partitions = probe.list_mbr_partitions()
    if not partitions:
        raise ValueError(
            f"{tibx_path}: no MBR partitions found in the source disk; "
            f"cannot mount."
        )
    if partition < 0 or partition >= len(partitions):
        choices = ", ".join(
            f"#{i}: type=0x{p['type']:02x} "
            f"size={p['byte_size'] / 1024**3:.1f} GiB"
            for i, p in enumerate(partitions)
        )
        raise ValueError(
            f"--partition {partition} out of range; the archive has "
            f"{len(partitions)} partition(s): {choices}"
        )
    p = partitions[partition]
    print(
        f"[tibread] selected partition #{partition}: "
        f"type=0x{p['type']:02x}  byte_offset={p['byte_offset']:,}  "
        f"size={p['byte_size'] / 1024**3:.2f} GiB"
    )
    print("[tibread] building data_map / segment_map indexes "
          "(can take ~30s on multi-GiB archives)...")
    adapter = TibxDiskAdapter(tibx_path, partition_offset=p["byte_offset"])
    try:
        vol = NtfsVolume(adapter, build_index=True)
    except Exception:
        adapter.close()
        raise
    return vol, adapter


def fuse_mount(tib_path: str, mountpoint: str, *, foreground: bool = False,
               cache_blocks: int = 128, partition: int = 1) -> int:
    """Mount the backup's NTFS volume at *mountpoint*. Returns 0 on success.

    Routes to the appropriate adapter based on the input file:

    * ``.tib`` (sector-mode): handled by :func:`tibread.indexer.open_tib`,
      which builds (or reuses) the partition-direct ``.idx`` sidecar.
      The ``partition`` argument is ignored — sector-mode `.tib` carries
      a single partition.

    * ``.tibx`` (QARCH archive3): handled by
      :class:`tibread.tibx.TibxDiskAdapter` + :class:`NtfsVolume`.  The
      ``partition`` argument selects which MBR partition to mount
      (default: 1, the larger main partition on a typical system disk).

    Detection is by file extension or by the ``QARCH`` magic at the
    head of page 0 (see :func:`is_tibx_file`).
    """
    if FUSE is None:
        print("ERROR: fusepy is not installed. Run: pip install fusepy", file=sys.stderr)
        return 1
    if not os.path.exists(mountpoint):
        os.makedirs(mountpoint, exist_ok=True)

    adapter = None
    if is_tibx_file(tib_path):
        vol, adapter = _open_tibx_volume(tib_path, partition)
        total = getattr(vol, "total_files", None)
        if total:
            print(f"[tibread] {total:,} files indexed; mounting at {mountpoint}")
        else:
            print(f"[tibread] mounting at {mountpoint}")
    else:
        print(f"[tibread] opening {tib_path} as sector-mode .tib...")
        vol = open_tib(tib_path, cache_blocks=cache_blocks, progress=True)
        print(f"[tibread] {vol.total_files:,} files indexed; mounting at {mountpoint}")

    try:
        fs = _NtfsFS(vol)
        FUSE(fs, mountpoint, foreground=foreground, ro=True,
             allow_other=False, nothreads=False)
    finally:
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m tibread.mount.fuse <tib|tibx> <mountpoint> [partition]")
        sys.exit(2)
    part = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    sys.exit(fuse_mount(sys.argv[1], sys.argv[2], foreground=True, partition=part))
