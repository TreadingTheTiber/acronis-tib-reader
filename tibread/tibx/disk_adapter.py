"""
tibread.tibx.disk_adapter — bridge :class:`TibxReader` to :class:`NtfsVolume`.

The existing NTFS parser (:class:`tibread.ntfs.NtfsVolume`) expects a
"disk reader" object that exposes:

* ``read(offset, length) -> bytes`` — return ``length`` bytes starting at
  byte offset ``offset`` on the source disk;
* ``partition_size`` (int, bytes) — total source-disk byte length;
* ``block_count`` (int) — number of 4 KiB blocks (used by some scan
  fast-paths).

:class:`TibxDiskAdapter` provides exactly that surface on top of a
:class:`TibxReader`, so a ``.tibx`` archive can be fed to ``NtfsVolume``
as if it were a flat partition image.

Status
------

Until the ``segment_map`` LSM walker lands (see
:mod:`tibread.tibx.lsm_cells`), only the **bootstrap** region of the
source disk (the first ``BOOTSTRAP_LEN`` = 256 KiB) is readable. Reads
beyond that range raise a clearer wrapping of
:class:`ChunkMapNotImplemented` so callers can detect the
"LSM-walker-not-yet-here" failure mode unambiguously and fall back if
appropriate.

In practice this is enough for ``NtfsVolume`` to:

* parse the boot sector (BPB) — succeeds, BPB lives at LBA 0;
* discover ``$MFT``'s LCN — succeeds (BPB byte at +0x30);

But the very next step (read MFT record 0 at LCN ~786432, byte offset
~3.2 GiB) will hit the not-yet-implemented path and raise.

Example
-------

>>> from tibread.tibx.disk_adapter import TibxDiskAdapter
>>> from tibread.ntfs import NtfsVolume
>>> adapter = TibxDiskAdapter("/mnt/e/Jmicron 0102.tibx")
>>> # Boot-sector parse works:
>>> mbr = adapter.read(0, 512)
>>> assert mbr[510:512] == b"\\x55\\xaa"
>>> # NtfsVolume bootstrap will get past the BPB but fail on MFT read.
"""
from __future__ import annotations

import struct
from typing import Optional

from .disk_image import BOOTSTRAP_LEN, ChunkMapNotImplemented
from .reader import TibxReader


__all__ = ["TibxDiskAdapter", "TibxAdapterError"]


# NTFS default cluster size on modern Windows; also matches the .tibx
# page size, which keeps a few power-of-two arithmetic invariants tidy.
DEFAULT_CLUSTER_SIZE = 4096

# Sector size for translating between byte offsets and the underlying
# read_lba_range API.  All known Acronis source disks use 512-byte
# sectors; if a larger physical sector ever appears we'll need to
# detect it from the BPB and rewire this.
SECTOR_SIZE = 512


class TibxAdapterError(IOError):
    """Raised when the adapter can't satisfy a request for non-LSM reasons.

    Distinct from :class:`ChunkMapNotImplemented` (which signals the
    in-flight LSM walker) so callers can tell apart "would work after
    the LSM cell decoder lands" from "this archive is malformed".
    """


class TibxDiskAdapter:
    """Adapter making a :class:`TibxReader` quack like an NtfsVolume disk.

    Parameters
    ----------
    tibx_path : str
        Path to the ``.tibx`` file.

    Notes
    -----
    The adapter takes ownership of the underlying :class:`TibxReader`
    file handle.  Use it as a context manager (or call :meth:`close`)
    to release the handle.

    The :attr:`partition_size` calculation is best-effort: the
    authoritative source is the ARCH header's TLV[18] ``volume_table``,
    but parsing that requires walking a TLV directory we haven't fully
    decoded.  As a fallback we read the source-disk MBR (which lives in
    the bootstrap region and is therefore always readable) and use the
    end of the largest primary partition.  If both paths fail we expose
    ``partition_size = BOOTSTRAP_LEN`` so callers at least see a
    consistent (if conservative) bound.
    """

    cluster_size: int = DEFAULT_CLUSTER_SIZE

    def __init__(
        self,
        tibx_path: str,
        partition_offset: int = 0,
    ) -> None:
        """Open ``tibx_path`` as a flat-disk view.

        Parameters
        ----------
        tibx_path : str
            Path to the ``.tibx`` archive.
        partition_offset : int, optional
            Byte offset on the source disk where the partition of
            interest starts.  All :meth:`read` calls add this to the
            requested offset, presenting a partition-relative view to
            ``NtfsVolume`` (which expects ``read(0, 512)`` to return the
            NTFS BPB, not the MBR).  Defaults to ``0`` (whole-disk
            view).
        """
        if partition_offset < 0:
            raise ValueError(
                f"partition_offset must be non-negative, got {partition_offset}"
            )
        self.tibx_path = tibx_path
        self.partition_offset = partition_offset
        self._reader = TibxReader(tibx_path)
        self._partition_size: Optional[int] = None

    # -------- resource management -------------------------------------- #

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None  # type: ignore[assignment]

    def __enter__(self) -> "TibxDiskAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # -------- core read API expected by NtfsVolume --------------------- #

    def read(self, offset: int, length: int) -> bytes:
        """Return ``length`` bytes starting at byte ``offset`` on the source disk.

        Routes the request through :meth:`TibxReader.read_lba_range`,
        which currently only services reads inside the bootstrap region
        ``[0, BOOTSTRAP_LEN)``. Reads beyond that re-raise as a clearer
        :class:`ChunkMapNotImplemented` instance so callers can detect
        the "LSM walker not yet implemented" failure cleanly.

        Byte-aligned reads (offset / length not multiples of 512) are
        supported by reading a sector-aligned superset and slicing.
        """
        if length <= 0:
            raise ValueError(f"length must be positive, got {length}")
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        # Translate from partition-relative to source-disk-absolute.
        abs_offset = offset + self.partition_offset

        # Sector-align the underlying read.
        sec_start = abs_offset // SECTOR_SIZE
        sec_byte_start = sec_start * SECTOR_SIZE
        slice_lo = abs_offset - sec_byte_start
        # Round the end up to the next sector boundary.
        end = abs_offset + length
        sec_byte_end = ((end + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
        aligned_len = sec_byte_end - sec_byte_start

        try:
            raw = self._reader.read_lba_range(
                sec_start, aligned_len, sector_size=SECTOR_SIZE
            )
        except ChunkMapNotImplemented as exc:
            # Re-raise with a clearer message that names the in-flight
            # decoder.  Preserve the chain so callers can see the
            # underlying disk_image-layer message if they care.
            raise ChunkMapNotImplemented(
                f"TibxDiskAdapter.read({offset}, {length}): "
                f"reading source bytes >= 256 KB requires the segment_map "
                f"LSM walker, which is not yet implemented. "
                f"See tibread/tibx/lsm_cells.py status."
            ) from exc

        return raw[slice_lo : slice_lo + length]

    # -------- properties expected by NtfsVolume ------------------------ #

    @property
    def partition_size(self) -> int:
        """Total source-disk size in bytes (best-effort)."""
        if self._partition_size is None:
            self._partition_size = self._discover_partition_size()
        return self._partition_size

    @property
    def block_count(self) -> int:
        """Number of :data:`DEFAULT_CLUSTER_SIZE`-byte blocks on the disk."""
        return self.partition_size // DEFAULT_CLUSTER_SIZE

    # -------- size discovery ------------------------------------------- #

    def _discover_partition_size(self) -> int:
        """Best-effort recovery of disk-or-partition byte length.

        When :attr:`partition_offset` is non-zero we are presenting a
        partition view — find the matching MBR entry and report just
        that partition's size.  Otherwise return the whole-disk size.

        Tries, in order:

        1. ARCH-header TLV[18] ``volume_table`` (authoritative when
           parseable) — see ``ARCHIVE3_TLV_DIRECTORY.md``.
        2. MBR partition table at sector 0 (always readable since LBA 0
           is in the bootstrap region).
        3. Fallback to ``BOOTSTRAP_LEN`` so callers see a consistent
           non-zero value even when nothing else worked.
        """
        if self.partition_offset > 0:
            size = self._partition_size_from_mbr()
            if size is not None:
                return size
            return BOOTSTRAP_LEN

        size = self._volume_size_from_tlv18()
        if size is not None:
            return size

        size = self._volume_size_from_mbr()
        if size is not None:
            return size

        return BOOTSTRAP_LEN

    def _partition_size_from_mbr(self) -> Optional[int]:
        """Return the byte-length of the partition starting at :attr:`partition_offset`.

        Looks up the MBR partition entry whose ``first_lba * SECTOR_SIZE``
        matches :attr:`partition_offset` and returns its ``lba_count``
        translated to bytes.  Returns ``None`` if no entry matches (e.g.
        the caller hand-rolled an offset into a GPT partition).
        """
        # Read MBR through the underlying reader (not self.read, which
        # would shift by partition_offset).
        try:
            raw = self._reader.read_lba_range(0, 512, sector_size=SECTOR_SIZE)
        except Exception:
            return None
        if len(raw) < 512 or raw[510:512] != b"\x55\xaa":
            return None
        for i in range(4):
            entry = raw[0x1BE + 16 * i : 0x1BE + 16 * (i + 1)]
            ptype = entry[4]
            if ptype == 0:
                continue
            first_lba = int.from_bytes(entry[8:12], "little")
            lba_count = int.from_bytes(entry[12:16], "little")
            if first_lba * SECTOR_SIZE == self.partition_offset:
                return lba_count * SECTOR_SIZE
        return None

    def list_mbr_partitions(self) -> "list[dict]":
        """Return a list describing the four MBR partition entries.

        Each entry is ``{'type': u8, 'first_lba': int, 'lba_count': int,
        'byte_offset': int, 'byte_size': int}``.  Empty entries (type
        0) are skipped.  Returns an empty list if the MBR signature is
        missing.
        """
        try:
            raw = self._reader.read_lba_range(0, 512, sector_size=SECTOR_SIZE)
        except Exception:
            return []
        if len(raw) < 512 or raw[510:512] != b"\x55\xaa":
            return []
        out: list[dict] = []
        for i in range(4):
            entry = raw[0x1BE + 16 * i : 0x1BE + 16 * (i + 1)]
            ptype = entry[4]
            if ptype == 0:
                continue
            first_lba = int.from_bytes(entry[8:12], "little")
            lba_count = int.from_bytes(entry[12:16], "little")
            out.append(
                {
                    "type": ptype,
                    "first_lba": first_lba,
                    "lba_count": lba_count,
                    "byte_offset": first_lba * SECTOR_SIZE,
                    "byte_size": lba_count * SECTOR_SIZE,
                }
            )
        return out

    def _volume_size_from_tlv18(self) -> Optional[int]:
        """Return total disk size derived from ARCH TLV[18], or ``None``.

        TLV[18] (``volume_table``) is documented as an array of 12-byte
        records ``{u32 vol_index, u64 start_offset}`` (see
        ``ARCHIVE3_TLV_DIRECTORY.md``). The records describe partition
        *start* offsets only; per-partition lengths are not stored
        here. We therefore use TLV[18] only as a lower bound on the
        disk size (``max(start_offset)``) and rely on the MBR fallback
        for the real total.  Returns ``None`` when the header can't be
        parsed or the slot is empty.
        """
        # Defer the import — ``lsm.py`` imports ``segment`` etc. and we
        # don't want to drag those into module-import time when only
        # ``read()`` is needed (e.g. in the unit tests for the
        # bootstrap region).
        try:
            from .lsm import read_archive_header
        except Exception:
            return None
        try:
            arch = read_archive_header(self._reader)
        except Exception:
            return None
        if len(arch.tlv) <= 18:
            return None
        slot = arch.tlv[18]
        if slot.length < 12:
            return None
        max_start = 0
        n_records = slot.length // 12
        for i in range(n_records):
            rec = slot.payload[i * 12 : (i + 1) * 12]
            try:
                _idx, off = struct.unpack(">IQ", rec)
            except struct.error:
                return None
            if off > max_start:
                max_start = off
        if max_start == 0:
            return None
        return max_start

    def _volume_size_from_mbr(self) -> Optional[int]:
        """Derive disk size from the MBR partition table at LBA 0.

        The MBR layout (legacy DOS partition table):
          * Bytes 0x1BE..0x1FD = four 16-byte partition-table entries.
          * Each entry +0x08 = u32 first LBA (LE), +0x0C = u32 LBA count (LE).
          * MBR signature 0x55AA at offset 0x1FE.

        We pick the largest ``first_lba + lba_count`` across the four
        entries and translate to bytes via ``SECTOR_SIZE``. Returns
        ``None`` if the MBR signature is missing or no partition entry
        is non-zero (e.g. GPT-only disk; we don't yet parse GPT).
        """
        try:
            mbr = self.read(0, 512)
        except Exception:
            return None
        if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
            return None
        max_end_lba = 0
        for i in range(4):
            entry = mbr[0x1BE + 16 * i : 0x1BE + 16 * (i + 1)]
            ptype = entry[4]
            if ptype == 0:
                continue
            first_lba = int.from_bytes(entry[8:12], "little")
            lba_count = int.from_bytes(entry[12:16], "little")
            end_lba = first_lba + lba_count
            if end_lba > max_end_lba:
                max_end_lba = end_lba
        if max_end_lba == 0:
            return None
        return max_end_lba * SECTOR_SIZE
