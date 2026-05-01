"""
tibread.tibx.disk_adapter - bridge :class:`TibxReader` to :class:`NtfsVolume`.

The existing NTFS parser (:class:`tibread.ntfs.NtfsVolume`) expects a
"disk reader" object that exposes:

* ``read(offset, length) -> bytes`` - return ``length`` bytes starting at
  byte offset ``offset`` on the source disk;
* ``partition_size`` (int, bytes) - total source-disk byte length;
* ``block_count`` (int) - number of 4 KiB blocks (used by some scan
  fast-paths).

:class:`TibxDiskAdapter` provides exactly that surface on top of a
:class:`TibxReader`, so a ``.tibx`` archive can be fed to ``NtfsVolume``
as if it were a flat partition image.

How a read is satisfied
-----------------------

There are three regions an offset can fall in:

1. **The whole-disk MBR / bootstrap region** ``[0, BOOTSTRAP_LEN)``.  The
   first SG segment in the archive (seg_id 4 in v8 archives) carries the
   uncompressed first 256 KiB of source-disk content; reads in this
   range are served directly from that segment.  Whole-disk views
   (``partition_offset == 0``) start here.

2. **Partition content**, when ``partition_offset > 0``.  The partition
   that starts at ``partition_offset`` corresponds to one of the
   ``data_map`` streams (``volume_id``), and reads are translated to the
   covering extent via :func:`tibread.tibx.data_map.lookup_le`.  The
   extent points at a segment id; that id is resolved through
   :mod:`tibread.tibx.segment_map` to a file byte offset, the segment
   is decompressed, and the requested slice is returned.  Decompressed
   segments are cached (LRU) so consecutive reads inside the same
   segment don't re-decompress.

3. **Sparse holes** between data_map extents are returned as zeros,
   matching the source-disk semantics for unallocated NTFS clusters.

Volume discovery
----------------

The ``data_map`` keys identify their stream by an opaque ``volume_id``
field (in :file:`example.tibx` the small metadata streams are 2..9,
the system-reserved partition is 6, and the main partition is 10).  We
discover which volume_id corresponds to a given ``partition_offset`` by:

1. Listing every ``volume_id`` that has at least one extent at source
   offset 0 (i.e. starts the partition);
2. Reading that extent's segment, peeking at the BPB ``total_sectors``;
3. Matching it to the MBR partition entry whose ``lba_count`` equals
   that ``total_sectors``.

This works for NTFS / exFAT / FAT32 partitions whose BPB carries a
sector count.  For partition layouts we can't auto-discover, the caller
can pass ``volume_id`` explicitly to the constructor.

Example
-------

>>> from tibread.tibx import TibxDiskAdapter
>>> from tibread.ntfs import NtfsVolume
>>> with TibxDiskAdapter("/path/to/example.tibx") as a:
...     parts = a.list_mbr_partitions()
>>> # Partition 0 = System Reserved, starts 1 MiB into the disk:
>>> with TibxDiskAdapter("/path/to/example.tibx",
...                      partition_offset=parts[0]["byte_offset"]) as pa:
...     bpb = pa.read(0, 512)
...     vol = NtfsVolume(pa, build_index=False)
...     mft0 = vol.read_mft_record(0)
"""
from __future__ import annotations

import bisect
import struct
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

from .data_map import DataMapEntry, load_extents
from .disk_image import BOOTSTRAP_LEN, ChunkMapNotImplemented
from .reader import TibxReader
from .segment import parse_sg_header
from .segment_map import SegLocator, load_seg_index


__all__ = ["TibxDiskAdapter", "TibxAdapterError"]


# NTFS default cluster size on modern Windows; also matches the .tibx
# page size, which keeps a few power-of-two arithmetic invariants tidy.
DEFAULT_CLUSTER_SIZE = 4096

# Sector size for translating between byte offsets and the underlying
# read_lba_range API.  All known Acronis source disks use 512-byte
# sectors; if a larger physical sector ever appears we'll need to
# detect it from the BPB and rewire this.
SECTOR_SIZE = 512

# Maximum number of decompressed segments to keep in the per-adapter
# LRU cache.  ~32 segments at a typical 200 KiB plaintext is ~6 MiB.
DEFAULT_SEGMENT_CACHE_SIZE = 32


class TibxAdapterError(IOError):
    """Raised when the adapter can't satisfy a request for non-LSM reasons.

    Distinct from :class:`ChunkMapNotImplemented` (which signals an
    unsupported region) so callers can tell the two apart.
    """


class TibxDiskAdapter:
    """Adapter making a :class:`TibxReader` quack like an NtfsVolume disk.

    Parameters
    ----------
    tibx_path : str
        Path to the ``.tibx`` file.
    partition_offset : int, optional
        Byte offset on the source disk where the partition of interest
        starts.  All :meth:`read` calls add this to the requested offset,
        presenting a partition-relative view to ``NtfsVolume`` (which
        expects ``read(0, 512)`` to return the NTFS BPB, not the MBR).
        Defaults to ``0`` (whole-disk view).
    volume_id : int, optional
        The data_map stream id for this partition's content.  When
        omitted (default), discovered automatically from the BPB
        ``total_sectors`` field on first non-bootstrap read.

    Notes
    -----
    The adapter takes ownership of the underlying :class:`TibxReader`
    file handle.  Use it as a context manager (or call :meth:`close`)
    to release the handle.
    """

    cluster_size: int = DEFAULT_CLUSTER_SIZE

    def __init__(
        self,
        tibx_path: str,
        partition_offset: int = 0,
        *,
        volume_id: Optional[int] = None,
        segment_cache_size: int = DEFAULT_SEGMENT_CACHE_SIZE,
    ) -> None:
        if partition_offset < 0:
            raise ValueError(
                f"partition_offset must be non-negative, got {partition_offset}"
            )
        self.tibx_path = tibx_path
        self.partition_offset = partition_offset
        self._reader = TibxReader(tibx_path)
        self._partition_size: Optional[int] = None

        # Lazy-built indexes.
        self._seg_index: Optional[Dict[int, SegLocator]] = None
        self._extents: Optional[List[DataMapEntry]] = None
        # Per-volume sorted source_offset arrays for binary search.
        self._extents_by_volume: Optional[
            Dict[int, Tuple[List[int], List[DataMapEntry]]]
        ] = None
        self._volume_id: Optional[int] = volume_id

        # LRU cache of decompressed segment plaintexts:
        # OrderedDict[seg_id -> bytes].  Most-recently-used at the end.
        self._segment_cache: "OrderedDict[int, bytes]" = OrderedDict()
        self._segment_cache_size = segment_cache_size

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
        """Return ``length`` bytes starting at byte ``offset``.

        ``offset`` is interpreted relative to :attr:`partition_offset`
        (so for a partition-view adapter, ``offset=0`` is the start of
        the partition).
        """
        if length <= 0:
            raise ValueError(f"length must be positive, got {length}")
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        # Partition-view: serve via data_map extents on the matching
        # volume_id.  Falls back to ChunkMapNotImplemented if the
        # discovery + lookup pipeline can't satisfy the read (rare).
        if self.partition_offset > 0:
            return self._read_partition(offset, length)

        # Whole-disk view: bootstrap-only path (the MBR and the first
        # 256 KiB of source content live in segment 4).  Anything past
        # that requires the per-volume data_map - which we don't have
        # for a whole-disk view because the disk's MBR isn't a member
        # of any data_map stream.
        abs_offset = offset
        end = abs_offset + length
        if end > BOOTSTRAP_LEN:
            raise ChunkMapNotImplemented(
                f"TibxDiskAdapter.read({offset}, {length}): whole-disk "
                f"reads past {BOOTSTRAP_LEN} (256 KiB) require a "
                f"partition-view adapter (pass partition_offset=...)."
            )
        return self._read_bootstrap(abs_offset, length)

    # -------- bootstrap (whole-disk) path ------------------------------ #

    def _read_bootstrap(self, abs_offset: int, length: int) -> bytes:
        """Serve a read from the first SG segment (whole-disk MBR + 256 KiB)."""
        sec_start = abs_offset // SECTOR_SIZE
        sec_byte_start = sec_start * SECTOR_SIZE
        slice_lo = abs_offset - sec_byte_start
        end = abs_offset + length
        sec_byte_end = ((end + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
        aligned_len = sec_byte_end - sec_byte_start

        raw = self._reader.read_lba_range(
            sec_start, aligned_len, sector_size=SECTOR_SIZE
        )
        return raw[slice_lo : slice_lo + length]

    # -------- partition-view path -------------------------------------- #

    def _ensure_indexes(self) -> None:
        """Build segment_map and data_map indexes lazily on first use."""
        if self._seg_index is None:
            self._seg_index = load_seg_index(self._reader)
        if self._extents is None:
            self._extents = load_extents(self._reader)
            # Group by volume_id and build a parallel sorted list of
            # source_offsets for bisect-based lookup.
            by_vol: Dict[int, List[DataMapEntry]] = {}
            for e in self._extents:
                by_vol.setdefault(e.key.volume_id, []).append(e)
            self._extents_by_volume = {
                vid: (
                    [e.key.source_offset for e in entries],
                    entries,
                )
                for vid, entries in by_vol.items()
            }

    def _discover_volume_id(self) -> int:
        """Pick the data_map ``volume_id`` matching :attr:`partition_offset`.

        Strategy: every candidate volume's first extent (at source
        offset 0) is its boot record.  We decompress the segment, peek
        at the BPB ``total_sectors`` field, and pick the volume whose
        sector count matches the MBR partition entry at our offset.

        Falls back to ``TibxAdapterError`` if no match is found - the
        caller can override by passing ``volume_id`` to the constructor.
        """
        self._ensure_indexes()
        assert self._extents_by_volume is not None

        # Find the MBR entry that matches our partition_offset.
        mbr_partitions = self.list_mbr_partitions()
        match = next(
            (
                p
                for p in mbr_partitions
                if p["byte_offset"] == self.partition_offset
            ),
            None,
        )
        expected_total_sectors = match["lba_count"] if match else None

        # For every volume whose lowest source_offset is 0, peek at the
        # boot sector of its first extent's segment.
        candidates: List[Tuple[int, int, int]] = []
        for vid, (offsets, entries) in self._extents_by_volume.items():
            if not offsets or offsets[0] != 0:
                continue
            entry = entries[0]
            seg_id = entry.value.segment_id
            try:
                segment = self._read_segment_plaintext(seg_id)
            except Exception:
                continue
            if len(segment) < 512 or segment[510:512] != b"\x55\xaa":
                continue
            # NTFS / exFAT / FAT BPBs all carry a 16-bit total_sectors
            # at +0x13 with 0 indicating "use the 32-bit field at +0x20"
            # for >= 64 KiB volumes.  We use the same fallback chain.
            small = struct.unpack("<H", segment[0x13:0x15])[0]
            big32 = struct.unpack("<I", segment[0x20:0x24])[0]
            if small != 0:
                total = small
            else:
                total = big32
            # NTFS specifically stores total_sectors at +0x28 as a u64.
            ntfs_total = struct.unpack("<Q", segment[0x28:0x30])[0]
            candidates.append((vid, total, ntfs_total))

        if not candidates:
            raise TibxAdapterError(
                "no data_map volume has an extent at source offset 0; "
                "cannot auto-discover volume_id - pass volume_id=... "
                "explicitly"
            )

        if expected_total_sectors is not None:
            # Try matching against the NTFS u64 first (most precise),
            # then the BPB u16/u32 (size + 1 because NTFS stores
            # last-sector index).
            for vid, total, ntfs_total in candidates:
                if (
                    ntfs_total + 1 == expected_total_sectors
                    or ntfs_total == expected_total_sectors
                    or total == expected_total_sectors
                ):
                    return vid

        # Fallback: if there's only one candidate, use it.
        if len(candidates) == 1:
            return candidates[0][0]

        candidates_repr = ", ".join(
            f"vol={vid}(bpb_total={t},ntfs_total={nt})"
            for vid, t, nt in candidates
        )
        raise TibxAdapterError(
            f"could not match partition_offset={self.partition_offset} "
            f"(expected_total_sectors={expected_total_sectors}) to any "
            f"data_map volume; candidates: {candidates_repr}"
        )

    def _ensure_volume_id(self) -> int:
        if self._volume_id is None:
            self._volume_id = self._discover_volume_id()
        return self._volume_id

    def _read_partition(self, offset: int, length: int) -> bytes:
        """Serve a partition-view read by walking data_map + segment_map."""
        self._ensure_indexes()
        vid = self._ensure_volume_id()
        assert self._extents_by_volume is not None

        out = bytearray()
        cursor = offset
        end = offset + length
        offsets, entries = self._extents_by_volume.get(vid, ([], []))
        while cursor < end:
            # Find the extent <= cursor.  bisect_right - 1.
            idx = bisect.bisect_right(offsets, cursor) - 1
            extent: Optional[DataMapEntry] = entries[idx] if idx >= 0 else None
            ext_end = extent.end_offset if extent else 0
            if extent is None or cursor >= ext_end:
                # In a sparse hole.  Zero-fill until the next extent
                # (or the requested end, whichever is sooner).
                if extent is None or idx + 1 >= len(entries):
                    next_off = end
                else:
                    next_off = min(end, entries[idx + 1].key.source_offset)
                fill = next_off - cursor
                out.extend(b"\x00" * fill)
                cursor = next_off
                continue

            # Take whatever this extent contributes up to ``end``.
            take_end = min(end, ext_end)
            seg_id = extent.value.segment_id
            seg_plain = self._read_segment_plaintext(seg_id)
            # extent_index 0xFFFF means "extent fills the whole
            # segment"; for now we always slice from offset zero in the
            # segment plaintext.  Multi-extent segments would need the
            # extent_index to translate to a within-segment offset; no
            # such case has been observed in the reference archive.
            seg_off = cursor - extent.key.source_offset
            chunk = seg_plain[seg_off : seg_off + (take_end - cursor)]
            if len(chunk) < (take_end - cursor):
                # Defensive: pad with zeros if the segment plaintext is
                # shorter than the extent claims.  Should not happen on
                # a well-formed archive.
                chunk = chunk + b"\x00" * ((take_end - cursor) - len(chunk))
            out.extend(chunk)
            cursor = take_end
        return bytes(out)

    def _read_segment_plaintext(self, seg_id: int) -> bytes:
        """Return the (cached) decompressed plaintext of segment ``seg_id``."""
        cached = self._segment_cache.get(seg_id)
        if cached is not None:
            self._segment_cache.move_to_end(seg_id)
            return cached
        assert self._seg_index is not None
        loc = self._seg_index.get(seg_id)
        if loc is None:
            raise TibxAdapterError(f"segment_id {seg_id} not in segment_map")
        # Re-parse the SG header at the recorded page so we can call
        # decompress_segment without re-scanning the file.
        page = self._reader._raw_read_page(loc.page_offset)  # type: ignore[attr-defined]
        seg = parse_sg_header(page, loc.page_offset)
        if seg is None:
            raise TibxAdapterError(
                f"segment_id {seg_id} at page {loc.page_offset} is not "
                f"an SG header (segment_map cache stale?)"
            )
        plain = self._reader.decompress_segment(seg)
        self._segment_cache[seg_id] = plain
        if len(self._segment_cache) > self._segment_cache_size:
            # Pop the least-recently-used entry.
            self._segment_cache.popitem(last=False)
        return plain

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
        """Best-effort recovery of disk-or-partition byte length."""
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
        """Return byte-length of the partition starting at :attr:`partition_offset`."""
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
        """Return a list describing the four MBR partition entries."""
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
        """Return total disk size derived from ARCH TLV[18], or ``None``."""
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
        """Derive disk size from the MBR partition table at LBA 0."""
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
