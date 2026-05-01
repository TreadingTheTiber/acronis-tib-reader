"""
tibread.tibx.segment_map - segment_map (TLV[2]) decoder + seg_id index.

The ``segment_map`` LSM tree maps **segment_id (BE u64)** to a 32-byte
record describing where the segment lives in the .tibx file::

    +0..+4   u32 LE  page_count    # number of 4 KiB pages occupied
    +4..+8   u32 BE  page_offset   # first page index (multiply by 4096
                                   # to get the file byte offset)
    +8..+12  u32 BE  slice_id      # slice number that owns the segment
    +12..+32 20 B    sha1_hash     # content fingerprint (20 raw bytes)

The mixed endianness is empirical: scanning every entry in
``example.tibx`` (263 063 segments) gives a byte-perfect match
between ``page_count`` decoded LE-u32 and the SgSegment.page_span()
counted directly from the SG header pages, and between ``page_offset``
decoded BE-u32 and the actual page index of the segment.  Mismatches:
0 / 263 063.

Public API
----------

* :func:`load_seg_index` - walk the segment_map LSM tree and return a
  ``dict[seg_id] -> SegLocator`` with cache-file persistence
  (``<tibx>.segidx`` next to the archive).
* :func:`save_seg_index` / :func:`load_seg_index_cache` - cache I/O
  (used internally; exposed for diagnostics).
* :class:`SegLocator` - dataclass with ``page_count`` /
  ``page_offset`` plus convenience properties (``file_offset``).

Cache format ``<tibx>.segidx``::

    +0   4   magic   "SGIX"
    +4   4   BE u32  version (== 1)
    +8   4   BE u32  entry_count
    +12  ... entry_count x 16 B records of (BE u64 seg_id,
                                            BE u32 page_count,
                                            BE u32 page_offset)
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Dict, Optional

from .format import PAGE_SIZE


__all__ = [
    "SegLocator",
    "decode_segment_map_value",
    "load_seg_index",
    "save_seg_index",
    "load_seg_index_cache",
    "build_seg_index_from_lsm",
    "SEGMENT_MAP_VALUE_SIZE",
    "SEG_INDEX_CACHE_MAGIC",
    "SEG_INDEX_CACHE_VERSION",
]


SEGMENT_MAP_VALUE_SIZE = 32
SEG_INDEX_CACHE_MAGIC = b"SGIX"
SEG_INDEX_CACHE_VERSION = 1


@dataclass(frozen=True)
class SegLocator:
    """Where one SG segment lives in the .tibx file."""

    seg_id: int
    page_count: int     # u32 LE in segment_map value bytes [0:4]
    page_offset: int    # u32 BE in segment_map value bytes [4:8]

    @property
    def file_offset(self) -> int:
        """Absolute byte offset of the SG segment header in the file."""
        return self.page_offset * PAGE_SIZE


def decode_segment_map_value(raw: bytes) -> "tuple[int, int]":
    """Return ``(page_count, page_offset)`` from a 32-byte segment_map value.

    Only the first 8 bytes are decoded here; the remaining 24 bytes
    (4-byte slice_id + 20-byte SHA-1 hash) are not needed for byte-range
    reads.
    """
    if len(raw) < 8:
        raise ValueError(
            f"segment_map value must be >= 8 bytes (got {len(raw)})"
        )
    page_count = struct.unpack("<I", raw[0:4])[0]
    page_offset = struct.unpack(">I", raw[4:8])[0]
    return page_count, page_offset


def build_seg_index_from_lsm(reader, sb=None) -> Dict[int, SegLocator]:
    """Walk the segment_map LSM tree once and return ``{seg_id: SegLocator}``.

    Parameters
    ----------
    reader : tibread.tibx.TibxReader
        An open reader.
    sb : LsmSuperblock, optional
        The segment_map L-SB (TLV slot 2).  If omitted, read the archive
        header and pick TLV[2] automatically.
    """
    from .lsm import iter_tree_entries, read_archive_header  # local import

    if sb is None:
        hdr = read_archive_header(reader)
        sb = next(s for s in hdr.lsm_trees if s.tlv_index == 2)

    out: Dict[int, SegLocator] = {}
    for raw_key, raw_val in iter_tree_entries(reader, sb):
        if not raw_val:
            # Tombstone (delete) - skip.
            continue
        if len(raw_key) != 8 or len(raw_val) < 8:
            continue
        seg_id = struct.unpack(">Q", raw_key)[0]
        # Earlier ctree entries are walked first ("newer" wins) - keep
        # whatever we saw first to mirror LSM merge semantics.
        if seg_id in out:
            continue
        page_count, page_offset = decode_segment_map_value(raw_val)
        out[seg_id] = SegLocator(
            seg_id=seg_id,
            page_count=page_count,
            page_offset=page_offset,
        )
    return out


def save_seg_index(path: str, index: Dict[int, SegLocator]) -> None:
    """Serialise ``index`` to ``path`` in the SGIX cache format."""
    with open(path, "wb") as f:
        f.write(SEG_INDEX_CACHE_MAGIC)
        f.write(struct.pack(">I", SEG_INDEX_CACHE_VERSION))
        f.write(struct.pack(">I", len(index)))
        # Write entries sorted by seg_id for reproducible cache files.
        for seg_id in sorted(index):
            loc = index[seg_id]
            f.write(struct.pack(">QII", seg_id, loc.page_count, loc.page_offset))


def load_seg_index_cache(path: str) -> Optional[Dict[int, SegLocator]]:
    """Load ``path`` if it's a valid SGIX cache, otherwise return ``None``.

    Returns ``None`` for missing file, wrong magic, unsupported version,
    or truncated content.  Callers should fall back to
    :func:`build_seg_index_from_lsm` in that case.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if len(blob) < 12:
        return None
    if blob[:4] != SEG_INDEX_CACHE_MAGIC:
        return None
    version = struct.unpack(">I", blob[4:8])[0]
    if version != SEG_INDEX_CACHE_VERSION:
        return None
    entry_count = struct.unpack(">I", blob[8:12])[0]
    if 12 + entry_count * 16 > len(blob):
        return None
    out: Dict[int, SegLocator] = {}
    p = 12
    for _ in range(entry_count):
        seg_id, page_count, page_offset = struct.unpack(
            ">QII", blob[p : p + 16]
        )
        out[seg_id] = SegLocator(
            seg_id=seg_id,
            page_count=page_count,
            page_offset=page_offset,
        )
        p += 16
    return out


def load_seg_index(reader, *, cache_path: Optional[str] = None,
                   write_cache: bool = True) -> Dict[int, SegLocator]:
    """Return the segment_map index, using a cache file if available.

    Parameters
    ----------
    reader : tibread.tibx.TibxReader
        Open reader for the archive.
    cache_path : str, optional
        Where to look for / write the SGIX cache.  Defaults to
        ``<reader.path>.segidx`` next to the archive.
    write_cache : bool, optional
        If True (default), save the cache after a fresh build so
        subsequent runs are instant.  Set False for read-only setups.
    """
    if cache_path is None:
        cache_path = reader.path + ".segidx"
    cached = load_seg_index_cache(cache_path)
    if cached is not None:
        return cached
    index = build_seg_index_from_lsm(reader)
    if write_cache:
        try:
            save_seg_index(cache_path, index)
        except OSError:
            # Read-only filesystem or permission denied: not fatal.
            pass
    return index
