"""
tibread.tibx.data_map — data_map (TLV[1]) key/value decoder + lookup helpers.

The ``data_map`` LSM tree maps **(volume_id, source_byte_offset)** to
**(segment_id, extent_index_in_segment)** for every extent stored in a
``.tibx`` archive.  Each on-disk record is a 31-byte key + 10-byte value.

Byte layout
-----------

The layout was confirmed by decompiling ``archive3.dll`` symbols
``lsm_key2dmap_ext`` (0x1800485d0), ``dmap_ext2ondisk`` (0x180048240),
``lsm_val2dmap_ext_info`` (0x180048640), and ``dmap_ext_info2ondisk``
(0x180048280).

Key (31 bytes, big-endian)::

    +0..+8    u64  volume_id        # 10 = main partition stream;
                                    #   2..12 are small metadata streams
    +8..+16   u64  source_byte_off  # source-disk byte offset within volume
    +16..+19  u24  extent_length    # length of this extent in bytes
    +19..+23  u32  field3           # always 0x00000002 in observed archives
                                    #   (record kind / version)
    +23..+31  u64  extent_id        # global monotonically-increasing extent id

Value (10 bytes, big-endian)::

    +0..+8    u64  segment_id       # key into segment_map (TLV[2])
    +8..+10   u16  extent_index     # 0,1,2,... for multi-extent segments;
                                    #   0xFFFF when the extent fills the
                                    #   whole segment (typical for big
                                    #   stream-10 extents)

Lex-sort property
-----------------

Because the 31-byte key starts with ``volume_id`` then
``source_byte_off`` (both BE u64), lexicographic order is equivalent to
``(volume_id, source_byte_off, ...)`` ordinal order.  This means
``lookup_le((volume_id, byte_offset))`` can find the extent containing
or preceding any given source byte by a simple ascending scan / binary
search across the on-disk ctrees.

Public API
----------

* :func:`decode_key`     — parse 31 raw key bytes into :class:`DataMapKey`
* :func:`decode_value`   — parse 10 raw value bytes into :class:`DataMapValue`
* :func:`load_extents`   — walk the data_map LSM tree and collect all
                            (DataMapKey, DataMapValue) pairs (sorted)
* :func:`lookup_le`      — given (volume_id, byte_offset), find the
                            extent that covers it (or the preceding one)
"""
from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

__all__ = [
    "DataMapKey",
    "DataMapValue",
    "DataMapEntry",
    "DATA_MAP_KEY_SIZE",
    "DATA_MAP_VALUE_SIZE",
    "DATA_MAP_KEY_FIELD3_DEFAULT",
    "DATA_MAP_VALUE_INDEX_SENTINEL",
    "decode_key",
    "decode_value",
    "encode_key",
    "load_extents",
    "lookup_le",
]


DATA_MAP_KEY_SIZE = 31
DATA_MAP_VALUE_SIZE = 10
# In observed Acronis 2025-era archives, key field3 is always 0x00000002.
# It corresponds to a record-kind / version selector in archive3.dll's
# in-memory ext struct.  We hard-code it for encoder use.
DATA_MAP_KEY_FIELD3_DEFAULT = 0x00000002
# Value field1 is 0xFFFF for "extent fills its segment".  Multi-extent
# segments use 0,1,2,... as a per-segment index.
DATA_MAP_VALUE_INDEX_SENTINEL = 0xFFFF


@dataclass(frozen=True)
class DataMapKey:
    """Decoded data_map key (per ``lsm_key2dmap_ext``)."""

    volume_id: int          # +0..+8   BE u64
    source_offset: int      # +8..+16  BE u64
    extent_length: int      # +16..+19 BE u24
    field3: int             # +19..+23 BE u32 (== 2 in observed archives)
    extent_id: int          # +23..+31 BE u64


@dataclass(frozen=True)
class DataMapValue:
    """Decoded data_map value (per ``lsm_val2dmap_ext_info``)."""

    segment_id: int         # +0..+8 BE u64 — key into segment_map (TLV[2])
    extent_index: int       # +8..+10 BE u16 (0xFFFF = whole-segment extent)


@dataclass(frozen=True)
class DataMapEntry:
    """One (key, value) pair from the data_map tree."""

    key: DataMapKey
    value: DataMapValue

    @property
    def end_offset(self) -> int:
        """Exclusive end offset of this extent within its volume."""
        return self.key.source_offset + self.key.extent_length

    def covers(self, volume_id: int, byte_offset: int) -> bool:
        """True iff ``(volume_id, byte_offset)`` is inside this extent."""
        return (
            self.key.volume_id == volume_id
            and self.key.source_offset <= byte_offset < self.end_offset
        )


def decode_key(raw: bytes) -> DataMapKey:
    """Parse a raw 31-byte data_map key."""
    if len(raw) != DATA_MAP_KEY_SIZE:
        raise ValueError(
            f"data_map key must be {DATA_MAP_KEY_SIZE} bytes, got {len(raw)}"
        )
    volume_id = struct.unpack(">Q", raw[0:8])[0]
    source_off = struct.unpack(">Q", raw[8:16])[0]
    extent_len = int.from_bytes(raw[16:19], "big")
    field3 = struct.unpack(">I", raw[19:23])[0]
    extent_id = struct.unpack(">Q", raw[23:31])[0]
    return DataMapKey(
        volume_id=volume_id,
        source_offset=source_off,
        extent_length=extent_len,
        field3=field3,
        extent_id=extent_id,
    )


def decode_value(raw: bytes) -> DataMapValue:
    """Parse a raw 10-byte data_map value."""
    if len(raw) != DATA_MAP_VALUE_SIZE:
        raise ValueError(
            f"data_map value must be {DATA_MAP_VALUE_SIZE} bytes, got {len(raw)}"
        )
    segment_id = struct.unpack(">Q", raw[0:8])[0]
    extent_index = struct.unpack(">H", raw[8:10])[0]
    return DataMapValue(segment_id=segment_id, extent_index=extent_index)


def encode_key(key: DataMapKey) -> bytes:
    """Serialise a DataMapKey back to its 31-byte on-disk form.

    Mirrors ``dmap_ext2ondisk`` in ``archive3.dll``.
    """
    if not (0 <= key.extent_length < 1 << 24):
        raise ValueError("extent_length must fit in 24 bits")
    return (
        struct.pack(">Q", key.volume_id)
        + struct.pack(">Q", key.source_offset)
        + key.extent_length.to_bytes(3, "big")
        + struct.pack(">I", key.field3)
        + struct.pack(">Q", key.extent_id)
    )


def load_extents(reader, sb=None) -> List[DataMapEntry]:
    """Walk the data_map LSM tree and return all extents, sorted by
    ``(volume_id, source_offset)``.

    Parameters
    ----------
    reader : tibread.tibx.TibxReader
        An open reader.
    sb : LsmSuperblock, optional
        The data_map L-SB (TLV slot index 1).  If ``None``, read the
        archive header and pick TLV[1] automatically.
    """
    # Local import keeps this module cheap to import.
    from .lsm import iter_tree_entries, read_archive_header

    if sb is None:
        hdr = read_archive_header(reader)
        sb = next(s for s in hdr.lsm_trees if s.tlv_index == 1)

    entries: List[DataMapEntry] = []
    for raw_key, raw_val in iter_tree_entries(reader, sb):
        if not raw_val:                  # tombstone
            continue
        if len(raw_key) != DATA_MAP_KEY_SIZE:
            continue
        if len(raw_val) != DATA_MAP_VALUE_SIZE:
            continue
        entries.append(
            DataMapEntry(
                key=decode_key(raw_key),
                value=decode_value(raw_val),
            )
        )

    # The tree spans multiple ctrees concatenated in walker order, so
    # sort here for binary-search-able lookup_le.
    entries.sort(key=lambda e: (e.key.volume_id, e.key.source_offset))
    return entries


def lookup_le(
    entries: List[DataMapEntry], volume_id: int, byte_offset: int
) -> Optional[DataMapEntry]:
    """Return the extent that covers ``byte_offset`` in volume
    ``volume_id``, or ``None`` if no such extent exists.

    Implements an LSM-style "lookup less-or-equal" against the sorted
    extents list.  Returns ``None`` if the offset falls in a gap (sparse
    region) between extents — the caller should treat that as a hole
    (zero-fill).
    """
    # Binary-search for the largest entry with
    # (volume_id, source_offset) <= (volume_id, byte_offset).
    # We use a synthetic key tuple for bisect.
    # Since entries is sorted, this is a standard bisect_right pattern.
    keys = [(e.key.volume_id, e.key.source_offset) for e in entries]
    idx = bisect.bisect_right(keys, (volume_id, byte_offset)) - 1
    if idx < 0:
        return None
    candidate = entries[idx]
    if candidate.covers(volume_id, byte_offset):
        return candidate
    return None
