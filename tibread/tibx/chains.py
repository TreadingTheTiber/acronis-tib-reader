"""
tibread.tibx.chains — slice / chain enumeration for .tibx archives.

Unlike legacy ``.tib`` files (which need a sidecar SQLite catalog —
``mms.db`` / ``local-archives.db`` — to enumerate the chain), a
``.tibx`` archive is **fully self-contained**: every slice in the
backup chain is described by a record in the slices LSM tree at
``arch+0x10b8`` (TLV slot 5).

This module provides a small high-level API on top of
:mod:`tibread.tibx.lsm` / :mod:`tibread.tibx.lsm_cells` that:

* enumerates every alive slice record (whether it lives in an on-disk
  ctree or in the residual LZ4-compressed mem-tree at the tail of the
  L-SB record);
* decodes the 132-byte on-disk slice record into a typed
  :class:`Slice` dataclass;
* follows ``parent_uuid`` links back to the chain's FULL backup.

Slice record byte layout (TLV[5] LSM value, 132 bytes effective).
Source: ``ar_slice_from_disk @ 0x18002da80`` in ``archive3.dll``
(decompiled, plus empirical confirmation against
``Jmicron 0102.tibx``)::

    +0x00  16   slice_uuid                 raw 16 B
    +0x10   8   ts_a                       BE u64  (start time, ms-epoch)
    +0x18   8   ts_b                       BE u64  (finish time, ms-epoch)
    +0x20  16   parent_uuid                raw 16 B  (zero for FULL)
    +0x30   4   features_or_flags          BE u32
    +0x34   4   reserved
    +0x38   4   counter_a                  BE u32
    +0x3c   4   counter_b                  BE u32
    +0x40   4   counter_c                  BE u32
    +0x44   1   flags_byte                 raw u8 (see below)
    +0x45   8   ts_c                       BE u64 unaligned
    +0x4d   4   slice_id                   BE u32 unaligned
    +0x51   8   chain_root_size_or_extra   BE u64 unaligned
    +0x59  42   reserved (zeros)

The flags byte at +0x44 carries both the slice type (bits 2/3) and a
small features bitmap (bits 0/1/4/5/6) plus an "internal hidden" bit
(bit 7).  See :func:`slice_type_from_flags`.

Where slice records live
------------------------
* Most archives keep slices in the L-SB's mem-tree (the LZ4-compressed
  ``memtree_extra_payload``); :func:`enumerate_slices` decodes that.
* Once the mem-tree compacts, slices end up in on-disk ctree LEAF
  pages reachable from one of the L-SB's ctree slots; the same
  function walks those too.
* Tombstone cells (deletions) are silently skipped.

References
~~~~~~~~~~
* ``docs/legacy/ARCHIVE3_CHAINS.md`` — full byte-precise documentation
* ``ar_slice_from_disk @ 0x18002da80`` (record decode)
* ``ar_slice_to_disk   @ 0x18002eef0`` (record encode)
* ``archive_slice_query @ 0x180030390`` (lookup by slice_id)
* ``archive_slice_query_by_uuid @ 0x1800303e0`` (linear scan by UUID)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .lsm import (
    LsmSuperblock,
    iter_tree_entries,
    read_archive_header,
)
from .lsm_cells import decode_cells_compact

try:
    import lz4.block as _lz4_block
except ImportError:  # pragma: no cover
    _lz4_block = None


SLICE_RECORD_LEN = 132
SLICE_UUID_LEN = 16
ZERO_UUID = b"\x00" * SLICE_UUID_LEN


SLICE_TYPE_FULL = "full"
SLICE_TYPE_INC = "inc"
SLICE_TYPE_DIFF = "diff"
SLICE_TYPE_EDITED = "edited"


def slice_type_from_flags(flags_byte: int) -> str:
    """Decode the slice-type bits from the ``flags_byte`` at +0x44.

    Mirrors ``ar_slice_from_disk`` exactly::

        if flags & 0x04:                  type = "diff"     (DIFFERENTIAL)
        elif flags & 0x08:                type = "edited"   (EDITED)
        elif (flags & 0x73) != 0:         type = "inc"      (INCREMENTAL)
        else:                             type = "full"     (BASE)
    """
    if flags_byte & 0x04:
        return SLICE_TYPE_DIFF
    if flags_byte & 0x08:
        return SLICE_TYPE_EDITED
    if (flags_byte & 0x73) != 0:
        return SLICE_TYPE_INC
    return SLICE_TYPE_FULL


def slice_features(flags_byte: int) -> List[str]:
    """Return human-readable feature names from the flags byte."""
    out: List[str] = []
    f = flags_byte & 0x73
    if f & 0x01:
        out.append("(unnamed)")
    if f & 0x02:
        out.append("hidden")
    if f & 0x10:
        out.append("before sys. patch")
    if f & 0x20:
        out.append("converted")
    if f & 0x40:
        out.append("created in network isolation")
    if flags_byte & 0x80:
        out.append("internal_hidden")
    return out


@dataclass(frozen=True)
class Slice:
    """One decoded slice record from the slices LSM tree (TLV[5]).

    Fields mirror the on-disk 132-byte record decoded by
    ``ar_slice_from_disk``.  Timestamps are Unix milliseconds (the same
    epoch the rest of archive3 uses for ``created_unix_ms``).

    ``slice_id`` is taken from the LSM **key** (4-byte BE u32).  The
    record body also carries a 4-byte ``slice_id`` at +0x4d; on every
    archive observed so far that field has been zero in the latest
    mem-tree records, so the key is the authoritative source.
    """

    uuid: bytes                 # 16 B raw slice UUID
    parent_uuid: bytes          # 16 B raw parent UUID (zero == FULL)
    slice_id: int               # from LSM key (BE u32)
    slice_type: str             # "full" / "inc" / "diff" / "edited"
    flags: int                  # raw flags byte at +0x44
    features: Tuple[str, ...]   # decoded feature strings
    ctime: int                  # ts_a — slice start time (ms epoch)
    mtime: int                  # ts_b — slice finish time (ms epoch)
    raw: bytes                  # original 132-byte record (for forensics)

    @property
    def is_full(self) -> bool:
        """Is this the chain's FULL (BASE) backup?

        We treat the slice as FULL iff EITHER the type bits in the
        flags byte say so OR the parent_uuid is the zero UUID — both
        criteria match in well-formed archives.  The redundancy guards
        against archives where the doc-claimed +0x20 layout is slightly
        off and parent_uuid bytes are non-zero counters rather than a
        UUID.
        """
        return self.slice_type == SLICE_TYPE_FULL or self.parent_uuid == ZERO_UUID

    @property
    def uuid_hex(self) -> str:
        return self.uuid.hex()

    @property
    def parent_uuid_hex(self) -> str:
        return self.parent_uuid.hex()


def parse_slice_record(slice_id: int, record: bytes) -> Slice:
    """Decode one 132-byte slice record + LSM key into a :class:`Slice`.

    ``slice_id`` is the BE u32 from the LSM key (the authoritative
    ordinal); ``record`` is the 132-byte LSM value.
    """
    if len(record) < SLICE_RECORD_LEN:
        raise ValueError(
            f"slice record too short: {len(record)} bytes (want {SLICE_RECORD_LEN})"
        )
    uuid = bytes(record[0x00:0x10])
    ts_a = struct.unpack(">Q", record[0x10:0x18])[0]
    ts_b = struct.unpack(">Q", record[0x18:0x20])[0]
    parent_uuid = bytes(record[0x20:0x30])
    flags_byte = record[0x44]
    return Slice(
        uuid=uuid,
        parent_uuid=parent_uuid,
        slice_id=slice_id,
        slice_type=slice_type_from_flags(flags_byte),
        flags=flags_byte,
        features=tuple(slice_features(flags_byte)),
        ctime=ts_a,
        mtime=ts_b,
        raw=bytes(record[:SLICE_RECORD_LEN]),
    )


# --- mem-tree decoding ----------------------------------------------------


def _decode_memtree_cells(sb: LsmSuperblock):
    """Decode the L-SB's residual mem-tree as a list of ``LsmCell``.

    The mem-tree blob in the L-SB ``memtree_extra_payload`` is laid out
    as a single LZ4-multi-block frame (``[c_len BE u32][u_len BE u32][LZ4 bytes]``)
    whose decompressed body is the same compact-cell stream used by
    LEAF pages — i.e. ``decode_cells_compact`` reads it directly given
    the tree's ``key_length`` / ``value_length``.  This was confirmed
    empirically against ``Jmicron 0102.tibx`` (TLV[5] mem-tree decodes
    cleanly to one alive cell + one tombstone with this scheme).
    """
    payload = sb.memtree_extra_payload
    if not payload or sb.memtree_node_count == 0:
        return []
    if sb.memtree_encoding & 0x80:
        raise NotImplementedError("encrypted mem-tree blobs not supported")
    if sb.memtree_encoding & 0x7F == 0:
        # raw — no LZ4 wrapper
        decoded = bytes(payload)
    elif sb.memtree_encoding & 0x7F == 1:
        if _lz4_block is None:
            raise RuntimeError("python-lz4 is required to decode mem-tree blobs")
        if len(payload) < 8:
            return []
        cs = struct.unpack(">I", payload[0:4])[0]
        ds = struct.unpack(">I", payload[4:8])[0]
        if 8 + cs > len(payload):
            raise ValueError(
                f"mem-tree LZ4 frame truncated: cs={cs}, payload={len(payload)}"
            )
        decoded = _lz4_block.decompress(
            bytes(payload[8:8 + cs]), uncompressed_size=ds,
        )
        if len(decoded) != ds:
            raise ValueError(
                f"mem-tree LZ4 decoded {len(decoded)} bytes, expected {ds}"
            )
    else:
        raise NotImplementedError(
            f"unknown mem-tree encoding {sb.memtree_encoding}"
        )
    if sb.key_length == 0:
        # no test fixture exercises this branch yet; safe fallback
        return []
    return decode_cells_compact(
        decoded,
        count=sb.memtree_node_count,
        fixed_key_size=sb.key_length,
        fixed_val_size=sb.value_length,
    )


# --- public API -----------------------------------------------------------


def _find_slices_superblock(reader) -> LsmSuperblock:
    hdr = read_archive_header(reader)
    for sb in hdr.lsm_trees:
        if sb.tlv_index == 5:
            return sb
    raise RuntimeError("TLV[5] (slices) superblock not found in archive header")


def enumerate_slices(reader) -> List[Slice]:
    """Return every alive slice in ``reader``'s slices LSM tree.

    Combines the L-SB residual mem-tree with every populated on-disk
    ctree.  When the same ``slice_id`` appears in both, the **mem-tree**
    record wins (it represents the more recent commit) — mirroring the
    LSM-merge semantics that ``lsm_lookup_eq`` would apply.

    Tombstones are silently skipped.  Records whose decoded slice_id
    differs from the LSM key always trust the key (the in-record
    ``slice_id`` field has been observed to be 0 in mem-tree-only
    records).
    """
    sb = _find_slices_superblock(reader)

    # Mem-tree first (most recent updates).
    seen: Dict[int, Slice] = {}
    tombstoned: set = set()
    for cell in _decode_memtree_cells(sb):
        if len(cell.key) < 4:
            continue
        slice_id = struct.unpack(">I", cell.key[:4])[0]
        if not cell.alive:
            tombstoned.add(slice_id)
            continue
        if len(cell.value) < SLICE_RECORD_LEN:
            continue
        seen[slice_id] = parse_slice_record(slice_id, cell.value)

    # On-disk ctrees (older records).  Skip slice_ids already covered
    # by the mem-tree (alive or tombstoned).
    if any(c.offset is not None for c in sb.ctrees):
        for raw_key, raw_val in iter_tree_entries(reader, sb):
            if len(raw_key) < 4 or len(raw_val) < SLICE_RECORD_LEN:
                continue
            slice_id = struct.unpack(">I", raw_key[:4])[0]
            if slice_id in seen or slice_id in tombstoned:
                continue
            seen[slice_id] = parse_slice_record(slice_id, raw_val)

    return [seen[sid] for sid in sorted(seen)]


def find_slice_by_uuid(reader, uuid: Union[bytes, str]) -> Optional[Slice]:
    """Return the slice whose 16-byte UUID equals ``uuid``, or ``None``.

    Accepts either a 16-byte ``bytes`` value or a 32-character hex
    string.  Mirrors ``archive_slice_query_by_uuid`` (linear scan;
    UUIDs are not separately indexed).
    """
    if isinstance(uuid, str):
        uuid_bytes = bytes.fromhex(uuid)
    else:
        uuid_bytes = bytes(uuid)
    if len(uuid_bytes) != SLICE_UUID_LEN:
        raise ValueError(f"uuid must be {SLICE_UUID_LEN} bytes; got {len(uuid_bytes)}")
    for s in enumerate_slices(reader):
        if s.uuid == uuid_bytes:
            return s
    return None


def walk_chain_from_uuid(reader,
                         uuid: Union[bytes, str]) -> List[Slice]:
    """Walk the chain backwards from ``uuid`` to its FULL backup.

    Returns the slice list **starting at the requested slice and
    ending at the FULL** (BASE).  If a parent UUID does not resolve
    to any known slice the walk stops (returning what's been collected
    so far) — useful for inspecting truncated/orphaned chains.
    """
    slices_by_uuid = {s.uuid: s for s in enumerate_slices(reader)}
    if isinstance(uuid, str):
        cur = bytes.fromhex(uuid)
    else:
        cur = bytes(uuid)
    chain: List[Slice] = []
    visited: set = set()
    while cur in slices_by_uuid:
        if cur in visited:
            break  # cycle guard — should never happen on well-formed data
        visited.add(cur)
        s = slices_by_uuid[cur]
        chain.append(s)
        if s.is_full:
            break
        cur = s.parent_uuid
        if cur == ZERO_UUID:
            break
    return chain


def iter_chains(reader) -> Iterator[List[Slice]]:
    """Yield each backup chain as a list of slices starting at the FULL.

    A "chain" is a connected sub-DAG of the slices: one FULL plus
    every slice whose ``parent_uuid`` lineage terminates at that
    FULL.  Slices are emitted in ``slice_id`` order within each chain.
    """
    slices = enumerate_slices(reader)
    by_uuid = {s.uuid: s for s in slices}
    fulls = [s for s in slices if s.is_full]
    fulls.sort(key=lambda s: s.slice_id)
    used: set = set()
    for full in fulls:
        chain = [full]
        used.add(full.uuid)
        # Greedy descendant collection: any slice whose chain to a
        # FULL passes through this one belongs here.
        for s in slices:
            if s.uuid == full.uuid or s.uuid in used:
                continue
            walk = walk_chain_from_uuid(reader, s.uuid)
            if walk and walk[-1].uuid == full.uuid:
                chain.append(s)
                used.add(s.uuid)
        chain.sort(key=lambda s: s.slice_id)
        yield chain
    # Orphans (parent_uuid points outside the archive).
    orphans = [s for s in slices if s.uuid not in used]
    if orphans:
        orphans.sort(key=lambda s: s.slice_id)
        yield orphans


__all__ = [
    "SLICE_RECORD_LEN",
    "SLICE_UUID_LEN",
    "SLICE_TYPE_FULL",
    "SLICE_TYPE_INC",
    "SLICE_TYPE_DIFF",
    "SLICE_TYPE_EDITED",
    "ZERO_UUID",
    "Slice",
    "slice_type_from_flags",
    "slice_features",
    "parse_slice_record",
    "enumerate_slices",
    "find_slice_by_uuid",
    "walk_chain_from_uuid",
    "iter_chains",
]
