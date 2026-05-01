"""
tibread.tibx.lsm — Acronis archive3 LSM-tree parser.

Two on-disk constructs are decoded here:

1. **L-SB superblocks** carried inline in the TLV directory of the
   latest ``ARCH`` page (page-type 0x01). Each L-SB describes one LSM
   tree's per-ctree run array (root page offsets + item counts) plus
   a residual mem-tree.

2. **LEAF / LDIR pages** (page-types 0x03 and 0x04) — the on-disk
   B-tree pages reachable from each ctree's ``root_page_offset``. The
   page envelope is decoded here; the **inner cell stream** (decoded
   key/value records inside a LEAF page body) is the focus of a
   companion module ``tibread.tibx.lsm_cells``.

The byte layouts implemented here are documented in
``docs/legacy/ARCHIVE3_LSM_SUPERBLOCK.md``. Confirmed against
``Jmicron 0102.tibx`` (header_version=8, hdr_size=0x1540, 13 347 630
pages).

What works today
----------------
* Read every L-SB from the latest ARCH header (multi-page-spanning is
  handled — the v8 archive's hdr is 0x1540 bytes, two ARCH pages).
* Decode the per-tree key/value sizes, sequence number, and full
  per-ctree run array (32 bytes per ctree slot, slot index `i` → ctree
  level `i+2`).
* Walk a tree top-down: read root LDIR page → LZ4-decompress the
  cell area → unpack `[key (k bytes), child_offset (BE u64)]` records
  → descend to next-level LDIR or LEAF.
* CRC-validated page reads via :class:`TibxReader`.

What's still WIP (delegated to ``lsm_cells``)
---------------------------------------------
* LEAF cell decoding (variable-stride packing with a presence bitmap;
  `ar_lsm_leaf_decompress` decompilation is the path forward).
* `encoding=0` raw-cell pages (rare; not seen in test archive).
* `encoding & 0x80` encrypted pages (not seen; would need key 1).

LSM tree mapping (TLV slot → tree)
----------------------------------
Authoritative table (matches the loader's struct offsets and decoder
length asserts). See ``ARCHIVE3_LSM_SUPERBLOCK.md`` for cross-checks.

==========  ======================  =========  ===========
TLV slot    Canonical tree name     key bytes  value bytes
==========  ======================  =========  ===========
0           ``lsm`` (meta)          0          0 (recursive)
1           ``data_map`` (dmap)     31         10
2           ``segment_map``         8          32
3           (unidentified)          9          0
4           ``dedup_map``           (empty)    (empty)
5           ``nlink_map``           4 / >=12   132
6           ``slices``              20         0
7           ``umap``                20         0 (empty)
8           ``notary`` (v7+)        special    special
==========  ======================  =========  ===========

Strings-agent's ``name_map`` candidate maps cleanly onto TLV[3]
(key=9, value=0) — its keys form a sorted lexicographic sequence
spanning the full byte range, consistent with a hashed-name index.
This is a strong inference but not yet decoder-confirmed.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from .format import (
    ENVELOPE_SIZE,
    INNER_MAGIC_ARCH,
    PAGE_BODY_SIZE,
    PAGE_SIZE,
    PAGE_TYPE_ARCH,
    PAGE_TYPE_ARCI,
    PAGE_TYPE_LEAF,
    PAGE_TYPE_LDIR,
    PAGE_TYPE_LSM5,
)


# Back-compat alias preserved for callers that imported the old name.
PAGE_TYPE_LSM_BLOB = PAGE_TYPE_LSM5

INNER_MAGIC_LDIR = b"LDIR"
INNER_MAGIC_LEAF = b"LEAF"
INNER_MAGIC_LSB = b"L-SB"

# Inner-page header layout (LEAF/LDIR):
#   +0x00  4   magic ("LEAF" or "LDIR")
#   +0x04  1   format_version (== 1)
#   +0x05  1   encoding (0=raw, 1=LZ4, 0x80-bit set = encrypted)
#   +0x06  2   reserved/level (BE u16; low byte often page-tree depth)
#   +0x08  4   uncompressed_payload_len (BE u32)
#   +0x0c  4   total_record_area_len    (BE u32; = inner_LZ4_clen + 8 if LZ4)
#   +0x10  4   page_id   (BE u32)
#   +0x14  4   sequence  (BE u32; == arch->seq or 0)
#   +0x18  0x1c reserved/padding (28 bytes; zero in v1)
#   +0x34  4   inner LZ4 stream-header: c_len  (BE u32) — only if encoding==1
#   +0x38  4   inner LZ4 stream-header: u_len  (BE u32) — only if encoding==1
#   +0x3c  ... LZ4 frame (or raw records)
LEAF_INNER_HEADER_LEN = 0x34       # bytes from start of body to the LZ4 preamble
LEAF_LZ4_PREAMBLE_LEN = 8          # [c_len BE u32][u_len BE u32]
LEAF_PAYLOAD_OFFSET_LZ4 = LEAF_INNER_HEADER_LEN + LEAF_LZ4_PREAMBLE_LEN  # 0x3c

# Back-compat constants — old code referenced these for the unfinished
# parser. They match the historical layout but are now superseded by
# the values above.
LEAF_HEADER_FIXED_LEN = 0x14
LEAF_PAYLOAD_OFFSET = 0x35

# Per-tree key / value sizes for the L-SB record at each TLV slot.
# Used by :func:`walk_ctree` to know how to slice each LDIR record.
# Indexed by ``(key_length, value_length)``; the value sizes for the
# trees that actually appear on disk are baked in.
TLV_TREE_NAMES: Dict[int, str] = {
    0: "lsm",
    1: "data_map",
    2: "segment_map",
    3: "tlv3",            # unidentified, possibly name_map
    4: "dedup_map",
    5: "nlink_map",
    6: "slices",
    7: "umap",
    8: "notary",
}


# --- L-SB superblock parsing ---------------------------------------------


@dataclass(frozen=True)
class CTreeRef:
    """One on-disk ctree (frozen LSM run) entry from an L-SB.

    All offsets are byte-offsets into the ``.tibx`` file. ``offset is
    None`` represents the empty-slot sentinel ``0xFFFFFFFFFFFFFFFF``.
    """

    offset: Optional[int]    # root page byte offset (None if empty)
    num_pages: int           # bytes occupied by this ctree (BE u64)
    item_count: int          # number of leaf entries (BE u32)
    max_key_or_size: int     # printed as "max" by dumper; BE u64

    # Back-compat fields kept so old callers continue to work. The old
    # parser exposed a ``tree_nr`` / ``tree_sz`` pair that was a
    # mis-decode of these same bytes.
    @property
    def tree_nr(self) -> int:        # legacy alias
        return self.item_count

    @property
    def tree_sz(self) -> int:        # legacy alias
        return self.num_pages

    @property
    def root_page(self) -> Optional[int]:
        if self.offset is None:
            return None
        return self.offset // PAGE_SIZE

    @property
    def page_count(self) -> int:
        """Pages occupied by this ctree (rounded up)."""
        return (self.num_pages + PAGE_SIZE - 1) // PAGE_SIZE

    @property
    def tree_page_count(self) -> int:    # legacy alias
        return self.page_count


@dataclass(frozen=True)
class LsmSuperblock:
    """One LSM-tree superblock parsed from an L-SB record.

    L-SB records are inline TLV payloads in the latest ARCH header. The
    archive header may span multiple 4 KiB pages; the parser here
    operates on a flat ``arch_body`` byte buffer assembled by
    :func:`read_full_arch_header`.
    """

    arch_page: int                     # ARCH page that carried this L-SB
    body_offset: int                   # byte offset within arch_body
    sb_size: int                       # total record size in bytes
    ver_block: bytes                   # the 4-byte version block after magic
    ctree_count: int                   # number of ctree slots present
    ctree_max: int                     # max ctree slots
    seq: int                           # commit sequence (BE u32)
    ctree_size_hint: int               # LSM compaction ctree size target
    key_length: int                    # per-record key bytes
    value_length: int                  # per-record value bytes
    ctrees: Tuple[CTreeRef, ...]
    memtree_encoding: int              # 0=raw, 1=LZ4, 0x80-bit = encrypted
    memtree_node_count: int            # # entries in residual mem-tree
    memtree_extra_len: int             # extra payload bytes after fixed L-SB
    memtree_pages_total: int           # cumulative pages contributing
    memtree_extra_payload: bytes       # raw extra payload bytes (may be LZ4)
    tlv_index: int = -1                # TLV slot index this came from
    name: str = ""                     # canonical tree name (best-effort)

    # Legacy fields preserved for callers of the previous parser.
    @property
    def nr_ctree(self) -> int:
        """Number of non-empty ctree slots."""
        return sum(1 for c in self.ctrees if c.offset is not None)

    @property
    def nr_max_ctree(self) -> int:    # legacy alias
        return self.ctree_max

    @property
    def max_ext_len(self) -> int:     # legacy alias
        return self.memtree_extra_len

    @property
    def c0_count(self) -> int:        # legacy alias
        return self.memtree_node_count

    @property
    def c0_blob(self) -> bytes:       # legacy alias
        return self.memtree_extra_payload

    @property
    def has_disk_runs(self) -> bool:
        return any(c.offset is not None for c in self.ctrees)

    @property
    def primary_root_page(self) -> Optional[int]:
        for c in self.ctrees:
            if c.offset is not None:
                return c.root_page
        return None


def parse_lsb(arch_body: bytes, magic_offset: int, arch_page: int,
              tlv_index: int = -1, sb_size: Optional[int] = None
              ) -> LsmSuperblock:
    """Parse a single L-SB record at ``magic_offset`` in ``arch_body``.

    The L-SB layout is documented in
    ``docs/legacy/ARCHIVE3_LSM_SUPERBLOCK.md``. ``sb_size`` is the
    total record byte length (= TLV payload length); when omitted, the
    parser infers a minimum of 0x178 bytes (L-SB has no self-length
    field — it relies on the enclosing TLV ``length`` to bound the
    extra-payload area).
    """
    p = magic_offset
    if arch_body[p : p + 4] != INNER_MAGIC_LSB:
        raise ValueError(f"L-SB magic missing at +{p:#x}")
    if sb_size is None:
        sb_size = 0x178

    ver_block = arch_body[p + 4 : p + 8]
    fmt_ver = ver_block[0]
    ctree_count_minus_2 = ver_block[1]
    ctree_max_minus_2 = ver_block[2]
    ctree_count = ctree_count_minus_2 + 2
    ctree_max = ctree_max_minus_2 + 2

    seq = struct.unpack(">I", arch_body[p + 8 : p + 12])[0]
    ctree_size_hint = struct.unpack(">I", arch_body[p + 12 : p + 16])[0]
    key_length = struct.unpack(">I", arch_body[p + 16 : p + 20])[0]
    value_length = struct.unpack(">I", arch_body[p + 20 : p + 24])[0]

    SENTINEL = 0xFFFFFFFFFFFFFFFF
    ctrees: List[CTreeRef] = []
    for ci in range(ctree_count):
        slot_off = p + 0x18 + ci * 32
        if slot_off + 32 > p + sb_size:
            break
        root_off = struct.unpack(">Q", arch_body[slot_off : slot_off + 8])[0]
        num_pages = struct.unpack(">Q", arch_body[slot_off + 8 : slot_off + 16])[0]
        item_count = struct.unpack(">I", arch_body[slot_off + 16 : slot_off + 20])[0]
        # +20..+24 is reserved/zero
        max_key = struct.unpack(">Q", arch_body[slot_off + 24 : slot_off + 32])[0]
        # Two encodings of "empty": the explicit 0xFF.. sentinel (slot
        # was once populated, then compacted away) and a plain zero
        # offset (slot was never used — these tail the array when
        # ``ctree_count`` over-counts the active runs).
        empty = (root_off == SENTINEL) or (
            root_off == 0 and num_pages == 0 and item_count == 0
        )
        ctrees.append(CTreeRef(
            offset=None if empty else root_off,
            num_pages=num_pages,
            item_count=item_count,
            max_key_or_size=max_key,
        ))

    # Mem-tree fields at +0x158..+0x178 (only valid if sb_size >= 0x178).
    memtree_encoding = 0
    memtree_node_count = 0
    memtree_extra_len = 0
    memtree_pages_total = 0
    if p + 0x178 <= len(arch_body) and sb_size >= 0x178:
        memtree_encoding = arch_body[p + 0x158]
        memtree_node_count = struct.unpack(">H", arch_body[p + 0x15a : p + 0x15c])[0]
        memtree_extra_len = struct.unpack(">I", arch_body[p + 0x15c : p + 0x160])[0]
        memtree_pages_total = struct.unpack(">I", arch_body[p + 0x160 : p + 0x164])[0]

    extra_start = p + 0x178
    extra_end = p + sb_size
    memtree_extra_payload = arch_body[extra_start : extra_end] if extra_end > extra_start else b""

    name = TLV_TREE_NAMES.get(tlv_index, "")

    return LsmSuperblock(
        arch_page=arch_page,
        body_offset=p,
        sb_size=sb_size,
        ver_block=ver_block,
        ctree_count=ctree_count,
        ctree_max=ctree_max,
        seq=seq,
        ctree_size_hint=ctree_size_hint,
        key_length=key_length,
        value_length=value_length,
        ctrees=tuple(ctrees),
        memtree_encoding=memtree_encoding,
        memtree_node_count=memtree_node_count,
        memtree_extra_len=memtree_extra_len,
        memtree_pages_total=memtree_pages_total,
        memtree_extra_payload=memtree_extra_payload,
        tlv_index=tlv_index,
        name=name,
    )


def find_lsb_records(arch_body: bytes) -> List[Tuple[int, int]]:
    """Locate every ``L-SB`` magic in ``arch_body``.

    Returns ``(magic_offset, sb_size_hint)`` pairs ordered by occurrence.
    The size hint is best-effort (extra-payload length parsed from
    +0x15c) and may be smaller than the enclosing TLV slot's length.

    .. note::

       Modern callers should use :func:`read_archive_header` which
       walks the TLV directory directly and gives precise per-slot
       payload lengths. This function is preserved for ad-hoc
       byte-level scans.
    """
    out: List[Tuple[int, int]] = []
    for m in re.finditer(re.escape(INNER_MAGIC_LSB), arch_body):
        p = m.start()
        if p + 0x178 > len(arch_body):
            continue
        # Best-effort sb_size: 0x178 + extra_len at +0x15c.
        try:
            extra_len = struct.unpack(">I", arch_body[p + 0x15c : p + 0x160])[0]
        except struct.error:
            extra_len = 0
        out.append((p, 0x178 + extra_len))
    return out


def parse_all_lsbs(arch_body: bytes, arch_page: int) -> List[LsmSuperblock]:
    """Parse every L-SB record in ``arch_body``, in disk order.

    Legacy entry point. New code should use :func:`read_archive_header`
    which walks the TLV directory and assigns each L-SB the correct
    TLV slot index + canonical name.
    """
    return [
        parse_lsb(arch_body, off, arch_page, sb_size=sz)
        for off, sz in find_lsb_records(arch_body)
    ]


# --- ARCH header reader (multi-page-aware) -------------------------------


@dataclass(frozen=True)
class TlvSlot:
    """One TLV directory entry from the ARCH header."""
    index: int               # 0..18
    offset: int              # body offset of the length field
    length: int              # payload length in bytes
    payload: bytes           # raw payload bytes


@dataclass
class ArchiveHeader:
    """Decoded archive header: fixed record + 19 TLV slots + LSM trees."""
    arch_page: int                       # latest ARCH page index
    body: bytes                          # concatenated body of arch + continuation pages
    hdr_size: int                        # header byte length (=0x400 + TLV area)
    hdr_version: int                     # header version (8 in v8 archives)
    tlv: Tuple[TlvSlot, ...]             # 19 slots (some empty if version-skipped)
    lsm_trees: Tuple[LsmSuperblock, ...] # one per L-SB-bearing TLV slot


def _arch_seq(body: bytes) -> int:
    if len(body) < 0x190:
        return 0
    return struct.unpack(">Q", body[0x188:0x190])[0]


def find_latest_arch_page(reader) -> Tuple[int, bytes]:
    """Return ``(page_idx, full_body)`` for the latest ARCH header.

    Walks the tail of the file looking for ARCH pages and picks the one
    with the highest commit sequence. The body is the **full** header,
    concatenated across continuation pages (per `hdr_size` at body+4).
    """
    candidates: List[Tuple[int, bytes, int]] = []
    # Scan a generous tail window — header pages cluster near the end.
    scan_window = min(reader.page_count, 64)
    for p in range(reader.page_count - 1,
                   max(-1, reader.page_count - scan_window - 1), -1):
        ptype, body = reader.read_page(p, validate_crc=False)
        if ptype == PAGE_TYPE_ARCH and body[:4] == INNER_MAGIC_ARCH:
            candidates.append((p, body, _arch_seq(body)))
    if not candidates:
        raise ValueError("no ARCH page found in tail of archive")
    candidates.sort(key=lambda t: t[2])
    page_idx, body, _seq = candidates[-1]

    # Extend across continuation pages until we have hdr_size bytes.
    hdr_size = struct.unpack(">I", body[4:8])[0]
    full = bytearray(body)
    next_page = page_idx + 1
    while len(full) < hdr_size and next_page < reader.page_count:
        ptype, more = reader.read_page(next_page, validate_crc=False)
        # Continuation pages also have type 0x01 (ARCH); their body is
        # raw header bytes (no inner magic).
        if ptype != PAGE_TYPE_ARCH:
            break
        full.extend(more)
        next_page += 1
    return page_idx, bytes(full[:hdr_size]) if hdr_size <= len(full) else bytes(full)


def parse_tlv_directory(arch_body: bytes) -> List[TlvSlot]:
    """Walk the 19-entry TLV directory at ``arch_body[0x400:hdr_size]``.

    Implements the version-conditional skip rules from
    ``ARCHIVE3_TLV_DIRECTORY.md``:

    =======  =========================
    Version  Indices zero-filled
    =======  =========================
    < 7      8, 12, 13, 14, 15, 16
    = 7      12, 13, 14, 15, 16
    >= 8     (none — all 19 parsed)
    =======  =========================
    """
    if len(arch_body) < 0x408:
        raise ValueError(f"arch body too short for TLV directory: {len(arch_body)} bytes")
    hdr_size = struct.unpack(">I", arch_body[4:8])[0]
    hdr_version = struct.unpack(">H", arch_body[8:10])[0]
    if hdr_version < 7:
        skip_set = {8, 12, 13, 14, 15, 16}
    elif hdr_version < 8:
        skip_set = {12, 13, 14, 15, 16}
    else:
        skip_set = set()

    p = 0x400
    end = min(hdr_size, len(arch_body))
    slots: List[TlvSlot] = []
    for i in range(19):
        if i in skip_set:
            slots.append(TlvSlot(index=i, offset=p, length=0, payload=b""))
            continue
        if p + 4 > end:
            slots.append(TlvSlot(index=i, offset=p, length=0, payload=b""))
            continue
        length = struct.unpack(">I", arch_body[p : p + 4])[0]
        payload = arch_body[p + 4 : p + 4 + length]
        slots.append(TlvSlot(index=i, offset=p, length=length, payload=bytes(payload)))
        stride = (length + 7) & ~3
        p += stride
    return slots


def read_archive_header(reader) -> ArchiveHeader:
    """Read & decode the full archive header (fixed record + TLV + LSMs)."""
    arch_page, body = find_latest_arch_page(reader)
    hdr_size = struct.unpack(">I", body[4:8])[0]
    hdr_version = struct.unpack(">H", body[8:10])[0]
    tlv_slots = parse_tlv_directory(body)
    # Slots 0..7 (and 8 if v>=7) are L-SB records.
    lsm_slots: List[LsmSuperblock] = []
    for slot in tlv_slots:
        if slot.length == 0 or slot.payload[:4] != INNER_MAGIC_LSB:
            continue
        if slot.index > 8:
            continue
        # Construct an L-SB by parsing relative to slot.payload.
        sb = parse_lsb(
            arch_body=slot.payload,
            magic_offset=0,
            arch_page=arch_page,
            tlv_index=slot.index,
            sb_size=slot.length,
        )
        # Adjust body_offset to absolute body position for diagnostics.
        sb_with_body_off = LsmSuperblock(
            arch_page=sb.arch_page,
            body_offset=slot.offset + 4,  # absolute offset in arch_body
            sb_size=sb.sb_size,
            ver_block=sb.ver_block,
            ctree_count=sb.ctree_count,
            ctree_max=sb.ctree_max,
            seq=sb.seq,
            ctree_size_hint=sb.ctree_size_hint,
            key_length=sb.key_length,
            value_length=sb.value_length,
            ctrees=sb.ctrees,
            memtree_encoding=sb.memtree_encoding,
            memtree_node_count=sb.memtree_node_count,
            memtree_extra_len=sb.memtree_extra_len,
            memtree_pages_total=sb.memtree_pages_total,
            memtree_extra_payload=sb.memtree_extra_payload,
            tlv_index=sb.tlv_index,
            name=sb.name,
        )
        lsm_slots.append(sb_with_body_off)
    return ArchiveHeader(
        arch_page=arch_page,
        body=body,
        hdr_size=hdr_size,
        hdr_version=hdr_version,
        tlv=tuple(tlv_slots),
        lsm_trees=tuple(lsm_slots),
    )


def read_lsm_superblocks(reader) -> List[LsmSuperblock]:
    """Convenience wrapper: return the list of L-SBs from the latest ARCH page.

    Legacy-compatible entry point.
    """
    return list(read_archive_header(reader).lsm_trees)


# --- LEAF / LDIR page envelope decoding ---------------------------------


@dataclass(frozen=True)
class LsmPageHeader:
    """Fixed-size header from a LEAF or LDIR page body."""

    magic: bytes            # b"LEAF" or b"LDIR"
    ver: int                # +0x04 (== 1)
    encoding: int           # +0x05 (0=raw, 1=LZ4, 0x80-bit = encrypted)
    level: int              # +0x06 BE u16 (low byte often page-tree depth)
    u_len: int              # +0x08 BE u32 — uncompressed payload length
    total_rec_len: int      # +0x0c BE u32 — = inner_LZ4_clen + 8 if LZ4
    page_id: int            # +0x10 BE u32
    sequence: int           # +0x14 BE u32
    page_type: int          # 0x03 LEAF or 0x04 LDIR

    # Legacy aliases for the old parser's field names.
    @property
    def reserved(self) -> int:
        return 0

    @property
    def count(self) -> int:
        # Old parser interpreted byte 7 as a "count"; that byte is
        # actually inside the BE u16 ``level`` field. Preserve as 0 for
        # compatibility.
        return 0

    @property
    def total_len(self) -> int:
        return self.u_len

    @property
    def payload_len(self) -> int:
        return self.total_rec_len

    @property
    def key_param(self) -> int:
        return self.page_id


def parse_leaf_header(body: bytes, page_type: int) -> LsmPageHeader:
    """Parse the 0x34-byte inner header of a LEAF or LDIR page."""
    if len(body) < 0x34:
        raise ValueError(f"LSM page body too short: {len(body)}")
    magic = body[:4]
    if magic not in (INNER_MAGIC_LEAF, INNER_MAGIC_LDIR):
        raise ValueError(f"unexpected LSM page magic {magic!r}")
    return LsmPageHeader(
        magic=bytes(magic),
        ver=body[4],
        encoding=body[5],
        level=struct.unpack(">H", body[6:8])[0],
        u_len=struct.unpack(">I", body[8:12])[0],
        total_rec_len=struct.unpack(">I", body[12:16])[0],
        page_id=struct.unpack(">I", body[16:20])[0],
        sequence=struct.unpack(">I", body[20:24])[0],
        page_type=page_type,
    )


def decode_lsm_page_payload(body: bytes) -> Tuple[LsmPageHeader, bytes]:
    """Return ``(header, decompressed_payload)`` for one LEAF/LDIR page.

    Handles ``encoding=0`` (raw) and ``encoding=1`` (Acronis LZ4 with
    the 8-byte ``[c_len][u_len]`` preamble at body+0x34). Encrypted
    pages (``encoding & 0x80``) raise :class:`NotImplementedError`.
    """
    page_type = PAGE_TYPE_LEAF if body[:4] == INNER_MAGIC_LEAF else PAGE_TYPE_LDIR
    hdr = parse_leaf_header(body, page_type)
    enc = hdr.encoding
    if enc & 0x80:
        raise NotImplementedError(
            f"encrypted LSM page (encoding=0x{enc:02x}) not supported"
        )
    if enc == 0:
        # Raw cells: the record area starts immediately after the 0x34
        # header. ``hdr.total_rec_len`` is the byte length.
        return hdr, body[0x34 : 0x34 + hdr.total_rec_len]
    if enc == 1:
        # LZ4 with 8-byte Acronis preamble.
        if len(body) < 0x3c:
            raise ValueError("LZ4 LSM page body too short for preamble")
        inner_clen = struct.unpack(">I", body[0x34:0x38])[0]
        inner_ulen = struct.unpack(">I", body[0x38:0x3c])[0]
        if 0x3c + inner_clen > len(body):
            raise ValueError(
                f"LZ4 frame extends past page body: c_len={inner_clen}, body={len(body)}"
            )
        try:
            import lz4.block  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "decoding LZ4-compressed LSM pages requires the 'lz4' package; "
                "install with `pip install lz4`"
            ) from e
        frame = body[0x3c : 0x3c + inner_clen]
        decoded = lz4.block.decompress(frame, uncompressed_size=inner_ulen)
        if len(decoded) != inner_ulen:
            raise ValueError(
                f"LZ4 decoded length {len(decoded)} != expected {inner_ulen}"
            )
        return hdr, decoded
    raise NotImplementedError(f"unknown LSM page encoding 0x{enc:02x}")


def parse_ldir_records(payload: bytes, key_length: int
                       ) -> List[Tuple[bytes, int]]:
    """Decode an LDIR page's payload into ``[(key, child_byte_offset)]``.

    Each record is ``[key (key_length bytes)][child_offset (BE u64)]``.
    Trailing zero padding (rare) is ignored.
    """
    rec_size = key_length + 8
    n = len(payload) // rec_size
    out: List[Tuple[bytes, int]] = []
    for i in range(n):
        rec = payload[i * rec_size : (i + 1) * rec_size]
        key = rec[:key_length]
        child_off = struct.unpack(">Q", rec[key_length:key_length + 8])[0]
        out.append((bytes(key), child_off))
    return out


# --- LEAF page cell decoder (delegated to lsm_cells) --------------------


def parse_leaf(body: bytes) -> List[Tuple[bytes, bytes]]:
    """Return decoded ``(key, value)`` pairs from a LEAF body.

    .. warning::

       The cell-payload decoder is **not yet implemented**; that work
       lives in the companion module :mod:`tibread.tibx.lsm_cells`.
       Until that lands, this function returns the LZ4-decompressed
       cell area as a single opaque entry so callers can drive
       end-to-end pipelines without crashing.
    """
    hdr, decoded = decode_lsm_page_payload(body)
    placeholder_key = bytes(
        [hdr.encoding, 0x00, *hdr.magic, *struct.pack(">I", hdr.u_len)]
    )
    return [(placeholder_key, decoded)]


# --- Tree walker --------------------------------------------------------


@dataclass
class CTreeWalkStats:
    """Per-ctree summary returned by :func:`walk_ctree`."""
    root_page: int
    levels_visited: int = 0
    ldir_pages: int = 0
    leaf_pages: int = 0
    ldir_entries: int = 0
    leaf_pages_reached: int = 0
    page_count_per_level: List[int] = field(default_factory=list)
    error: Optional[str] = None


def walk_ctree(reader, ctree: CTreeRef, key_length: int,
               max_depth: int = 8) -> CTreeWalkStats:
    """Walk one ctree top-down from its LDIR root.

    Reads the root page, decodes its LDIR records, then descends into
    the **first** child (depth-first along the leftmost path) until it
    reaches a LEAF page. This validates the LDIR/LEAF chain without
    requiring the LEAF cell decoder.
    """
    stats = CTreeWalkStats(root_page=ctree.root_page or 0)
    if ctree.offset is None:
        stats.error = "empty ctree"
        return stats
    cur_page = ctree.root_page
    if cur_page is None:
        stats.error = "no root page"
        return stats
    for depth in range(max_depth):
        try:
            ptype, body = reader.read_page(cur_page, validate_crc=False)
        except Exception as e:
            stats.error = f"read_page({cur_page}): {e}"
            return stats
        if ptype not in (PAGE_TYPE_LDIR, PAGE_TYPE_LEAF):
            stats.error = (
                f"page {cur_page} has type 0x{ptype:02x}, "
                f"expected LEAF/LDIR"
            )
            return stats
        try:
            hdr, payload = decode_lsm_page_payload(body)
        except Exception as e:
            stats.error = f"decode page {cur_page}: {e}"
            return stats
        stats.levels_visited += 1
        if ptype == PAGE_TYPE_LDIR:
            stats.ldir_pages += 1
            recs = parse_ldir_records(payload, key_length)
            stats.ldir_entries += len(recs)
            stats.page_count_per_level.append(len(recs))
            if not recs:
                stats.error = f"LDIR at page {cur_page} has 0 records"
                return stats
            # Descend leftmost child.
            cur_page = recs[0][1] // PAGE_SIZE
            continue
        else:  # LEAF
            stats.leaf_pages += 1
            stats.leaf_pages_reached += 1
            stats.page_count_per_level.append(len(payload))
            return stats
    stats.error = f"max_depth={max_depth} exhausted (last page {cur_page})"
    return stats


# Legacy header-only walker preserved for callers that just want a
# scan over a page range.
@dataclass
class LsmWalkStats:
    leaf_pages: int = 0
    ldir_pages: int = 0
    blob_pages: int = 0
    other_pages: int = 0
    headers: List[LsmPageHeader] = field(default_factory=list)


def walk_lsm_region(reader, start_page: int, end_page: int) -> LsmWalkStats:
    """Walk every page in ``[start_page, end_page)`` and tally header info."""
    stats = LsmWalkStats()
    for p in range(start_page, end_page):
        page_type, body = reader.read_page(p, validate_crc=False)
        if page_type == PAGE_TYPE_LEAF:
            stats.leaf_pages += 1
            try:
                stats.headers.append(parse_leaf_header(body, page_type))
            except ValueError:
                pass
        elif page_type == PAGE_TYPE_LDIR:
            stats.ldir_pages += 1
            try:
                stats.headers.append(parse_leaf_header(body, page_type))
            except ValueError:
                pass
        elif page_type == PAGE_TYPE_LSM5:
            stats.blob_pages += 1
        else:
            stats.other_pages += 1
    return stats


def walk_lsm_tree(reader, root_page: int, max_pages: int = 4096
                  ) -> Iterator[Tuple[bytes, bytes]]:
    """Yield ``(key, value)`` pairs from the LSM tree rooted at ``root_page``.

    Currently this only descends through LDIR/LEAF pages and yields the
    placeholder entries from :func:`parse_leaf` (the cell decoder is
    in ``lsm_cells``). Useful as a smoke test that pages decompress
    cleanly along the leftmost path.
    """
    pages_walked = 0
    cur_page = root_page
    while pages_walked < max_pages and 0 <= cur_page < reader.page_count:
        page_type, body = reader.read_page(cur_page, validate_crc=False)
        if page_type == PAGE_TYPE_LDIR:
            try:
                hdr, payload = decode_lsm_page_payload(body)
            except Exception:
                break
            # Need key_length to slice; default to 31 if unknown
            # (data_map's key length, the most common in practice).
            recs = parse_ldir_records(payload, 31)
            if not recs:
                break
            cur_page = recs[0][1] // PAGE_SIZE
            pages_walked += 1
            continue
        if page_type == PAGE_TYPE_LEAF:
            yield from parse_leaf(body)
            break
        break


__all__ = [
    "PAGE_TYPE_LDIR",
    "PAGE_TYPE_LSM_BLOB",
    "INNER_MAGIC_LDIR",
    "INNER_MAGIC_LEAF",
    "INNER_MAGIC_LSB",
    "LEAF_HEADER_FIXED_LEN",
    "LEAF_PAYLOAD_OFFSET",
    "LEAF_INNER_HEADER_LEN",
    "LEAF_LZ4_PREAMBLE_LEN",
    "LEAF_PAYLOAD_OFFSET_LZ4",
    "TLV_TREE_NAMES",
    "CTreeRef",
    "LsmSuperblock",
    "LsmPageHeader",
    "LsmWalkStats",
    "CTreeWalkStats",
    "TlvSlot",
    "ArchiveHeader",
    "find_lsb_records",
    "find_latest_arch_page",
    "parse_lsb",
    "parse_all_lsbs",
    "parse_tlv_directory",
    "parse_leaf_header",
    "parse_leaf",
    "parse_ldir_records",
    "decode_lsm_page_payload",
    "read_archive_header",
    "read_lsm_superblocks",
    "walk_ctree",
    "walk_lsm_region",
    "walk_lsm_tree",
]
