"""
tibread.tibx.format — on-disk constants for Acronis archive3 ``.tibx`` files.

The ``.tibx`` format is a 4 KiB-page store:

* every page begins with an 8-byte envelope ``41 <type> 00 00 <crc32 LE>``
* page-type bytes:

    ============  ====================================================
    ``0x01``      ARCH/QARCH archive header / metadata page
    ``0x02``      ARCI archive index / LSM root pointer page
    ``0x03``      LEAF LSM-tree leaf page
    ``0xFF``      data page (Zstd segment header or continuation bytes)
    ============  ====================================================

Segment ("SG") records live inside type-``0xFF`` pages.  The 0x2C-byte
header is at offset +8 of the page; multi-byte length fields are
**big-endian**.

See ``docs/legacy/RESEARCH_TIBX_STRUCTURE.md`` for the empirical decode
that backs every constant in this module.
"""

from __future__ import annotations

# --- page envelope -------------------------------------------------------

PAGE_SIZE = 4096
ENVELOPE_SIZE = 8           # 41 <type> 00 00 <crc32 LE>
PAGE_BODY_SIZE = PAGE_SIZE - ENVELOPE_SIZE  # 4088

PAGE_MAGIC_BYTE = 0x41

# Page type bytes (offset +1 of each page).
PAGE_TYPE_ARCH = 0x01       # archive header / metadata
PAGE_TYPE_ARCI = 0x02       # archive index (LSM root, B-tree style)
PAGE_TYPE_LEAF = 0x03       # LSM leaf
PAGE_TYPE_DATA = 0xFF       # data (SG segment header or continuation)

PAGE_TYPE_NAMES = {
    PAGE_TYPE_ARCH: "ARCH",
    PAGE_TYPE_ARCI: "ARCI",
    PAGE_TYPE_LEAF: "LEAF",
    PAGE_TYPE_DATA: "DATA",
}

# --- inner-page magics (at offset +8 of the page) ------------------------

INNER_MAGIC_QARCH = b"QARCH"            # only on page 0
INNER_MAGIC_ARCH = b"ARCH"
INNER_MAGIC_ARCI = b"ARCI"
INNER_MAGIC_LEAF = b"LEAF"
INNER_MAGIC_SG = b"SG\x00\x01"          # segment header, version 1

# --- SG segment record (offsets relative to start of page) ---------------

SG_HEADER_OFFSET = 8           # +8 from page start
SG_HEADER_SIZE = 0x2C - 8      # 36 bytes of fixed-format header
SG_PAYLOAD_OFFSET = 0x2C       # Zstd frame begins here on the SG page

# Field offsets inside the 0x2C SG header block (page-relative):
#   +0x08  4   "SG\x00\x01"
#   +0x0C  4   len   (BE u32)  uncompressed length
#   +0x10  4   zlen  (BE u32)  compressed length
#   +0x14  4   key   (BE u32)  encryption key id (0 = plaintext)
#   +0x18  2   comp  (BE u16)  compression variant (0x0300..0x0302 Zstd)
#   +0x1A  2   cache (BE u16)  cache hint flags
#   +0x1C 12   reserved/zero

# Compression variants observed in the wild.  All three are Zstd frames;
# the low byte appears to indicate the dictionary preset used by the
# Acronis encoder (no externally-supplied dictionary is needed to decode
# them — a stock zstd decompressor handles all three).
COMP_NONE = 0x0000              # stored (uncompressed); zlen == len
COMP_ZSTD_V0 = 0x0300
COMP_ZSTD_V1 = 0x0301
COMP_ZSTD_V2 = 0x0302
ZSTD_COMP_VARIANTS = frozenset({COMP_ZSTD_V0, COMP_ZSTD_V1, COMP_ZSTD_V2})

# Maximum number of compressed bytes that can fit on the SG page itself
# (after the page envelope and the SG header).  Subsequent compressed
# bytes spill onto continuation pages of type 0xFF without an inner
# magic, with each continuation page contributing PAGE_BODY_SIZE bytes.
SG_FIRST_PAGE_PAYLOAD_BYTES = PAGE_SIZE - SG_PAYLOAD_OFFSET  # 4052

# --- Zstd frame magic (informational) ------------------------------------

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


__all__ = [
    "PAGE_SIZE",
    "ENVELOPE_SIZE",
    "PAGE_BODY_SIZE",
    "PAGE_MAGIC_BYTE",
    "PAGE_TYPE_ARCH",
    "PAGE_TYPE_ARCI",
    "PAGE_TYPE_LEAF",
    "PAGE_TYPE_DATA",
    "PAGE_TYPE_NAMES",
    "INNER_MAGIC_QARCH",
    "INNER_MAGIC_ARCH",
    "INNER_MAGIC_ARCI",
    "INNER_MAGIC_LEAF",
    "INNER_MAGIC_SG",
    "SG_HEADER_OFFSET",
    "SG_HEADER_SIZE",
    "SG_PAYLOAD_OFFSET",
    "SG_FIRST_PAGE_PAYLOAD_BYTES",
    "COMP_NONE",
    "COMP_ZSTD_V0",
    "COMP_ZSTD_V1",
    "COMP_ZSTD_V2",
    "ZSTD_COMP_VARIANTS",
    "ZSTD_MAGIC",
]
