"""
tibread.tibx.format — on-disk constants for Acronis archive3 ``.tibx`` files.

The ``.tibx`` format is a 4 KiB-page store:

* every page begins with an 8-byte envelope ``41 <type> 00 00 <crc32c BE>``
* page-type bytes:

    ============  ====================================================
    ``0x01``      ARCH/QARCH archive header / metadata page
    ``0x02``      ARCI archive index / LSM root pointer page (commit info)
    ``0x03``      LEAF LSM-tree leaf page
    ``0x04``      LDIR LSM-tree directory / internal node
    ``0x05``      LSM5 (interleaved index region; semantics under RE)
    ``0xFF``      data page (Zstd segment header or continuation bytes)
    ============  ====================================================

Segment ("SG") records live inside type-``0xFF`` pages.  The 0x2C-byte
header is at offset +8 of the page; multi-byte length fields are
**big-endian**.

The page CRC at envelope offset +4 is **CRC-32C (Castagnoli)** stored
big-endian, computed over the full 4096-byte page with the CRC field
itself zero-filled.  Despite the libpcs symbol being named ``pcs_crc32``
(suggesting IEEE 802.3), empirical verification against the real archive
shows the polynomial is Castagnoli (reflected ``0x82F63B78``).  See
:func:`compute_page_crc32` and ``docs/legacy/ARCHIVE3_PAGE_VERIFY.md``.

See ``docs/legacy/RESEARCH_TIBX_STRUCTURE.md`` for the empirical decode
that backs every constant in this module.
"""

from __future__ import annotations

# --- page envelope -------------------------------------------------------

PAGE_SIZE = 4096
ENVELOPE_SIZE = 8           # 41 <type> 00 00 <crc32c BE>
PAGE_BODY_SIZE = PAGE_SIZE - ENVELOPE_SIZE  # 4088

PAGE_MAGIC_BYTE = 0x41

# Page type bytes (offset +1 of each page).
PAGE_TYPE_ARCH = 0x01       # archive header / metadata
PAGE_TYPE_ARCI = 0x02       # archive index (LSM root / commit info)
PAGE_TYPE_LEAF = 0x03       # LSM leaf
PAGE_TYPE_LDIR = 0x04       # LSM directory / internal node
PAGE_TYPE_LSM5 = 0x05       # interleaved-index region page (semantics TBD)
PAGE_TYPE_DATA = 0xFF       # data (SG segment header or continuation)

PAGE_TYPE_NAMES = {
    PAGE_TYPE_ARCH: "ARCH",
    PAGE_TYPE_ARCI: "ARCI",
    PAGE_TYPE_LEAF: "LEAF",
    PAGE_TYPE_LDIR: "LDIR",
    PAGE_TYPE_LSM5: "LSM5",
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


# --- page CRC (CRC-32C / Castagnoli) -------------------------------------

# CRC-32C (Castagnoli): polynomial 0x1EDC6F41, reflected input/output,
# init 0xFFFFFFFF, final XOR 0xFFFFFFFF.  Reflected polynomial constant
# is 0x82F63B78.  Verified empirically against ``example.tibx`` —
# every page's stored BE u32 at +0x04 matches CRC32C of the page with
# the CRC field zero-filled.

_CRC32C_POLY_REFLECTED = 0x82F63B78

# Build the byte-wise CRC32C table once, at import time.  This is small
# (1 KiB) and keeps the per-page hot loop in pure Python at a reasonable
# ~10 MiB/s, which is fine for spot-validation.  For full-file walks
# (~13 M pages × 4 KiB = 51 GiB) callers should prefer the optional
# ``crc32c`` C extension if installed; ``compute_page_crc32`` picks it up
# automatically.
_CRC32C_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ (_CRC32C_POLY_REFLECTED if _crc & 1 else 0)
    _CRC32C_TABLE.append(_crc & 0xFFFFFFFF)
_CRC32C_TABLE = tuple(_CRC32C_TABLE)
del _byte, _crc

# Optional C extension — `pip install crc32c` provides a SSE4.2-accelerated
# implementation at roughly 10 GiB/s on modern x86.  If absent we fall
# back to the pure-Python table.
try:  # pragma: no cover - optional fast path
    from crc32c import crc32c as _crc32c_native  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    _crc32c_native = None


def crc32c(data: bytes, init: int = 0) -> int:
    """Compute CRC-32C (Castagnoli) over ``data``.

    Parameters
    ----------
    data : bytes
        Buffer to checksum.
    init : int, optional
        Previous CRC for incremental computation (default 0 = fresh CRC).
        Treated identically to the ``value`` argument of
        :func:`zlib.crc32` — i.e. the *finalised* CRC of the bytes
        already consumed.  ``crc32c(b'', x) == x``.

    Returns
    -------
    int
        Unsigned 32-bit CRC value.
    """
    if _crc32c_native is not None and init == 0:
        # Fast path for the common single-shot call.
        return int(_crc32c_native(data)) & 0xFFFFFFFF

    crc = (~init) & 0xFFFFFFFF
    table = _CRC32C_TABLE
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF


def compute_page_crc32(page: bytes) -> int:
    """Return the CRC-32C of one 4096-byte page with bytes [4:8] zeroed.

    This is the algorithm used by the ``.tibx`` page envelope: the four
    CRC bytes at offset 0x04 are excluded from the CRC by zero-filling,
    and the CRC is computed over the entire 4 KiB page.  The result is
    compared against the big-endian u32 stored in those four bytes.

    Parameters
    ----------
    page : bytes
        Exactly :data:`PAGE_SIZE` (4096) bytes of one page.

    Returns
    -------
    int
        Unsigned 32-bit CRC-32C value.
    """
    if len(page) != PAGE_SIZE:
        raise ValueError(
            f"compute_page_crc32 expects exactly {PAGE_SIZE} bytes, "
            f"got {len(page)}"
        )
    # Build a copy with the CRC slot zero-filled, then CRC the whole page.
    buf = bytearray(page)
    buf[4:8] = b"\x00\x00\x00\x00"
    return crc32c(bytes(buf))


def read_stored_page_crc32(page: bytes) -> int:
    """Return the big-endian u32 CRC stored in the page envelope."""
    return int.from_bytes(page[4:8], "big")


__all__ = [
    "PAGE_SIZE",
    "ENVELOPE_SIZE",
    "PAGE_BODY_SIZE",
    "PAGE_MAGIC_BYTE",
    "PAGE_TYPE_ARCH",
    "PAGE_TYPE_ARCI",
    "PAGE_TYPE_LEAF",
    "PAGE_TYPE_LDIR",
    "PAGE_TYPE_LSM5",
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
    "crc32c",
    "compute_page_crc32",
    "read_stored_page_crc32",
]
