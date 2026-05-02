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
    ``0x05``      GOLOMB Rice-coded delta-encoded sorted-hash dedup filter
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

import struct
from dataclasses import dataclass
from typing import List

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
PAGE_TYPE_GOLOMB = 0x05     # Golomb-Rice (M=256) sorted-hash dedup filter
PAGE_TYPE_DATA = 0xFF       # data (SG segment header or continuation)

# Back-compat alias — the page was originally documented as ``LSM5`` while
# its semantics were under RE. The current name is :data:`PAGE_TYPE_GOLOMB`,
# which matches the ``golomb.c`` writer in ``archive3.dll`` (function
# ``golomb_index_create`` and friends; v7 archive-upgrade log message
# ``"Upgrade ver.7: create golomb filter"``). Existing callers that import
# ``PAGE_TYPE_LSM5`` continue to work.  See ``ARCHIVE3_PAGE_05.md``.
PAGE_TYPE_LSM5 = PAGE_TYPE_GOLOMB

PAGE_TYPE_NAMES = {
    PAGE_TYPE_ARCH: "ARCH",
    PAGE_TYPE_ARCI: "ARCI",
    PAGE_TYPE_LEAF: "LEAF",
    PAGE_TYPE_LDIR: "LDIR",
    PAGE_TYPE_GOLOMB: "GOLOMB",
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

# Compression variants observed in the wild.  The high byte selects the
# compression family (0x03 = Zstd) and the low byte indexes a preset
# dictionary used by the Acronis encoder (no externally-supplied
# dictionary is needed to decode them — a stock zstd decompressor
# handles every observed Zstd preset).
#
# The Zstd preset list was empirically verified by walking every SG
# segment in the reference archive ``example.tibx`` (263,063
# segments total) and checking that every ``comp=0x03xx`` payload
# starts with the Zstd frame magic ``28 b5 2f fd`` and decompresses to
# ``len`` bytes.  Variant ``0x0303`` was missed by the original RE pass
# (only one segment uses it in the reference archive: page 13,346,697)
# and is added here so the reader covers the full population. See
# ``docs/legacy/STRESS_TEST_RESULTS.md`` for the full histogram.
COMP_NONE = 0x0000              # stored (uncompressed); zlen == len
COMP_ZSTD_V0 = 0x0300
COMP_ZSTD_V1 = 0x0301
COMP_ZSTD_V2 = 0x0302
COMP_ZSTD_V3 = 0x0303
ZSTD_COMP_VARIANTS = frozenset({
    COMP_ZSTD_V0,
    COMP_ZSTD_V1,
    COMP_ZSTD_V2,
    COMP_ZSTD_V3,
})

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


# --- TLV[9] meta_keys / TLV[18] volume_table ----------------------------

# TLV[9] holds a fixed-position array of NUL-terminated UTF-8 strings,
# parallel to the in-binary ``ar_meta_keys`` global table. Per the
# decompilation of ``archive3.dll`` (loader ``FUN_1800155d0``) the
# loader iterates the blob with ``memchr(.., 0, ..)`` and writes the
# resulting strings into ``arch+0x1da8`` (a 20-entry table). Empty
# slots (consecutive NUL bytes) represent meta-keys whose value is not
# populated for this archive.  See ``ARCHIVE3_TLV_DIRECTORY.md``.
META_KEYS_MAX = 20

# Empirical positional → key-name mapping observed on
# ``example.tibx`` (header_version=8). The slot indices line up
# with ``ar_meta_keys``; positions where the test archive carries a
# value give us the key name. Unobserved positions are left blank
# until another sample archive populates them.
META_KEY_NAMES: tuple[str, ...] = (
    "type",            # 0  e.g. "disk", "volume"
    "",                # 1  (empty in test archive)
    "",                # 2
    "disk_guid",       # 3  source disk UUID
    "hostname",        # 4
    "agent_build",     # 5  product name + version
    "",                # 6
    "",                # 7
    "",                # 8
    "",                # 9
    "install_guid",    # 10 Acronis install UUID
    "",                # 11
    "",                # 12
    "",                # 13
    "",                # 14
    "",                # 15
    "",                # 16
    "",                # 17
    "",                # 18
    "",                # 19
)


def parse_meta_keys(blob: bytes) -> List[str]:
    """Parse a TLV[9] ``meta_keys`` payload into its per-slot strings.

    Each slot is one NUL-terminated UTF-8 string, and the slots are
    *positional* — empty slots (back-to-back NUL bytes) represent
    meta-keys whose value is not stored for this archive. The loader
    consumes at most :data:`META_KEYS_MAX` slots.

    Parameters
    ----------
    blob : bytes
        The raw TLV[9] payload (the bytes between the TLV length field
        and the next TLV slot's length field).

    Returns
    -------
    list[str]
        A list of decoded UTF-8 strings, one per consumed slot. Empty
        slots are returned as the empty string. The list length is
        bounded by :data:`META_KEYS_MAX`.
    """
    out: List[str] = []
    pos = 0
    while pos < len(blob) and len(out) < META_KEYS_MAX:
        end = blob.find(b"\x00", pos)
        if end == -1:
            # Trailing run with no NUL — treat as a final entry.
            out.append(blob[pos:].decode("utf-8", errors="replace"))
            break
        out.append(blob[pos:end].decode("utf-8", errors="replace"))
        pos = end + 1
    return out


def parse_meta_keys_dict(blob: bytes) -> dict[str, str]:
    """Like :func:`parse_meta_keys`, but tagged with the key names.

    Uses :data:`META_KEY_NAMES` to label each non-empty slot. Slots
    whose key name is unknown (still blank in :data:`META_KEY_NAMES`)
    are tagged ``"slot_<i>"`` so callers don't lose them.
    """
    values = parse_meta_keys(blob)
    out: dict[str, str] = {}
    for i, val in enumerate(values):
        if not val:
            continue
        name = META_KEY_NAMES[i] if i < len(META_KEY_NAMES) and META_KEY_NAMES[i] else f"slot_{i}"
        out[name] = val
    return out


@dataclass(frozen=True)
class VolumeTableEntry:
    """One TLV[18] ``volume_table`` record.

    On-disk layout is 12 bytes: ``{BE u32 idx, BE u64 byte_offset}``.
    ``idx`` is a per-archive volume index (0-based); ``byte_offset`` is
    the source-disk byte offset where the volume's first sector lives.

    Empirically (e.g. ``example.tibx``) a whole-disk image archive
    carries a single ``(idx=0, byte_offset=0)`` record — i.e. one
    "volume" covering the entire disk. Per-partition archives are
    expected to carry one record per partition with the byte offsets
    matching the MBR partition table, but no such sample has been
    confirmed yet.
    """

    idx: int
    byte_offset: int


def parse_volume_table(blob: bytes) -> List[VolumeTableEntry]:
    """Parse a TLV[18] ``volume_table`` payload into 12-byte records.

    Returns an empty list when the blob is empty or its length is not
    a multiple of 12. Padding tail bytes (blob length not divisible by
    12) are silently dropped — they are not expected on disk but the
    parser is permissive to keep failure modes obvious upstream.
    """
    n = len(blob) // 12
    out: List[VolumeTableEntry] = []
    for i in range(n):
        rec = blob[i * 12 : (i + 1) * 12]
        idx, byte_offset = struct.unpack(">IQ", rec)
        out.append(VolumeTableEntry(idx=idx, byte_offset=byte_offset))
    return out


__all__ = [
    "PAGE_SIZE",
    "ENVELOPE_SIZE",
    "PAGE_BODY_SIZE",
    "PAGE_MAGIC_BYTE",
    "PAGE_TYPE_ARCH",
    "PAGE_TYPE_ARCI",
    "PAGE_TYPE_LEAF",
    "PAGE_TYPE_LDIR",
    "PAGE_TYPE_GOLOMB",
    "PAGE_TYPE_LSM5",       # back-compat alias for PAGE_TYPE_GOLOMB
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
    "COMP_ZSTD_V3",
    "ZSTD_COMP_VARIANTS",
    "ZSTD_MAGIC",
    "crc32c",
    "compute_page_crc32",
    "read_stored_page_crc32",
    "META_KEYS_MAX",
    "META_KEY_NAMES",
    "parse_meta_keys",
    "parse_meta_keys_dict",
    "VolumeTableEntry",
    "parse_volume_table",
]
