"""
tibread.tibx.disk_image — source-disk LBA -> segment lookup helpers.

This module is the **planned** entry point for reading the bytes of the
backed-up source disk via :class:`TibxReader`.  In a finished
implementation, ``read_lba_range(start_lba, length)`` walks the
``segment_map`` LSM tree (one of the seven LSM trees described in
``tibread.tibx.lsm``) to translate a source-disk byte range into a list
of ``(segment_id, offset_in_segment, length)`` tuples, decompresses the
referenced segments, and concatenates the requested bytes.

Status (as of April 2026)
-------------------------

The segment_map LSM tree's leaf-cell decoder is **not yet implemented**
(it requires the Acronis Golomb / LZ4 codec from ``lsm_golomb.c`` —
see :mod:`tibread.tibx.lsm`).  Until the cell decoder lands, this
module exposes only a *bootstrap* path:

* The very first SG segment in the file (the segment beginning at the
  first ``0xFF`` page after the header pages) is empirically the
  whole-disk MBR plus the first 256 KiB of source-disk content,
  uncompressed-length 262,144 bytes.
* :func:`read_lba_range` can therefore satisfy any read whose byte
  range falls entirely inside ``[0, 262144)`` of the source disk by
  returning bytes from that first segment.
* Reads that fall outside the bootstrap range raise
  :class:`ChunkMapNotImplemented` until the segment_map walker is
  finished.

This is enough to verify the MBR signature and to prove the read
plumbing end-to-end; arbitrary LBA reads will land once
:func:`tibread.tibx.lsm.parse_leaf` learns to decode cells.

Why there is no ``segment 3 = u16 chunk-id index``
--------------------------------------------------

Earlier exploratory notes hypothesised that the 4th SG segment in
``example.tibx`` (the 139,264-byte segment starting at page 9)
was a flat ``u16`` array mapping ``chunk_id -> segment_id``.  Empirical
inspection refutes this:

* The first 65,536 ``u16`` values *do* form a near-identity ramp
  (0, 1, 2, ..., 96, 65, 66, ..., 90, 123, ..., then a "paired
  doubling" pattern at index 256+) but the remaining 4,096 ``u16``
  values are clearly NTFS structures: at offset 0x20000 the bytes
  spell ``"INDX"`` followed by a valid NTFS index-buffer header
  (USA offset=40, USA count=9, allocated-size=4072), and at offset
  0xa485 there is an ``"RCRD"`` tag (NTFS $LogFile record).  An
  ``INDX`` record at byte offset 131072 of a "u16 chunk index" would
  be inexplicable; in NTFS metadata it is unsurprising.
* The total decompressed length (139,264 bytes) is not a power of two
  and does not match any plausible chunk-count for a 51 GB archive
  (which at the empirically observed maximum segment size of 512 KiB
  would have ~100,000 chunks, not 65,536 or 69,632).
* Segment lengths in the wild are highly variable: scanning 3,493 SG
  segments shows lengths ranging from 4,096 to 524,288 bytes (mean
  209,610 bytes), with no fixed chunk size.  A flat
  ``chunk_id -> segment_id`` array therefore cannot exist — the
  archive uses a **variable-length extent map** keyed on source
  byte-range, not a fixed-stride chunk array.

The authoritative chunk -> segment mapping lives in the
``segment_map`` LSM tree (L-SB index 2 in ``example.tibx``, root
page 13,347,532).  Decoding that tree's cells is the next step on the
critical path.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Tuple

from .segment import SgSegment

if TYPE_CHECKING:  # pragma: no cover
    from .reader import TibxReader


# Empirical: the first SG segment in example.tibx covers source-disk
# bytes [0, BOOTSTRAP_LEN).  The value is the segment's ``length`` field.
BOOTSTRAP_LEN = 262_144  # 256 KiB

# Sector size for translating between LBA and byte offsets.
DEFAULT_SECTOR_SIZE = 512


class ChunkMapNotImplemented(NotImplementedError):
    """Raised when a logical-disk read requires the segment_map LSM walk.

    The segment_map LSM tree's cell decoder (Acronis Golomb / LZ4) is
    not yet implemented in this package.  Until it lands, only reads
    inside the bootstrap range ``[0, BOOTSTRAP_LEN)`` of the source
    disk are supported by :func:`read_lba_range`.
    """


def _bootstrap_segment(reader: "TibxReader") -> Optional[SgSegment]:
    """Return the first SG segment in the archive, or ``None``.

    The first segment is empirically the source-disk MBR plus the first
    256 KiB of disk content (uncompressed length 262,144 bytes,
    Zstd-compressed in the file).  We locate it by scanning the early
    pages with the standard segment iterator and returning the first
    hit.
    """
    for seg in reader.find_segments(page_range=range(0, 64)):
        return seg
    return None


def read_lba_range(
    reader: "TibxReader",
    start_lba: int,
    length: int,
    *,
    sector_size: int = DEFAULT_SECTOR_SIZE,
) -> bytes:
    """Read ``length`` bytes from the source disk starting at ``start_lba``.

    Parameters
    ----------
    reader : TibxReader
        An open :class:`tibread.tibx.TibxReader`.
    start_lba : int
        Source-disk Logical Block Address (LBA) of the first byte to
        return.  An LBA is ``sector_size`` bytes (default 512).
    length : int
        Number of bytes to return.  Must be > 0.
    sector_size : int, optional
        Bytes per LBA.  Defaults to 512, matching the Example source
        disk's MBR layout.

    Returns
    -------
    bytes
        Exactly ``length`` bytes from the source disk image.

    Raises
    ------
    ChunkMapNotImplemented
        If the requested range extends past the bootstrap region
        (``[0, BOOTSTRAP_LEN)``) — full random access requires the
        segment_map LSM walker, which is not yet implemented.
    ValueError
        On invalid arguments.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if start_lba < 0:
        raise ValueError(f"start_lba must be non-negative, got {start_lba}")

    start_byte = start_lba * sector_size
    end_byte = start_byte + length

    if end_byte > BOOTSTRAP_LEN:
        raise ChunkMapNotImplemented(
            f"read_lba_range: range [{start_byte}, {end_byte}) extends past "
            f"the bootstrap segment ([0, {BOOTSTRAP_LEN})). The segment_map "
            f"LSM tree walker is required for arbitrary random access and "
            f"is not yet implemented (see tibread.tibx.lsm.parse_leaf)."
        )

    seg = _bootstrap_segment(reader)
    if seg is None:
        raise IOError("no SG segment found in archive head — file may be malformed")
    if seg.length < BOOTSTRAP_LEN:
        raise IOError(
            f"first SG segment is unexpectedly short ({seg.length} bytes); "
            f"expected at least {BOOTSTRAP_LEN}"
        )

    plaintext = reader.decompress_segment(seg)
    if len(plaintext) < end_byte:
        raise IOError(
            f"bootstrap segment shorter than expected: "
            f"have {len(plaintext)} bytes, need {end_byte}"
        )
    return plaintext[start_byte:end_byte]


def lookup_chunk_via_segment_map(
    reader: "TibxReader", source_byte_offset: int
) -> Tuple[int, int, int]:
    """Resolve a source-disk byte offset to ``(segment_id, off, len)``.

    .. warning::

        Not yet implemented.  This is a placeholder describing the
        eventual API once the ``segment_map`` LSM-tree leaf decoder
        lands in :func:`tibread.tibx.lsm.parse_leaf`.  Calling it
        currently raises :class:`ChunkMapNotImplemented`.

    Parameters
    ----------
    reader : TibxReader
        Reader whose archive contains the LSM index to walk.
    source_byte_offset : int
        Byte offset on the source disk.

    Returns
    -------
    (segment_id, offset_in_segment, available_length)
        Locator triple for the segment containing the requested byte.
    """
    raise ChunkMapNotImplemented(
        "lookup_chunk_via_segment_map: requires segment_map LSM cell decoder"
    )


__all__ = [
    "BOOTSTRAP_LEN",
    "DEFAULT_SECTOR_SIZE",
    "ChunkMapNotImplemented",
    "read_lba_range",
    "lookup_chunk_via_segment_map",
]
