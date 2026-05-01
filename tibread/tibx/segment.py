"""
tibread.tibx.segment — SG segment record parsing and decompression.

A "segment" is the unit of bulk data storage in a ``.tibx`` file.  It
consists of a 0x2C-byte SG header followed by a Zstd frame whose
compressed length is given by ``zlen``.  When ``zlen`` exceeds the bytes
available on the segment's first page (4052 bytes), the frame spills
onto subsequent type-``0xFF`` pages whose own 8-byte envelopes are
stripped before the bytes are concatenated.

This module exposes:

* :class:`SgSegment` — a small dataclass describing a parsed segment
  header together with the page index it lives on.
* :func:`parse_sg_header` — decode the 0x2C-byte SG header from a page.
* :func:`decompress_segment` — read continuation pages, strip envelopes,
  and Zstd-decompress to the segment's plaintext payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

import zstandard as zstd

from .format import (
    COMP_NONE,
    ENVELOPE_SIZE,
    INNER_MAGIC_SG,
    PAGE_BODY_SIZE,
    PAGE_SIZE,
    PAGE_TYPE_DATA,
    SG_FIRST_PAGE_PAYLOAD_BYTES,
    SG_HEADER_OFFSET,
    SG_PAYLOAD_OFFSET,
    ZSTD_COMP_VARIANTS,
)


@dataclass(frozen=True)
class SgSegment:
    """One parsed SG segment header.

    Attributes
    ----------
    page_idx : int
        Index of the page that begins this segment (offset = page_idx * 4096).
    length : int
        Uncompressed payload size in bytes.
    zlen : int
        Compressed payload size in bytes (size of the Zstd frame).
    key : int
        Encryption key id.  ``0`` means plaintext (no AES wrapping).
    comp : int
        Compression variant.  ``0x0300`` / ``0x0301`` / ``0x0302`` are
        the three Zstd presets seen in the wild.
    cache : int
        Cache hint flags (parsed but not interpreted).
    """

    page_idx: int
    length: int
    zlen: int
    key: int
    comp: int
    cache: int

    @property
    def file_offset(self) -> int:
        """Absolute byte offset of the segment's start-of-page in the file."""
        return self.page_idx * PAGE_SIZE

    @property
    def payload_offset(self) -> int:
        """Absolute byte offset of the first compressed byte (Zstd frame start)."""
        return self.file_offset + SG_PAYLOAD_OFFSET

    @property
    def is_plaintext(self) -> bool:
        return self.key == 0

    @property
    def is_zstd(self) -> bool:
        return self.comp in ZSTD_COMP_VARIANTS

    @property
    def is_stored(self) -> bool:
        """True for ``comp=0x0000`` segments where the payload is not compressed."""
        return self.comp == COMP_NONE

    def page_span(self) -> int:
        """Number of pages this segment occupies (header + continuation)."""
        if self.zlen <= SG_FIRST_PAGE_PAYLOAD_BYTES:
            return 1
        remaining = self.zlen - SG_FIRST_PAGE_PAYLOAD_BYTES
        # Each continuation page contributes PAGE_BODY_SIZE = 4088 bytes.
        return 1 + (remaining + PAGE_BODY_SIZE - 1) // PAGE_BODY_SIZE


def parse_sg_header(page_bytes: bytes, page_idx: int) -> Optional[SgSegment]:
    """Parse the 0x2C-byte SG header from a 4 KiB page.

    Parameters
    ----------
    page_bytes : bytes
        Exactly ``PAGE_SIZE`` (4096) bytes of one page.
    page_idx : int
        Index of this page in the .tibx file.

    Returns
    -------
    SgSegment or None
        ``None`` if the page is not a type-``0xFF`` data page or lacks
        the ``SG\\x00\\x01`` inner magic.
    """
    if len(page_bytes) < SG_PAYLOAD_OFFSET:
        return None
    if page_bytes[0] != 0x41 or page_bytes[1] != PAGE_TYPE_DATA:
        return None
    if page_bytes[SG_HEADER_OFFSET : SG_HEADER_OFFSET + 4] != INNER_MAGIC_SG:
        return None

    # Big-endian fields, per archive3.dll format string
    # "magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u".
    length, zlen, key = struct.unpack(
        ">III", page_bytes[SG_HEADER_OFFSET + 4 : SG_HEADER_OFFSET + 16]
    )
    comp, cache = struct.unpack(
        ">HH", page_bytes[SG_HEADER_OFFSET + 16 : SG_HEADER_OFFSET + 20]
    )
    return SgSegment(
        page_idx=page_idx,
        length=length,
        zlen=zlen,
        key=key,
        comp=comp,
        cache=cache,
    )


def read_segment_compressed_bytes(
    file_obj, seg: SgSegment, *, file_size: Optional[int] = None
) -> bytes:
    """Read exactly ``seg.zlen`` raw (still-compressed) bytes for a segment.

    Walks the SG page plus as many continuation pages of type ``0xFF``
    (without an inner magic) as needed, stripping each page's 8-byte
    envelope before concatenating bytes.

    Parameters
    ----------
    file_obj : BinaryIO
        A seekable file open in binary mode.
    seg : SgSegment
        The parsed SG header for this segment.
    file_size : int, optional
        Total file size; used as a hard upper bound when scanning
        continuation pages.  If omitted, ``os.fstat`` is consulted.
    """
    if file_size is None:
        import os

        file_size = os.fstat(file_obj.fileno()).st_size

    parts: list[bytes] = []
    remaining = seg.zlen

    # First page contributes bytes from +SG_PAYLOAD_OFFSET to end-of-page.
    file_obj.seek(seg.file_offset + SG_PAYLOAD_OFFSET)
    first_chunk_len = min(SG_FIRST_PAGE_PAYLOAD_BYTES, remaining)
    chunk = file_obj.read(first_chunk_len)
    if len(chunk) != first_chunk_len:
        raise IOError(
            f"short read on SG page {seg.page_idx}: wanted "
            f"{first_chunk_len}, got {len(chunk)}"
        )
    parts.append(chunk)
    remaining -= first_chunk_len

    next_page_idx = seg.page_idx + 1
    while remaining > 0:
        page_off = next_page_idx * PAGE_SIZE
        if page_off + PAGE_SIZE > file_size:
            raise IOError(
                f"segment at page {seg.page_idx} runs off end of file "
                f"(needs continuation page {next_page_idx})"
            )
        file_obj.seek(page_off)
        page = file_obj.read(PAGE_SIZE)
        if len(page) != PAGE_SIZE:
            raise IOError(f"short page read at {page_off}")
        # Sanity check: continuation pages must be type 0xFF and
        # MUST NOT carry an SG inner magic (that would indicate the
        # previous segment had ended prematurely).
        if page[0] != 0x41 or page[1] != PAGE_TYPE_DATA:
            raise IOError(
                f"unexpected non-data page at {next_page_idx} "
                f"while reading continuation of segment at page {seg.page_idx} "
                f"(tag={page[:4].hex()})"
            )
        if page[SG_HEADER_OFFSET : SG_HEADER_OFFSET + 4] == INNER_MAGIC_SG:
            raise IOError(
                f"unexpected SG header on continuation page {next_page_idx}; "
                f"segment at page {seg.page_idx} has zlen={seg.zlen} but only "
                f"{seg.zlen - remaining} bytes were collected before this header"
            )

        body = page[ENVELOPE_SIZE:]
        take = min(len(body), remaining)
        parts.append(body[:take])
        remaining -= take
        next_page_idx += 1

    return b"".join(parts)


def decompress_segment(
    file_obj, seg: SgSegment, *, file_size: Optional[int] = None
) -> bytes:
    """Read and decompress one segment to its plaintext payload.

    Returns exactly ``seg.length`` bytes.  Raises ``NotImplementedError``
    for encrypted segments (``seg.key != 0``) or unknown compression
    variants — the format spec implies AES wrapping is *inside* the SG
    record, but no encrypted segment has been observed in the test
    archive (``Jmicron 0102.tibx`` is plaintext throughout).
    """
    if seg.key != 0:
        raise NotImplementedError(
            f"segment at page {seg.page_idx} is encrypted (key={seg.key}); "
            f"AES unwrap is not implemented"
        )

    raw = read_segment_compressed_bytes(file_obj, seg, file_size=file_size)
    if len(raw) != seg.zlen:
        raise IOError(
            f"payload length mismatch: read {len(raw)}, "
            f"expected zlen={seg.zlen}"
        )

    if seg.is_stored:
        # comp == 0x0000: payload is stored verbatim (zlen == len).
        if seg.zlen != seg.length:
            raise IOError(
                f"stored segment at page {seg.page_idx} has zlen={seg.zlen} "
                f"!= len={seg.length}"
            )
        return raw

    if not seg.is_zstd:
        raise NotImplementedError(
            f"segment at page {seg.page_idx} uses comp=0x{seg.comp:04x} "
            f"which is not a known compression variant"
        )

    decompressor = zstd.ZstdDecompressor()
    plaintext = decompressor.decompress(raw, max_output_size=seg.length)
    if len(plaintext) != seg.length:
        raise IOError(
            f"decompressed length mismatch: got {len(plaintext)}, "
            f"expected len={seg.length}"
        )
    return plaintext


__all__ = [
    "SgSegment",
    "parse_sg_header",
    "read_segment_compressed_bytes",
    "decompress_segment",
]
