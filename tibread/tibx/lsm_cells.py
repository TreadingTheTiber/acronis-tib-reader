"""
tibread.tibx.lsm_cells - LEAF / LDIR cell-stream decoder.

This module decodes the per-page cell stream that lives inside the body of
a LEAF (page-type 0x03) or LDIR (page-type 0x04) page.  The encoding was
recovered by reverse-engineering ``archive3.dll`` (functions
``FUN_180046530``, ``FUN_1800462f0``, ``FUN_180043d10``, ``FUN_180046d00``,
``FUN_180046790`` -- LSM page-read pipeline).

Page-body layout (offsets relative to the LEAF/LDIR magic; this is the
form returned by :meth:`tibread.tibx.reader.TibxReader.read_page` -- i.e.
the outer page envelope has already been stripped):

::

    +0x00  4   magic               "LEAF" / "LDIR"
    +0x04  1   format version      (must be < 2)
    +0x05  1   encoding            low 7 bits = 0 raw, 1 LZ4; bit 7 = encrypted
    +0x06  2   cell_count          BE u16
    +0x08  4   uncompressed_size   BE u32   (size of decoded cell stream)
    +0x0C  4   on_disk_size        BE u32   (size of compressed stream
                                             on disk; equals body_size-0x34)
    +0x10  4   key_size_param      BE u32   (must equal the layer's expected
                                             key-prefix size)
    +0x14  4   sequence_id         LE u32
    +0x18 ..  zero pad
    +0x34 ..  cell stream (length = on_disk_size)

Cell-stream encoding
--------------------

After optional decryption (high bit of the encoding byte) and optional
decompression (low bits of the encoding byte) the result is a raw byte
buffer of ``uncompressed_size`` bytes that contains the cells.

* **encoding & 0x7f == 0**: stream is already raw; nothing to do.
* **encoding & 0x7f == 1**: stream is a sequence of independent LZ4 blocks,
  each prefixed by ``(comp_size_be_u32, decomp_size_be_u32)`` and using
  ``LZ4_decompress_safe_continue`` (each block sees the previously emitted
  buffer as its dictionary).
* **encoding & 0x80**: stream is encrypted with a key set by
  ``archive_set_compatibility(... encryption ...)``.  Not implemented here
  (the encryption hook is per-archive and per-key).

Once the raw cell buffer is obtained, the cells themselves are encoded as:

* For LDIR pages and LEAF pages with ``fixed_key_size == 0``:
  variable-length ``(leb128 key_len, leb128 val_len, key, val)`` records
  packed back-to-back.  No deletion bitmap.

* For LEAF pages with ``fixed_key_size != 0``:
  "compact" mode -- cells are grouped into runs of up to 24, each group
  preceded by a 4-byte header laid out as a little-endian u32 where the
  low byte is ``group_count`` (1..24) and the upper 24 bits are an
  alive-bitmap (bit 0 = first cell, ``1`` = cell carries a value, ``0`` =
  tombstone, no value bytes follow the key).  Within a group, every alive
  cell is ``fixed_key_size`` bytes of key followed by ``fixed_val_size``
  bytes of value; tombstone cells are just the ``fixed_key_size`` bytes of
  key.

LDIR pages always use ``fixed_val_size = 8`` (an 8-byte child page id).
LEAF pages use the per-tree ``fixed_key_size`` / ``fixed_val_size`` taken
from the L-SB superblock that owns the tree (offsets +0x10 / +0x14 in the
L-SB record).

References
----------
* archive3.dll: ``FUN_180046530`` (header validate),
  ``FUN_1800462f0`` (decode + decompress dispatch),
  ``FUN_180046790`` (multi-block LZ4),
  ``FUN_180043d10`` (cell loop + compact group header),
  ``FUN_180046d00`` (variable leb128 record).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import lz4.block as _lz4_block
except ImportError:  # pragma: no cover - lz4 is required for non-raw pages
    _lz4_block = None


LSM_PAGE_HEADER_LEN = 0x34    # cell stream begins this many bytes after the magic


@dataclass(frozen=True)
class LsmInnerHeader:
    """Fields parsed from the inner LEAF/LDIR page header (at body+8)."""

    magic: bytes              # b"LEAF" or b"LDIR"
    version: int              # +0x04
    encoding: int             # +0x05  (low 7 bits, bit 7 = encrypted)
    cell_count: int           # +0x06 BE u16
    uncompressed_size: int    # +0x08 BE u32
    on_disk_size: int         # +0x0C BE u32
    key_size_param: int       # +0x10 BE u32
    sequence_id: int          # +0x14 LE u32

    @property
    def is_encrypted(self) -> bool:
        return bool(self.encoding & 0x80)

    @property
    def codec(self) -> int:
        """Codec id (low 7 bits): 0 = raw, 1 = multi-block LZ4."""
        return self.encoding & 0x7F


@dataclass(frozen=True)
class LsmCell:
    """One decoded cell.  ``alive`` is False for tombstones (deletes)."""

    key: bytes
    value: bytes
    alive: bool


def parse_inner_header(page_body: bytes) -> LsmInnerHeader:
    """Parse the LEAF/LDIR header at the start of ``page_body``."""
    if len(page_body) < 0x18:
        raise ValueError("page body too short for LSM header")
    h = page_body
    magic = bytes(h[:4])
    if magic not in (b"LEAF", b"LDIR"):
        raise ValueError(f"not a LEAF/LDIR page: magic={magic!r}")
    return LsmInnerHeader(
        magic=magic,
        version=h[4],
        encoding=h[5],
        cell_count=struct.unpack(">H", h[6:8])[0],
        uncompressed_size=struct.unpack(">I", h[8:12])[0],
        on_disk_size=struct.unpack(">I", h[12:16])[0],
        key_size_param=struct.unpack(">I", h[16:20])[0],
        sequence_id=struct.unpack("<I", h[20:24])[0],
    )


def _decompress_lz4_multiblock(stream: bytes, total_out: int) -> bytes:
    """Decode the multi-block LZ4 frame used by ``encoding & 0x7f == 1``.

    Each block in the stream is laid out as::

        +0  4   compressed_size    BE u32
        +4  4   uncompressed_size  BE u32
        +8  N   LZ4 block payload  (N = compressed_size)

    Successive blocks are dependent: the decoder uses the previously
    emitted bytes as its dictionary (``LZ4_decompress_safe_continue``).
    """
    if _lz4_block is None:
        raise RuntimeError("python-lz4 is required to decode LZ4 LSM pages")
    out = bytearray()
    pos = 0
    while pos < len(stream):
        if pos + 8 > len(stream):
            raise ValueError(f"truncated LZ4 frame at {pos}")
        cs = struct.unpack(">I", stream[pos:pos + 4])[0]
        ds = struct.unpack(">I", stream[pos + 4:pos + 8])[0]
        pos += 8
        if pos + cs > len(stream):
            raise ValueError(f"LZ4 block extends past stream ({cs} > {len(stream)-pos})")
        block = bytes(stream[pos:pos + cs])
        pos += cs
        # Use the last <= 64 KiB of output as the LZ4 history dictionary.
        history = bytes(out[-65536:]) if out else b""
        chunk = _lz4_block.decompress(
            block, uncompressed_size=ds, dict=history,
        )
        if len(chunk) != ds:
            raise ValueError(
                f"LZ4 block decoded {len(chunk)} bytes, expected {ds}"
            )
        out += chunk
    if len(out) != total_out:
        raise ValueError(
            f"LZ4 frame total {len(out)} != header uncompressed_size {total_out}"
        )
    return bytes(out)


def decode_cell_stream(page_body: bytes,
                       header: Optional[LsmInnerHeader] = None,
                       decrypt=None) -> bytes:
    """Return the raw decoded cell-buffer bytes from a LEAF/LDIR page body.

    Parameters
    ----------
    page_body
        The page body slice as returned by
        :meth:`tibread.tibx.reader.TibxReader.read_page`: 4088 bytes
        starting at the LEAF/LDIR magic (the outer 8-byte envelope has
        already been stripped).
    header
        Optional pre-parsed header; if omitted the function will parse it.
    decrypt
        Optional callable ``(ciphertext, length) -> plaintext`` used when
        ``header.is_encrypted``; mirrors the per-archive
        ``lsm->decrypt_cb`` hook in ``archive3.dll``.  Raises if the page
        is encrypted and no callback is provided.

    Returns
    -------
    bytes
        ``header.uncompressed_size`` bytes of raw cell data, ready to be
        passed to :func:`decode_cells`.
    """
    if header is None:
        header = parse_inner_header(page_body)
    stream_start = LSM_PAGE_HEADER_LEN
    stream = page_body[stream_start:stream_start + header.on_disk_size]

    # Optional decrypt step.
    if header.is_encrypted:
        if decrypt is None:
            raise NotImplementedError(
                "encrypted LSM page; provide decrypt= callback"
            )
        stream = decrypt(stream, header.on_disk_size)

    codec = header.codec
    if codec == 0:
        if len(stream) != header.uncompressed_size:
            raise ValueError(
                f"raw page: on_disk_size={len(stream)} != "
                f"uncompressed_size={header.uncompressed_size}"
            )
        return bytes(stream)
    if codec == 1:
        return _decompress_lz4_multiblock(stream, header.uncompressed_size)
    raise NotImplementedError(f"unknown LSM page codec {codec}")


# --- cell-record parsers --------------------------------------------------


def _read_leb128(buf: bytes, p: int) -> Tuple[int, int]:
    """Decode a 7-bit-per-byte little-endian LEB128 unsigned integer."""
    v = 0
    shift = 0
    while True:
        if p >= len(buf):
            raise ValueError("leb128 ran off end of buffer")
        b = buf[p]
        p += 1
        v |= (b & 0x7F) << shift
        if b < 0x80:
            return v, p
        shift += 7
        if shift > 28:
            raise ValueError("leb128 too long (max 4 bytes)")


def decode_cells_variable(buf: bytes, count: int,
                          fixed_key_size: int = 0,
                          fixed_val_size: int = 0) -> List[LsmCell]:
    """Decode ``count`` cells from a *non-compact* (no group bitmap) buffer.

    Used for LDIR pages and for LEAF pages whose owning tree was created
    with ``fixed_key_size == 0``.

    * If ``fixed_key_size == 0``:  each cell is variable-length, encoded as
      ``leb128 key_len | leb128 val_len | key | val`` (the "lsm record"
      layout from ``FUN_180046d00``).

    * If ``fixed_key_size != 0``:  each cell is ``key (fixed_key_size) ||
      val (fixed_val_size)`` back-to-back, with no per-cell length
      prefix.  This is the layout used for LDIR (interior) pages of a
      fixed-key tree -- ``fixed_val_size`` is forced to 8 (one child page
      id) before this is called.
    """
    cells: List[LsmCell] = []
    p = 0
    for _ in range(count):
        if fixed_key_size == 0:
            if p >= len(buf):
                raise ValueError("ran out of buffer mid-cell (variable mode)")
            key_len, p = _read_leb128(buf, p)
            val_len, p = _read_leb128(buf, p)
            if key_len > 0x8000 or val_len > 0x8000:
                raise ValueError(f"cell sizes too large: {key_len}, {val_len}")
        else:
            key_len, val_len = fixed_key_size, fixed_val_size
        key = bytes(buf[p:p + key_len]); p += key_len
        val = bytes(buf[p:p + val_len]); p += val_len
        # Non-compact mode does not carry a tombstone bit; an empty
        # value is just a zero-length value.
        cells.append(LsmCell(key=key, value=val, alive=True))
    return cells


def decode_cells_compact(buf: bytes, count: int,
                         fixed_key_size: int,
                         fixed_val_size: int) -> List[LsmCell]:
    """Decode ``count`` cells from a *compact* (LEAF, fixed-size) buffer.

    Compact layout: the buffer is partitioned into back-to-back groups,
    each preceded by a 4-byte header::

        u32 LE  (group_count_byte | (alive_bitmap_b1 << 8) |
                 (alive_bitmap_b2 << 16) | (alive_bitmap_b3 << 24))

    where the low byte is the number of cells in the group (1..24) and
    the upper three bytes encode an alive-bitmap.  The bitmap is recovered
    in code as ``b3 | (b2 << 8) | (b1 << 16)``; bit ``i`` of the bitmap
    refers to cell ``i`` of the group, and bit set => alive (carries a
    value).  Tombstone cells store only the ``fixed_key_size`` key bytes.
    """
    cells: List[LsmCell] = []
    p = 0
    decoded = 0
    while decoded < count:
        if p + 4 > len(buf):
            raise ValueError(f"compact: short group header at {p}")
        u32 = struct.unpack("<I", buf[p:p + 4])[0]
        p += 4
        group_count = u32 & 0xFF
        b1 = (u32 >> 8) & 0xFF
        b2 = (u32 >> 16) & 0xFF
        b3 = (u32 >> 24) & 0xFF
        bitmap = b3 | (b2 << 8) | (b1 << 16)
        if group_count == 0 or group_count > 24:
            raise ValueError(f"compact: bad group_count {group_count} at {p-4}")
        for j in range(group_count):
            if decoded >= count:
                # The DLL code wraps once group_count cells have been emitted;
                # if the page terminates early in the middle of a group,
                # we stop at ``count``.
                break
            alive = bool((bitmap >> j) & 1)
            key = bytes(buf[p:p + fixed_key_size]); p += fixed_key_size
            if alive:
                val = bytes(buf[p:p + fixed_val_size]); p += fixed_val_size
            else:
                val = b""
            cells.append(LsmCell(key=key, value=val, alive=alive))
            decoded += 1
    return cells


def decode_page_cells(page_body: bytes,
                      *,
                      fixed_key_size: int,
                      fixed_val_size: int,
                      decrypt=None) -> Tuple[LsmInnerHeader, List[LsmCell]]:
    """Decode every cell in a LEAF or LDIR page body.

    Parameters
    ----------
    page_body
        Full 4088-byte body slice (including the 8-byte inner header).
    fixed_key_size
        Fixed key length for the owning tree (from the L-SB superblock at
        offset +0x10).  Pass ``0`` for variable-length keys.
    fixed_val_size
        Fixed value length for the owning tree (from the L-SB superblock
        at offset +0x14).  For LDIR pages this is internally forced to
        8 (the size of an on-disk page id).  Pass ``0`` for variable-length
        values.
    decrypt
        Optional decryption callback (see :func:`decode_cell_stream`).

    Returns
    -------
    (header, cells)
        Parsed header and list of decoded :class:`LsmCell` records.
    """
    header = parse_inner_header(page_body)
    is_ldir = (header.magic == b"LDIR")
    # LDIR cells are always 8-byte child page-ids (per FUN_180045510).
    if is_ldir:
        fixed_val_size = 8
    raw = decode_cell_stream(page_body, header, decrypt=decrypt)

    # Compact mode is enabled only for LEAF pages (FUN_1800452f0:
    #   local_45f = page_type == 3).  LDIR pages always use the variable
    #   layout regardless of fixed sizes.
    use_compact = (not is_ldir) and (fixed_key_size != 0)

    if use_compact:
        cells = decode_cells_compact(
            raw, header.cell_count, fixed_key_size, fixed_val_size,
        )
    else:
        cells = decode_cells_variable(
            raw, header.cell_count,
            fixed_key_size=fixed_key_size,
            fixed_val_size=fixed_val_size,
        )
    return header, cells


__all__ = [
    "LSM_PAGE_HEADER_LEN",
    "LsmInnerHeader",
    "LsmCell",
    "parse_inner_header",
    "decode_cell_stream",
    "decode_cells_variable",
    "decode_cells_compact",
    "decode_page_cells",
]
