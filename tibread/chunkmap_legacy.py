#!/usr/bin/env python3
"""
chunkmap_legacy.py — TI 2014/2015/2016-era ("legacy") `.tib` chunk-map decoder.

Implementation notes
====================

The legacy sector-mode `.tib` (TI 2014-2016) does NOT carry the modern
`ExtraFileChunkMap` zlib stream + 13-byte `06 V[6] 01 00 03 S[3]` locator.
Instead, the per-block chunk map is split into one or more **inline
metadata records** interleaved with the block stream itself. Each inline
record sits in the block-stream byte stream where a normal block would,
and has the form:

    [u8 L]
    [L bytes  TLV (Acronis u16-LE-tag grammar)]
    [zlib stream]    ─→ inflates to (count × 12) bytes
                       ─→ matrix-transposed (column-major to row-major)
                       ─→ 12-byte records {u64 zigzag-delta-offset, u32 length}
                       ─→ zigzag accumulator carries across records:
                              acc += zigzag(delta);  rec.offset = acc;
                              acc += rec.length

TLV tag dictionary (FUN_08982090 in product.bin):

  tag 0x02 = u16  bytes per sector       (= 512 in miner1)
  tag 0x03 = u8   sectors per cluster    (= 8   in miner1; cluster = 4096 B)
  tag 0x04 = u8   clusters per block     (= 64  in miner1; block = 256 KiB)
  tag 0x05 = u32  optional, possibly compression alg id (absent in miner1)
  tag 0x06 = u24  record count
  tag 0x07 = u32  optional, transient (absent in miner1)
  tag 0xD4 = u8   optional boolean flag

Inline records are detected during a forward walk of the block stream:

  - A normal data block is `[preamble_len B preamble][zlib]` where the
    zlib stream begins at +preamble_len with magic `78 01`.
  - An inline metadata record begins with `0x11` or `0x13` (a small TLV
    length prefix) followed by `78 01` somewhere in the next ~32 bytes
    BUT NOT at exactly +preamble_len (which would be a normal block whose
    preamble first byte happens to be 0x11/0x13).

The walker reads each record's preamble + zlib header, consumes the zlib
stream via `zlib.decompressobj` to discover its compressed length (we
don't need the inflated bytes for chunk-map discovery), then advances.
On hitting an inline metadata record it parses the TLV and decodes the
chunk-map records, accumulating them across all inline records.

After the LAST inline record the block stream is over; the rest of the
file is the MD5 manifest + residual + trailer. The walker recognises
this state by failing to find a valid block preamble after the inline
record's zlib ends (within a small lookahead window).

Verified empirically against `/mnt/e/miner1_default_full_b1_s1_v1.tib`
(8 GB TI 2014 archive): 70,709 data blocks, 2 inline metadata records
at file offsets 10,431,214 (135 chunkmap records) and 8,773,374,742
(259,108 chunkmap records). Total: 70,709 partition_blocks indexed.
"""
from __future__ import annotations

import struct
import zlib
from typing import Iterator, List, Tuple

from .chunkmap import transpose, decode_records

# Volume header is 32 bytes; the block stream starts immediately after.
DATA_START = 32

# Legacy block geometry (as encoded in inline-TLV tags 0x02/0x03/0x04).
LEGACY_PREAMBLE_LEN = 8
LEGACY_CLUSTERS_PER_BLOCK = 64
LEGACY_CLUSTER_SIZE = 4096
LEGACY_BLOCK_SIZE = LEGACY_CLUSTERS_PER_BLOCK * LEGACY_CLUSTER_SIZE  # 262144

# Inline-metadata first-byte heuristic. The byte is the `L` prefix on the
# inline record's TLV section; in TI 2014/15/16 we observe 0x11 and 0x13.
INLINE_TLV_FIRST_BYTES = (0x11, 0x13)

# Look-ahead window when locating the `78 01` zlib magic inside an inline
# TLV header. 32 is generous; observed forms are 18 or 20 bytes.
INLINE_TLV_SCAN_WINDOW = 32


def _parse_tlv_u16(buf: bytes) -> List[Tuple[int, int, bytes]]:
    """Parse Acronis-style TLV: u16-LE tag + length-prefix + value.

    Length prefix:
      - high bit clear: 1-byte length (low 7 bits)
      - high bit set:   2-byte length, ((b0 << 8) | b1) & 0x7FFF
    """
    out: List[Tuple[int, int, bytes]] = []
    i = 0
    n = len(buf)
    while i < n:
        if i + 3 > n:
            break
        tag = buf[i] | (buf[i + 1] << 8)
        lb = buf[i + 2]
        if lb & 0x80:
            if i + 4 > n:
                break
            length = ((lb << 8) | buf[i + 3]) & 0x7FFF
            vs = i + 4
        else:
            length = lb
            vs = i + 3
        if vs + length > n:
            break
        out.append((tag, length, buf[vs : vs + length]))
        i = vs + length
    return out


def _looks_like_inline_metadata(head: bytes, preamble_len: int) -> int:
    """If `head` starts with the inline-metadata signature, return the
    file-offset (within `head`) of the `78 01` zlib magic. Else return -1.

    A normal data block has its zlib magic at exactly `+preamble_len`; an
    inline metadata record places the zlib magic somewhere ELSE in the
    first ~32 bytes (and always after a small TLV section).
    """
    if not head or head[0] not in INLINE_TLV_FIRST_BYTES:
        return -1
    limit = min(INLINE_TLV_SCAN_WINDOW, len(head) - 1)
    for i in range(2, limit):
        if head[i] == 0x78 and head[i + 1] == 0x01:
            if i == preamble_len:
                # Just a normal block whose preamble starts with 0x11/0x13
                return -1
            return i
    return -1


def _consume_zlib_stream(f, max_extra: int = 1 << 22) -> Tuple[int, bytes]:
    """Inflate a zlib stream starting at the file's current position.

    Returns (compressed_length, decompressed_bytes). Reads in chunks so
    we never load more than necessary. Stops as soon as the
    `decompressobj.eof` flag is set; reports the consumed compressed
    length via `unused_data` accounting.
    """
    d = zlib.decompressobj()
    decompressed = bytearray()
    consumed = 0
    chunk_size = 64 * 1024
    while not d.eof:
        buf = f.read(chunk_size)
        if not buf:
            raise ValueError("EOF while inflating zlib stream")
        decompressed.extend(d.decompress(buf))
        consumed += len(buf)
        if d.eof:
            break
        if consumed > max_extra and len(decompressed) == 0:
            # Sanity: a zlib stream that consumes >4 MB without producing
            # any output is not real; bail out.
            raise ValueError("zlib stream did not produce any output")
    # The last `chunk_size` slurp may have read past the stream end.
    unused = len(d.unused_data)
    consumed -= unused
    return consumed, bytes(decompressed)


def decode_inline_chunkmap(f, md_offset: int) -> Tuple[dict, List[Tuple[int, int]]]:
    """Decode one inline SequentialChunkMap at the given file offset.

    Returns (tlv_dict, [(concat_offset, length), ...]) where
    `concat_offset` is relative to data_start (= 32) and `length` is the
    on-disk compressed length of the block at that concat offset
    (preamble_len + zlib_len).
    """
    f.seek(md_offset)
    head = f.read(INLINE_TLV_SCAN_WINDOW)
    if not head:
        raise ValueError(f"EOF at md_offset {md_offset}")
    L = head[0]
    if L < 8 or L > 64:
        raise ValueError(f"implausible inline TLV length L={L} at offset {md_offset:#x}")
    f.seek(md_offset + 1)
    tlv_bytes = f.read(L)

    records = _parse_tlv_u16(tlv_bytes)
    tlv: dict = {}
    for tag, _length, val in records:
        if len(val) <= 8:
            tlv[tag] = int.from_bytes(val, "little")
        else:
            tlv[tag] = val

    if 6 not in tlv:
        raise ValueError(f"no record-count (tag 6) at offset {md_offset:#x}")
    count = int(tlv[6])
    expected_inflated = count * 12

    f.seek(md_offset + 1 + L)
    comp_len, plain = _consume_zlib_stream(f)
    if len(plain) != expected_inflated:
        raise ValueError(
            f"inline chunkmap inflate gave {len(plain)} bytes; expected {expected_inflated}"
        )

    transposed = transpose(bytearray(plain), count, 12)
    raw = decode_records(bytes(transposed), count)
    # `decode_records` returns a list of (offset, length); for the legacy
    # in-block-stream chunkmap these offsets are concat coords (relative to
    # data_start = 32). The accumulator semantics are identical to the
    # modern chunk map (delta + previous-length carry).
    return tlv, raw


def discover_inline_chunkmaps_legacy(
    tib_path: str,
    *,
    progress: bool = False,
) -> Tuple[List[int], int, int]:
    """Walk the legacy block stream forward, discovering all inline
    SequentialChunkMap records.

    Returns (md_offsets, clusters_per_block, preamble_len) where
    `md_offsets` is the file-offset of each inline metadata record's
    `[u8 L]` length-prefix byte, in order. Geometry (clusters_per_block,
    preamble_len) is read from the first inline record's TLV.

    Implementation: starts at file offset 32, reads `preamble_len`-byte
    preambles and zlib stream lengths via `decompressobj`, recognising
    inline metadata records by the `0x11`/`0x13` first-byte heuristic.
    Stops when encountering an inline metadata record that is the LAST
    one (no further valid block preamble follows within the lookahead
    window).
    """
    import os

    file_size = os.path.getsize(tib_path)
    md_offsets: List[int] = []
    clusters_per_block = LEGACY_CLUSTERS_PER_BLOCK
    preamble_len = LEGACY_PREAMBLE_LEN
    geometry_locked = False

    with open(tib_path, "rb") as f:
        cur = DATA_START
        last_pct = -1
        while cur < file_size:
            f.seek(cur)
            head = f.read(INLINE_TLV_SCAN_WINDOW)
            if len(head) < preamble_len + 2:
                break
            zoff_in_head = _looks_like_inline_metadata(head, preamble_len)
            if zoff_in_head >= 0:
                # Inline metadata record.
                tlv_len = head[0]
                tlv = head[1 : 1 + tlv_len]
                parsed = _parse_tlv_u16(tlv)
                tdict = {}
                for tag, _l, val in parsed:
                    if len(val) <= 8:
                        tdict[tag] = int.from_bytes(val, "little")
                if not geometry_locked:
                    if 4 in tdict:
                        clusters_per_block = int(tdict[4])
                    preamble_len = clusters_per_block // 8
                    geometry_locked = True
                md_offsets.append(cur)
                f.seek(cur + 1 + tlv_len)
                comp_len, _plain = _consume_zlib_stream(f)
                cur += 1 + tlv_len + comp_len
                if cur >= file_size:
                    break
                # After an inline record there may be a small "tail pad"
                # of zero/cipher bytes before the next block. Scan up to
                # ~128 KiB for the next valid block preamble. If none
                # found, this was the terminal inline record.
                next_off = _find_next_block(
                    f, cur, file_size, preamble_len, max_skip=128 * 1024
                )
                if next_off is None:
                    break
                cur = next_off
                if progress:
                    pct = int(cur * 100 / file_size)
                    if pct != last_pct and pct % 5 == 0:
                        print(f"[tibread]   walking block stream {pct}%", flush=True)
                        last_pct = pct
                continue

            # Normal data block.
            if head[preamble_len] != 0x78 or head[preamble_len + 1] != 0x01:
                break
            f.seek(cur + preamble_len)
            try:
                comp_len, _plain = _consume_zlib_stream(f)
            except (zlib.error, ValueError):
                break
            cur += preamble_len + comp_len
            if progress:
                pct = int(cur * 100 / file_size)
                if pct != last_pct and pct % 5 == 0:
                    print(f"[tibread]   walking block stream {pct}%", flush=True)
                    last_pct = pct

    if not md_offsets:
        raise ValueError(
            "legacy block-stream walk found no inline SequentialChunkMap records"
        )
    return md_offsets, clusters_per_block, preamble_len


def _find_next_block(f, start: int, file_size: int, preamble_len: int,
                     max_skip: int = 128 * 1024):
    """After an inline metadata record, scan up to `max_skip` bytes
    forward looking for the next valid block.

    A valid block has zlib magic `78 01` at exactly +preamble_len AND its
    zlib stream inflates cleanly to a positive multiple of 4096. If no
    valid block is found within `max_skip` bytes, returns None — meaning
    the caller's inline record was the terminal one.
    """
    pos = start
    end = min(start + max_skip, file_size)
    while pos + preamble_len + 2 <= end:
        f.seek(pos + preamble_len)
        magic = f.read(2)
        if magic == b"\x78\x01":
            # Validate by attempting to inflate the zlib stream.
            f.seek(pos + preamble_len)
            try:
                comp_len, plain = _consume_zlib_stream(f)
                if (
                    comp_len > 0
                    and len(plain) > 0
                    and len(plain) % 4096 == 0
                    and len(plain) <= preamble_len * 8 * 4096
                ):
                    return pos
            except (zlib.error, ValueError):
                pass
        pos += 1
    return None


def decode_chunkmap_legacy_from_md_offsets(
    tib_path: str,
    md_offsets: List[int],
) -> Tuple[List[Tuple[int, int]], int]:
    """Decode all inline SequentialChunkMap records and concatenate them
    in order. `md_offsets` is the list of file offsets at which inline
    metadata records begin (= the `[u8 L]` byte position).

    Returns (records, count) — `records[i]` is `(concat_offset, length)`
    for partition_block `i`. Sparse partition blocks have `length == 0`.
    """
    out: List[Tuple[int, int]] = []
    with open(tib_path, "rb") as f:
        for md_off in md_offsets:
            _tlv, recs = decode_inline_chunkmap(f, md_off)
            out.extend(recs)
    return out, len(out)
