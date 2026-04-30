#!/usr/bin/env python3
"""
build_skipmap_from_tib.py — Final on-disk chunk-map decoder.

Reverse-engineered from Acronis True Image's `product.bin`:
  ExtraFileChunkMap = FUN_089839b0 (k:/8029/resizer/backup/openimg.cpp)

Reads the on-disk chunk-map zlib stream from a sector-mode .tib backup,
decodes it via {inflate → byte-transpose → zigzag-delta}, and writes a
per-partition-block index mapping (orig_partition_block → file_offset_in_tib).

Validates with both MFT extent anchors:
  orig_block 6144 (MFT extent 1) → reader_block 6017 (file_offset matches blocks.idx)
  orig_block 2864367 (MFT extent 2) → reader_block 1693384

USAGE:
  python3 build_skipmap_from_tib.py <path_to_tib> <output_csv>

OUTPUT (CSV):
  partition_block_idx, file_offset, comp_length, reader_block_idx
  - file_offset 0 + length 0 = sparse (block not stored)
  - reader_block_idx = -1 for sparse blocks
"""
from __future__ import annotations
import struct
import sys
import zlib
from pathlib import Path

# Volume header is at file offset 0..32; data area starts at 32.
DATA_START = 32

# Self-describing chunk-map discovery — the (offset, size) for the on-disk
# chunk-map zlib stream is parsed out of the .tib's metadata blob TLV.
# See discover_chunkmap.py for the layout details.
from .chunkmap_locator import discover_chunkmap_offset


def parse_storereader(blob: bytes):
    """Parse StoreReader TLV header. Returns (fields_dict, header_end)."""
    if not blob:
        return {}, 0
    L = blob[0]
    fields = {}
    pos = 1
    end = 1 + L
    while pos < end:
        if pos + 2 > len(blob):
            break
        fid = blob[pos]
        size = blob[pos + 1]
        pos += 2
        if size & 0x80:
            ext_len = size & 0x7F
            data = blob[pos : pos + ext_len]
            pos += ext_len
        else:
            data = blob[pos : pos + size]
            pos += size
        fields[fid] = data
    return fields, end


def transpose(buf: bytearray, rows: int, cols: int) -> bytearray:
    """Column-major → row-major byte transpose (FUN_08999130)."""
    try:
        import numpy as np
        arr = np.frombuffer(buf, dtype=np.uint8).reshape(cols, rows).T.copy()
        return bytearray(arr.tobytes())
    except ImportError:
        out = bytearray(len(buf))
        for c in range(cols):
            col_base = c * rows
            for r in range(rows):
                out[r * cols + c] = buf[col_base + r]
        return out


def decode_records(plaintext: bytes, chunk_count: int):
    """Zigzag-delta decode of 12-byte records.
    Each record: {u64 enc_offset_delta, u32 length}
    Accumulator = offset + length"""
    try:
        import numpy as np
        words = np.frombuffer(plaintext, dtype=np.uint32, count=chunk_count * 3).reshape(chunk_count, 3)
        enc_lo = words[:, 0].astype(np.uint64)
        enc_hi = words[:, 1].astype(np.uint64)
        lengths = words[:, 2].astype(np.uint64)
        sign = (enc_lo & 1).astype(np.uint64)
        mag_lo = (enc_lo >> 1) | ((enc_hi & 1).astype(np.uint64) << 31)
        mag_hi = enc_hi >> 1
        mag = (mag_hi << 32) | mag_lo
        mask = np.uint64(0xFFFFFFFFFFFFFFFF)
        delta = np.where(sign != 0, ((~mag) + np.uint64(1)) & mask, mag).astype(np.uint64)
        cumulative = np.empty(chunk_count, dtype=np.uint64)
        cumulative[0] = delta[0]
        cumulative[1:] = (delta[1:] + lengths[:-1]) & mask
        offsets = np.cumsum(cumulative).astype(np.uint64) & mask
        return list(zip(offsets.tolist(), lengths.tolist()))
    except ImportError:
        # Pure Python fallback
        running = 0
        mask = 0xFFFFFFFFFFFFFFFF
        out = []
        for i in range(chunk_count):
            base = i * 12
            enc_lo, enc_hi, length = struct.unpack_from("<III", plaintext, base)
            sign = enc_lo & 1
            mag = ((enc_hi >> 1) << 32) | ((enc_lo >> 1) | ((enc_hi & 1) << 31))
            delta = ((~mag) + 1) & mask if sign else mag
            offset = (running + delta) & mask
            out.append((offset, length))
            running = (offset + length) & mask
        return out


def decode_chunk_map(tib_path: str, file_offset: int | None = None,
                    compressed_size: int | None = None):
    """Read & fully decode the on-disk chunk map. Returns list of (file_offset_in_data, length).

    If `file_offset` / `compressed_size` are None, they are discovered from
    the .tib's metadata blob via `discover_chunkmap_offset` (self-describing).

    The zlib stream sits inside a tiny TLV preamble (length byte + small
    payload of 0x02-tagged fields).  `file_offset` should point AT the zlib
    stream itself (past the preamble); `compressed_size` is the zlib stream's
    on-disk length.  Chunk_count is derived from the decompressed length / 12.
    """
    if file_offset is None or compressed_size is None:
        d_off, d_sz = discover_chunkmap_offset(tib_path)
        if file_offset is None:
            file_offset = d_off
        if compressed_size is None:
            compressed_size = d_sz
    with open(tib_path, "rb") as f:
        f.seek(file_offset)
        compressed = f.read(compressed_size)
    plaintext = zlib.decompress(compressed)
    if len(plaintext) % 12 != 0:
        raise ValueError(f"inflate produced {len(plaintext)} bytes, not multiple of 12")
    chunk_count = len(plaintext) // 12
    transposed = transpose(bytearray(plaintext), chunk_count, 12)
    records = decode_records(bytes(transposed), chunk_count)
    return records, chunk_count


def build_skipmap_csv(tib_path: str, csv_path: str):
    """Decode chunk map and write CSV with absolute file_offsets and reader_block indices."""
    print(f"Decoding chunk map from {tib_path}...", flush=True)
    records, chunk_count = decode_chunk_map(tib_path)
    print(f"  {chunk_count:,} partition_blocks decoded", flush=True)

    with open(csv_path, "w") as f:
        f.write("partition_block,file_offset,comp_length,reader_block\n")
        reader_idx = 0
        stored = 0
        sparse = 0
        for i, (off, ln) in enumerate(records):
            if ln > 0:
                # File offset in chunk map is relative to data start; add DATA_START for absolute
                abs_off = off + DATA_START
                f.write(f"{i},{abs_off},{ln},{reader_idx}\n")
                reader_idx += 1
                stored += 1
            else:
                f.write(f"{i},0,0,-1\n")
                sparse += 1

    print(f"\nResults:")
    print(f"  total partition blocks: {chunk_count:,}")
    print(f"  stored:                 {stored:,}")
    print(f"  sparse:                 {sparse:,}")

    # Validate MFT extent anchors
    print("\nMFT EXTENT ANCHOR VALIDATION:")
    for orig_block, expected_reader in [(6144, 6017), (2_864_367, 1_693_384)]:
        if orig_block < len(records):
            off, ln = records[orig_block]
            if ln > 0:
                # Count non-zero records before this one
                actual_reader = sum(1 for k in range(orig_block) if records[k][1] > 0)
                status = "✅" if actual_reader == expected_reader else "❌"
                print(f"  {status} orig_block {orig_block:>10,} → reader_block {actual_reader:>10,} (expected {expected_reader:,})")
            else:
                print(f"  ❌ orig_block {orig_block:,} reported as sparse (length=0)!")

    print(f"\nWrote {csv_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 build_skipmap_from_tib.py <tib> <output_csv>")
        sys.exit(1)
    build_skipmap_csv(sys.argv[1], sys.argv[2])
