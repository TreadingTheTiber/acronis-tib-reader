"""
indexer.py — automatic partition-direct index builder for any sector-mode .tib.

Given a `.tib` file path, produces a `blocks.idx` (partition-direct format,
v10) that lets `TibReader` random-access the original partition image. The
process is:

  1. Discover the chunk-map's file_offset and compressed_size by parsing
     the metadata-blob TLV (see chunkmap_locator.py — self-describing,
     no hardcoded constants).
  2. Inflate + de-transpose + zigzag-delta-decode the chunk map (see
     chunkmap.py) to get one record per partition_block.
  3. Read each stored block's 16-byte preamble from the .tib at its
     authoritative file_offset.
  4. Write a 28-byte-per-entry index covering ALL partition_blocks
     (sparse blocks have file_offset=0, comp_len=0, zero preamble).

The index is cached next to the .tib (or in a user-specified cache dir)
so subsequent opens are instant.

Index file format (TIBIDX02):
  [8B magic "TIBIDX02"]
  [u64 tib_size]
  [u64 data_start]
  [u64 data_end]
  [u64 block_count]
  [block_count × 28-byte records of (u64 file_offset, 16B preamble, u32 comp_len)]

Sparse partition_block markers: file_offset=0, comp_len=0, preamble=zeros.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional

from .chunkmap_locator import discover_chunkmap_offset
from .chunkmap import decode_chunk_map
from .reader import TibReader, INDEX_MAGIC, INDEX_REC_SIZE, VOLUME_HEADER_LEN


def _default_index_path(tib_path: str | os.PathLike) -> Path:
    """The default cached index lives next to the .tib as `<tib>.idx`."""
    return Path(tib_path).with_suffix(Path(tib_path).suffix + ".idx")


def build_index(
    tib_path: str | os.PathLike,
    index_path: Optional[str | os.PathLike] = None,
    *,
    force: bool = False,
    progress: bool = False,
) -> Path:
    """Build (or reuse) a partition-direct index for a sector-mode `.tib`.

    Returns the index path. Idempotent: if the index already exists and
    `force` is False, the existing file is returned untouched.

    Raises ValueError if the `.tib` is not sector-mode (e.g. filesystem-mode
    `.tib` files use a different magic and aren't supported by this reader).
    """
    tib_path = Path(tib_path)
    if index_path is None:
        index_path = _default_index_path(tib_path)
    index_path = Path(index_path)

    if index_path.exists() and not force:
        return index_path

    # Step 1: locate the chunk map (self-describing — no hardcoded constants)
    if progress:
        print(f"[tibread] discovering chunk-map location in {tib_path.name}...", flush=True)
    chunkmap_off, chunkmap_size = discover_chunkmap_offset(str(tib_path))

    # Step 2: decode the chunk map → one record per partition_block
    if progress:
        print(
            f"[tibread] decoding chunk map at offset {chunkmap_off:,}, "
            f"size {chunkmap_size:,}...",
            flush=True,
        )
    records, partition_block_count = decode_chunk_map(
        str(tib_path), chunkmap_off, chunkmap_size
    )
    n_stored = sum(1 for off, ln in records if ln > 0)
    n_sparse = partition_block_count - n_stored
    if progress:
        print(
            f"[tibread]   {partition_block_count:,} partition_blocks "
            f"({n_stored:,} stored, {n_sparse:,} sparse)",
            flush=True,
        )

    # Step 3: read each stored block's 16-byte preamble from the .tib.
    # Sort by file_offset for sequential I/O (much faster on spinning disks
    # and remote mounts). Each preamble is the cluster-presence bitmap.
    if progress:
        print(
            f"[tibread] reading {n_stored:,} preambles "
            f"(sequential file order)...",
            flush=True,
        )

    # Pair each stored entry with its partition_block index, sort by file_offset.
    stored = [
        (pb, off + VOLUME_HEADER_LEN, ln)
        for pb, (off, ln) in enumerate(records)
        if ln > 0
    ]
    stored.sort(key=lambda x: x[1])

    preambles: dict[int, bytes] = {}
    tib_size = tib_path.stat().st_size
    with open(tib_path, "rb") as f:
        last_pct = -1
        for i, (pb, foff, _ln) in enumerate(stored):
            if progress and n_stored:
                pct = (i * 100) // n_stored
                if pct != last_pct and pct % 5 == 0:
                    print(f"[tibread]   {pct}%", flush=True)
                    last_pct = pct
            f.seek(foff)
            preambles[pb] = f.read(16)

    # Step 4: write the partition-direct index
    if progress:
        print(f"[tibread] writing index → {index_path}", flush=True)

    data_start = VOLUME_HEADER_LEN
    data_end = chunkmap_off  # block-stream ends where the post-data region starts
    zero_preamble = b"\x00" * 16

    with open(index_path, "wb") as out:
        out.write(INDEX_MAGIC)
        out.write(struct.pack("<QQQQ", tib_size, data_start, data_end, partition_block_count))
        for pb, (off, ln) in enumerate(records):
            if ln > 0:
                out.write(
                    struct.pack(
                        "<Q16sI",
                        off + VOLUME_HEADER_LEN,
                        preambles[pb],
                        ln,
                    )
                )
            else:
                out.write(struct.pack("<Q16sI", 0, zero_preamble, 0))

    if progress:
        print(
            f"[tibread] done. index size: "
            f"{index_path.stat().st_size / 1024 / 1024:.1f} MB",
            flush=True,
        )
    return index_path


def open_tib(
    tib_path: str | os.PathLike,
    *,
    index_path: Optional[str | os.PathLike] = None,
    cache_blocks: int = 32,
    build_ntfs_index: bool = True,
    progress: bool = False,
):
    """High-level entry point: open a `.tib`, build/load index, return NtfsVolume.

    The index is auto-cached next to the `.tib` as `<tib>.idx` unless an
    explicit `index_path` is given.
    """
    from .ntfs import NtfsVolume  # imported lazily to avoid cycles

    idx = build_index(tib_path, index_path, progress=progress)
    reader = TibReader(str(tib_path), str(idx), cache_blocks=cache_blocks)
    mft_lcn = NtfsVolume.find_mft_lcn(reader)
    vol = NtfsVolume(
        reader,
        build_index=build_ntfs_index,
        mft_lcn_override=mft_lcn,
    )
    return vol
