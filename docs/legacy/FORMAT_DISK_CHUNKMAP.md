# FORMAT_DISK_CHUNKMAP.md — the third chunk-map class

Companion to `FORMAT.md` (modern sector-mode .tib) and `FORMAT_LEGACY.md`
(legacy sector-mode .tib). This document covers the third of the four
chunk-map classes used by Acronis True Image's reader stack:

| Class                | Constructor   | Source line                  | Record size | Use case |
|----------------------|---------------|------------------------------|-------------|----------|
| `ExtraFileChunkMap`  | `FUN_089839b0`| `openimg.cpp` ~ line 0x140  | 12 bytes    | Per-volume modern (TI 2018+) |
| `HybridChunkMap`     | `FUN_08982860`| `openimg.cpp` line 0x80     | 20 bytes    | Per-volume modern, parallel-pipeline |
| `DiskChunkMap`       | `FUN_08983090`| `openimg.cpp` line 0xba     | 20 bytes    | **Whole-disk-image backups** |
| `SequentialChunkMap` | `FUN_08982090`| `openimg.cpp` ~ line 0x60   | 12 bytes    | Per-volume legacy (TI 2014/15/16) |

The four classes share the same TLV grammar (u16 LE tag + length prefix),
the same matrix-transpose helper (`FUN_08999130`), the same zigzag-delta
record decoding, and the same zlib decompressor selection (via tag 99 and
`FUN_08ae2b30` / `FUN_08ae49e0`). They differ in:

- Record size (12 vs 20 bytes).
- TLV tag set.
- Where the chunk-map descriptor is stored on disk.
- Which parent stream type owns them.

## DiskChunkMap purpose

**Confirmed via decompilation:** DiskChunkMap is constructed by
`DiskImageStream` (`FUN_08ad2ad0`), which is itself constructed by
`BackupImageOpener::OpenHardDiskImage` (`FUN_08ad64e0`). The latter calls
`GetHardDiskImageParameters` (`FUN_08984240`, source
`k:/8029/resizer/backup/openimg.cpp:0x139`), which only succeeds if the
parameter-block tag value is **2** (vs 0 = volume-image, 1 = ?).

> **Use case: whole-physical-disk-image backups** — backups that capture
> an entire disk including its MBR/GPT, partition table, and all
> partitions in a single linear stream, rather than per-volume backups
> where each partition is a separate stream.

When you back up a "Disk" target in TI 2018+ (vs a "Volume" target), the
resulting archive uses `DiskImageStream` + `DiskChunkMap` for the disk
itself, plus normal per-volume `HybridImageStream` + `HybridChunkMap` for
each partition inside.

## TLV tag dictionary

`FUN_08983090` reads exactly four tags:

| Tag    | Meaning                                                   |
|--------|-----------------------------------------------------------|
| 0x02   | Block-stream metadata field A (analogous to Sequential tag 2) |
| 0x04   | Block-stream metadata field B (analogous to Sequential tag 4 = clusters/block) |
| 0x06   | **Record count**                                          |
| 0x99 (decimal 199 / 0xC7) | **Tag-99 flag**: when present (length 0), records are stored as full 20-byte structs. When absent, records are stored as 16-byte structs and the trailing 4 bytes per record are zero-filled. |
| 99 (0x63) | **Decompressor selector** (read via `FUN_089883d0`): when absent, the `ZLibDecompressor` (zlib 1.2.8) is used. Same as Sequential/Hybrid. |

(Two distinct numeric tags are tested as length-0 booleans:
`tag 99 = 0x63` selects the decompressor;
`tag 0xC7 = 199` selects the on-disk record padding.)

The DiskChunkMap tag set is **a strict subset** of the SequentialChunkMap
set: it has tags 2, 4, 6, 0xC7 — no tag 3, no tag 5, no tag 7, no tag
0xD4. The missing tags (especially 3 = sectors per cluster) are likely
defaulted because a whole-disk image works at the disk-sector level, not
the partition-cluster level: there is no FAT/NTFS cluster size when you're
imaging the disk including its MBR.

## Record format (20 bytes per record)

```
offset  size  field
0       8     u64 zigzag-delta file_offset
8       4     u32 length (bytes consumed in the block stream)
12      8     u64 zigzag-delta extra_value (only when tag 0xC7 is present)
              — when tag 0xC7 absent: zeros, ignored
```

After matrix-transpose + zigzag-delta accumulation:

```c
acc_off = 0;
acc_extra = 0;
for (i = 0; i < count; i++) {
    rec[i].file_offset = acc_off + zigzag_decode(rec[i].delta);
    acc_off = rec[i].file_offset + rec[i].length;
    rec[i].extra = acc_extra + rec[i].extra_delta;   // (only when 0xC7 present)
    acc_extra = rec[i].extra;
}
```

The `extra` field is presumably a disk-LBA offset, since DiskChunkMap
operates at the whole-disk level where blocks need both a file_offset
(where the compressed bytes live) AND a disk-LBA (where the bytes belong
on the original physical disk including pre-MBR / inter-partition gaps).
HybridChunkMap has a similar 20-byte layout but uses tag `0xDF` (vs
`0xC7`) to gate the trailing 8 bytes — different name, same role.

## Empirical sighting in miner1

Miner1 is a **per-volume legacy** archive, NOT a whole-disk-image. So
miner1's main stream is `SequentialImageStream` + (inline)
`SequentialChunkMap`. **However**, miner1's trailing metadata blob
(at file offset `0x20b234d98`, 921 bytes) does contain a 1-record
DiskChunkMap-style descriptor in its first ZLIB-compressed sub-region:

```
blob[0..17]   = 17-byte TLV: { tag 2 = 512, tag 4 = 512, tag 6 = 1, tag 0xC7 = present }
blob[18..38]  = 21-byte zlib stream → 20 bytes inflated
   = 28 d1 44 16 04 00 00 00 e4 e4 00 00 00 00 00 00 00 00 00 00
   → record 0: zigzag=0x041644d128 → delta=+8776738964
                    abs_offset = 0x20b226894
                    length     = 58596
                    extra      = 0
```

This single record describes the LAST data block in the block stream
(starts at file offset `0x20b226894`, length 58596 bytes — the same
58596-byte zlib stream the empirical block walker observed at the end of
the file).

So in legacy archives the trailing metadata blob includes an
"end-of-stream marker" in DiskChunkMap form, even though the archive
itself isn't a whole-disk-image. Likely this is a generation marker /
final-block bookmark used by Acronis's catalog walker to validate
archive integrity (the disk-LBA/extra slot is unused).

## Triggering DiskChunkMap (full call chain)

```
BackupImageOpener::OpenHardDiskImage (FUN_08ad64e0)
    → GetHardDiskImageParameters (FUN_08984240)        // requires *piVar1 == 2
    → operator new(0x50)
    → DiskImageStream ctor (FUN_08ad2ad0)
        → DiskChunkMap ctor (FUN_08983090)
            → FUN_08996de0 (build TLV index over 17-byte preamble)
            → FUN_089974c0 (look up tags 2, 4, 6, 199 = 0xC7)
            → FUN_089883d0 + FUN_08ae2b30 (build ZLibDecompressor)
            → operator new(count * 0x14)
            → ZLibDecompressor::decompress(zpayload → records)
            → FUN_08999130 (matrix transpose)
            → zigzag-delta accumulator loop
```

Other callers of DiskChunkMap:
- `RemovePoints::Create` (`FUN_08ad1290`) — invokes whichever chunk-map
  constructor matches the slice-removal map type at switch arm `== 2`.
  This is the dispatch that tells you the enum value semantics:
  `0=Sequential, 1=Hybrid, 2=Disk`.

## Confidence levels

| Finding | Source |
|---|---|
| DiskChunkMap = whole-physical-disk-image backups | **Decompiled** (FUN_08984240 = `GetHardDiskImageParameters` requires param == 2) |
| 20-byte records, 12B significant + optional 8B extra | **Decompiled** (FUN_08983090) |
| Tag set: 2, 4, 6, 0xC7, 99 | **Decompiled** (FUN_08983090) |
| Tag 0xC7 (=199) gates the trailing 8 bytes per record | **Decompiled** (FUN_08983090 condition `cVar5 != '\0'`) |
| Records zlib-compressed with same `ZLibDecompressor` | **Decompiled** + miner1 empirical (the embedded 21-byte zlib in miner1's trailing metadata blob inflates cleanly) |
| Constructor chain: OpenHardDiskImage → DiskImageStream → DiskChunkMap | **Decompiled** (xrefs from FUN_08983090 → FUN_08ad2ad0 → FUN_08ad64e0) |
| RemovePoints::Create enum: 0=Seq, 1=Hyb, 2=Disk | **Decompiled** (FUN_08ad1290 lines 511..554) |
| One DiskChunkMap-style record sits in miner1's trailing metadata blob | **Empirical** (decoded byte-by-byte) |

## Open question

The miner1 trailing-blob 1-record DiskChunkMap is unusual: miner1 is a
per-volume legacy archive (no MBR, no whole-disk semantics), yet has a
DiskChunkMap descriptor in its trailing metadata. The semantics here are
**probably "last block bookmark"** — a single record pointing at the
file offset where the last compressed block lives, used by the archive
verifier to confirm the block stream terminates cleanly. The `extra`
field is zero in miner1, supporting "this is bookmark, not LBA mapping".

A more authoritative answer would require finding a real whole-disk-image
.tib (Acronis True Image with a "Disk" backup target rather than
"Volume"), where DiskChunkMap would carry a real multi-partition
disk-LBA mapping.

## product.bin Ghidra anchors

| Address     | Symbol                                | Source                          |
|-------------|---------------------------------------|---------------------------------|
| `0x08983090` | `DiskChunkMap::ctor`                  | `openimg.cpp:0xba`              |
| `0x08984240` | `GetHardDiskImageParameters`          | `openimg.cpp:0x139`             |
| `0x08ad2ad0` | `DiskImageStream::ctor`               | (probably `image_stream.cpp`)   |
| `0x08ad64e0` | `BackupImageOpener::OpenHardDiskImage`| (`backup_image_opener.cpp`)     |
| `0x08ad1290` | `RemovePoints::Create`                | `remove_points.cpp:0x4c`        |
| `0x08ae2b30` | `CreateDecompressor`                  | `compress/create_d.cpp:0x23`    |
| `0x08ae49e0` | `ZLibDecompressor::ctor`              | `compress/zlibdf_d.cpp:0x17`    |
