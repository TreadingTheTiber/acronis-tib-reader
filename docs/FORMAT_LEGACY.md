# FORMAT_LEGACY.md — older sector-mode `.tib` files (TI 2014 / 2015 / 2016 era)

Companion to `FORMAT.md`, which describes the v23.5 (TI 2018+) sector-mode
`.tib` layout. This document covers the LEGACY variant that TI 2018+ retains
read-only support for, identified empirically against
`/mnt/e/miner1_default_full_b1_s1_v1.tib` (8 GB, January 2014) and confirmed
via decompilation of `product.bin`.

The two relevant translation units are:

- `k:/8029/resizer/backup/openimg.cpp` — sector-mode reader core
- `k:/8029/resizer/backup/image_stream_sequential.cpp` — legacy block stream
- `k:/8029/backup/container_convert.cpp` — even-older container converter

---

## TL;DR

- The TI 2018+ binary recognises **two distinct legacy generations**:
  1. **`SequentialImageStream`** — reads TI 2014/15/16 sector-mode `.tib`
     files DIRECTLY at runtime (no conversion). Selected when the metadata
     blob lacks **TLV tag `0x9b`**. This is the path miner1 takes.
  2. **`ConvertFromLegacyFormat`** (`container_convert.cpp`) — converts an
     even-older "ancient" container into a newer container in-place. Tests
     `header_length==0x20`, `version==1`, `flags==1`, `sector_size==0x1000`.
     **Miner1 fails this test** (its `version==0` and `+0x1c==0x20`), so it
     does NOT go through the converter.
- Format detection is **TLV-based, not header-based.** The volume header is
  identical (same magic `0xA2B924CE`, same `header_length=0x20`); the
  discriminator lives inside the metadata blob: presence/absence of tag
  `0x9b`.
- The legacy block geometry is **8-byte preambles + 64-cluster (256 KiB)
  blocks**, vs. v23.5's 16-byte preambles + 128-cluster (512 KiB) blocks.
  This is empirical — the relevant clusters-per-block field is parsed from
  TLV tag `3` of the SequentialChunkMap blob, but in practice 64 is the
  fixed value Acronis emitted in this era.
- The legacy block stream IS chunk-map indexed (`SequentialChunkMap`). The
  chunk-map ON-DISK ENCODING is **structurally identical to the modern
  `ExtraFileChunkMap`**: 12-byte zigzag-delta records `{u64
  enc_offset_delta, u32 length}`, byte-wise transpose, single zlib stream.
  Acronis even uses the same matrix-transpose helper (`FUN_08999130`).
- Where the chunk map LIVES on disk differs: in v23.5 the metadata blob
  contains a 13-byte locator (`06 V[6] 01 00 03 S[3]`) pointing to a
  separately-stored chunk-map region; in legacy the chunk map is part of
  the metadata-blob descriptor passed by the opener — see "Where the chunk
  map lives" below.
- The trailer is **completely different**. Legacy has no 41-byte trailer
  body, no `0x94E18A2B` trailer-magic, just a 16-byte mini-trailer +
  mirror header. There is no separate "trailer size + magic" pair.

---

## How `product.bin` decides legacy vs. modern

The dispatcher is **`FUN_08973290`** in `image_stream.cpp` (the constructor
for the read-side `ImageStream` family):

```c
// Pseudocode from FUN_08973290 (anchor: 0x08973290)
if (param_6 == 0) {                            // read-mode
    metadata_reader = FUN_08972eb0(file, blob_descriptor);
    tlv = metadata_reader + 2;
    if (FUN_089974c0(tlv, 0x9b, NULL, 0) == 0) {
        // tag 0x9b ABSENT → LEGACY
        stream = operator_new(0x5C);
        FUN_08977a70(stream, file, blob_descriptor, ...);   // SequentialImageStream
    } else {
        // tag 0x9b PRESENT → modern
        stream = operator_new(0x134);
        FUN_0898bbd0(stream, file, ...);                    // HybridImageStream
        FUN_0898bd50(stream, tlv);                          // parse modern tags
    }
}
```

**Confirmed via decompilation.** `FUN_089974c0` is the generic TLV-tag
lookup. Tag `0x9b` is the modern-format presence flag — its body in the
modern layout is the chunk-map locator (the 13-byte signature already
documented in `FORMAT.md`). When tag `0x9b` is missing, the stream is
constructed as `SequentialImageStream`, which uses `SequentialChunkMap`
directly.

There is NO version-field branch in `CheckVolumeHeader` (`FUN_082160c0`):
that function only validates the magic word. `header.version` is read but
never used for legacy/modern dispatch. The only version-style branch is
deeper down in `ConvertFromLegacyFormat` (see below), which handles a
DIFFERENT, even older format that requires structural conversion.

### A note on the second legacy tier (`ConvertFromLegacyFormat`)

`FUN_091f6780` in `container_convert.cpp` (`ConvertFromLegacyFormat` at line
0x65) is a **container-level migration** function. Its volume-header gate is

```
magic   == 0xA2B924CE
hdr_len == 0x20
version == 1               (NOTE: explicitly version 1)
field_+0x14 == 1
field_+0x1c == 0x1000      (sector size)
```

Miner1 has `version=0` and `+0x1c=0x20`, so it FAILS this gate — meaning it
is NOT touched by ConvertFromLegacyFormat. It is read directly via
SequentialImageStream. The converter targets an even older container
generation (likely TI 11 / TI 2009 era) that had a multi-slice layout
needing structural rewrite to be readable by the modern engine.

Both legacy tiers are independent code paths; SequentialImageStream is the
one that matters for TI 2014/15/16-era files.

---

## Volume header

Same 32 bytes as the modern format. Magic `0xA2B924CE`, `header_length =
0x20`, Adler32 at +0x18 over `header[:0x20]` with `[0x18..0x1C]` zeroed.
Confirmed empirically against miner1: stored Adler32 `0xA42A071E` validates.

The `version` field at +0x06 is **not** what triggers the legacy reader.
miner1 has `version=0` and is read as legacy. Per the version-field
convention (0=Win, 1=Mac), this is a Windows-source legacy archive.

The trailing `+0x1C` u32 in miner1 is `0x20` (32). In the modern format
this is `block_align = 32` per `FORMAT.md`, so this is **the same field**
(value happens to be identical). It is NOT `0x1000` as
`ConvertFromLegacyFormat` checks for; that converter targets a different
file family.

---

## Block geometry

Empirically confirmed against miner1; matches the on-disk pattern reported
by the user.

| Field | TI 2014 (legacy) | TI 2018+ (modern) |
|---|---|---|
| Preamble length | **8 bytes** | 16 bytes |
| Clusters per block | **64** | 128 |
| Cluster size | 4096 B | 4096 B |
| Block payload size | **256 KiB** | 512 KiB |

The preamble is a sparse-cluster bitmap (1 bit per cluster, set = stored,
clear = sparse-zero). 64 clusters × 1 bit = 8 bytes; 128 clusters × 1 bit
= 16 bytes. Empirically confirmed for miner1: first block at offset 32 has
8 bytes of `0xFF` (all-set), then `0x78 0x01` zlib magic, decompressing to
exactly 262144 bytes (= 64 × 4096). Later sparse-bitmap regions in the
file body (e.g., bytes near offset `filesize - 86 KB`) show patchy bit
patterns consistent with 8-byte width (multi-byte runs flipping at bit
boundaries).

### How `product.bin` parametrises the block geometry

In both `SequentialImageStream::ctor` (`FUN_08977a70`) and
`HybridImageStream::ctor` (`FUN_0898bbd0`), bytes `+0x10` and `+0x11` of
the stream struct are initialised to `0x3F` and `0x0F` respectively. These
are **defaults**, not legacy-specific. The actual clusters-per-block value
in legacy is set via TLV parsing inside `SequentialChunkMap::ctor`
(`FUN_08982090`), which reads tags `2,3,4,5,6,7` from the metadata blob
into stream offsets `+0x1C` through `+0x28`. Tag `3` lands at stream word
index `[0xC]` (= byte 0x30), and that word is what subsequent bitmap-size
calculations multiply by. The clusters-per-block is therefore
**TLV-encoded per file**, not hard-coded — but in TI 2014/15/16 archives
Acronis emits tag `3 = 64`.

For a third-party reader, the simplest and safest behaviour is:

- If the modern tag `0x9b` is present → use 128-cluster blocks + 16-byte
  preambles.
- Else (legacy) → use 64-cluster blocks + 8-byte preambles.

This is what Acronis itself does in the dispatch.

---

## SequentialChunkMap — the legacy chunk map

**Yes, the legacy format DOES have a random-access chunk map**, contrary
to one of the hypotheses in the briefing. It is structurally similar to
modern `ExtraFileChunkMap` but has a slightly different metadata wrapper.

### Confirmed via decompilation (`FUN_08982090`):

```
[1 byte: TLV-section length L]
[L bytes:  TLV records — tags 2, 3, 4, 5, 6, 7, 0xD4]
[count×12 bytes: chunk-map records, byte-transposed]
```

where `count` comes from TLV tag `6`. After reading the records, Acronis:

1. Calls `FUN_08999130(records, count, 12)` — the same matrix-transpose
   used for `ExtraFileChunkMap` (column-major → row-major over an Nx12
   matrix).
2. Iterates the records as `{u64 enc_offset_delta, u32 length}` with
   zigzag decoding (`bit 0 of low u32` → sign), accumulating across
   records.

This is **byte-for-byte the same algorithm** as
`build_skipmap_from_tib.py` already implements; the only difference is
where the records live and the TLV tags surrounding them.

### Where the chunk map lives

In `FUN_08973290` (the dispatcher), the legacy branch passes the
**entire metadata-blob descriptor** (`{file_offset, ?, size}`) verbatim
to `FUN_08977a70`, which forwards it to `FUN_08982090`. So the legacy
chunk-map region IS the metadata-blob region.

In the modern format, the metadata blob (~780 B of TLV) and the chunk
map (megabytes) are separate; the metadata blob holds a 13-byte locator
pointing to the chunk-map region. In legacy, there is no locator; the
metadata-blob descriptor itself points at a region that is "TLV header +
chunk-map records appended".

### Empirical layout in miner1

The trailer body (16 bytes immediately before the mirror header) holds
the metadata-blob descriptor:

```
filesize -48 ..  -33    16 bytes:
  +0  u32 zero
  +4  u32 volumeId          (= 0x06496f23, mirrors header[+0x10])
  +8  u32 metaDataOffset    (= 0x0b23513e in miner1)
  +12 u32 fullSize_or_count (= 0x02 in miner1)
filesize -32 ..  -1     32 bytes: byte-reversed mirror of volume header
```

**This is provisional** — `0x0b23513e` (≈ 187 MB) is plausible as a
metadata-blob FILE OFFSET and the corresponding region around
`filesize - 60 KB` does contain dense TLV-looking data, but a definitive
parse pass on the entire 60 KB region was not completed in this
investigation. Block-density profiling shows:

```
  filesize -100..-93 KB : block-stream tail (high-entropy compressed data)
  filesize  -92..-86 KB : sparse-bitmap region (medium density)
  filesize  -85..-65 KB : ZEROS (alignment gap)
  filesize  -62..-1  KB : metadata-blob region (high density)
        of which the last ~330 B is two TLV "partition info" records
        ('System Reserved' UTF-16, 'Volume3' / 'Volume4', etc.)
        and the bulk is the SequentialChunkMap records.
```

The ~60 KB chunk-map size for miner1 is plausible: 8 GB / 256 KiB = 32 K
blocks × 12 B = 384 KB raw, zlib-compressing to roughly 60 KB given the
low-entropy delta-encoded structure.

### Verdict on "is there an index?"

**There IS a random-access index**: the on-disk SequentialChunkMap has
the same 12-byte zigzag-delta record layout as ExtraFileChunkMap.
"Sequential" in the name refers to the BLOCK STREAM being laid down
sequentially (no out-of-order reordering — that's a hybrid feature
introduced by the parallel-compressor pipeline in TI 2018+). The chunk
map exists to handle the sparse case (blocks where the bitmap shows some
clusters absent need a way to look up which file_offset stores the
remaining clusters, even though they're sequential by partition_block).

A naive third-party reader can also do **pure sequential scan**: walk
forward through the file from offset 32, decode each `[8B preamble][zlib
stream]` back-to-back, and count blocks. This works for full-volume
restore (all 32 K blocks present) but fails for sparse-volume blocks if
sparse-block-count > 0 (because the preamble of a sparse block has fewer
than 64 set bits and the next block's `file_offset` depends on how many
clusters were stored, which varies). The chunk map provides O(1)
random-access without scanning.

---

## Trailer — structural differences

Modern (TI 2018+, per FORMAT.md):

```
... block stream ...
... post-data streams (chunk map, MD5 manifest, LDM, XML) ...
[3.16 MB tail terminator]   51 bytes
[metadata blob]            ~780 bytes (TLV)
[sector trailer]            41 bytes (TLV-ish, contains metaDataOffset & fullSize)
[trailer size+magic]         8 bytes (u32 size=0x29, u32 0x94E18A2B)
[padding]                   52 bytes (zeros)
[volume footer]             48 bytes (mirror + sliceSize64)
```

Legacy (TI 2014, miner1):

```
... block stream ...
... metadata blob (TLV records + SequentialChunkMap zlib stream) ...
[zero alignment gap]      ~24 KB
[mini-trailer]              16 bytes
       +0  u32 zero
       +4  u32 volumeId
       +8  u32 metaDataOffset
      +12  u32 fullSize_or_count
[volume footer]             32 bytes (byte-reversed mirror of 32-byte header)
```

Differences from modern:

- **No 41-byte sector trailer body.** Modern has a TLV-ish trailer with
  multiple records (timestamps, slice info, etc.); legacy has only the
  minimal 16 bytes.
- **No `0x94E18A2B` trailer-magic / size pair.** Modern places these 8
  bytes between the trailer body and the final footer; legacy has no
  equivalent — the footer (mirror header) is preceded directly by the
  16-byte mini-trailer (and any zero padding).
- **Mirror is 32 bytes, not 48 bytes.** Modern's footer is 48 bytes (32 B
  mirrored header + 16 B sliceSize64); legacy's footer is exactly 32
  bytes (just the mirrored header). There is no `sliceSize64` field.
- **No post-data streams.** Modern has 7 streams (chunk map, preamble
  mirror, LDM primary/secondary, XML metadata, two mini-descriptors).
  Legacy only has the metadata-blob region containing the chunk map and
  partition-info TLVs. No MD5 dedup table, no LDM, no XML metainfo, no
  cuckoo filter.

A reader that wants to support both must:

1. Read the volume header (32 B from offset 0). If `header_length != 0x20`
   bail (or handle Mac).
2. Read the last 32 bytes; if they byte-reverse-match the header, this is
   either format.
3. Look at byte `(filesize - 33)` (just before the mirror) backwards. If
   you see the modern pattern (`0x94E18A2B` magic dword at known offset
   relative to footer), it's modern. Otherwise legacy.
4. Locate the metadata blob:
   - Modern: parse the 41-byte trailer for the `metaDataOffset` /
     `fullSize` records (length-prefix-encoded varints).
   - Legacy: read the 16 bytes immediately before the mirror; the u32 at
     +8 is `metaDataOffset`. The descriptor size is `(filesize - 48) -
     metaDataOffset` (the blob ends just before the mini-trailer +
     padding).
5. Parse the metadata blob:
   - Look up TLV tag `0x9b`. Present → modern; absent → legacy.

(Note: per `FORMAT.md`, modern uses a 6-byte length-prefix for
metaDataOffset; legacy uses a fixed 4-byte u32 in the mini-trailer at
offset +8. Both `tibread`'s existing trailer-parsing code paths
generalise correctly when the prefix is "5 bytes" vs "6 bytes", but
the LEGACY case is simpler and not actually a length-prefix at all —
it's a fixed u32 at a fixed position.)

---

## Metadata blob TLV

Both formats use Acronis's TLV grammar (`FUN_089974c0` reader), but the
tag set differs.

Tags read by `SequentialChunkMap::ctor` (FUN_08982090):

| Tag | Meaning (inferred from offset and size) | Stream-struct word index |
|---|---|---|
| 2 | Block-stream metadata field A | [0xB] (= byte 0x2C) |
| 3 | **Clusters per block** (= 64 in TI 2014) | [0xC] (= byte 0x30) |
| 4 | Block-stream metadata field B | [0xD] (= byte 0x34) |
| 5 | Block-stream metadata field C | [0xE] (= byte 0x38) |
| 6 | **Record count** for chunk map | [0x8] (= byte 0x20) |
| 7 | (read into a local; transient) | — |
| 0xD4 | Boolean flag | byte +0x40 |

Tags read by `HybridImageStream::ctor` (FUN_0898bd50, modern):

| Tag | Stream-struct field |
|---|---|
| 2 | +0x10 |
| 3 | +0x68 |
| 4 | +0x6C |
| 5 | +0x78 |
| 6 | +0x7C / +0x130 (depending on 0x9c presence) |
| 7 | local |
| 0x14 | +0x74 |
| 0x8C | +0x70 |
| 0x9B | **(presence-only — the legacy/modern discriminator)** |
| 0x9C | +0x128 |
| 0xD2 | +0x12C |

The legacy tag set is a strict subset of the modern set, with **`0x9B`,
`0x9C`, `0xD2`, `0x14`, `0x8C` all absent** — only the basic
`{2,3,4,5,6,7}` plus the `0xD4` flag.

(Tag-name-to-semantic mapping for `2..7` is provisional; their absolute
semantics aren't documented in `METADATA_BLOB_TLV.md` and weren't
chased to ground in this pass — knowing which struct field each lands in
is sufficient for a working reader.)

---

## product.bin Ghidra anchors

| Address | Symbol | Source | Role |
|---|---|---|---|
| `0x08973290` | (anonymous) | `image_stream.cpp` | **Format dispatcher** — checks tag `0x9b`, picks Sequential vs Hybrid |
| `0x08977a70` | `SequentialImageStream::ctor` | `image_stream_sequential.cpp` | Builds the legacy stream; sets defaults `+0x10=0x3F`, `+0x11=0x0F` |
| `0x08982090` | `SequentialChunkMap::ctor` | `openimg.cpp` | Parses legacy metadata blob: TLV (tags 2-7, 0xD4) + 12-byte zigzag-delta records |
| `0x08982860` | `HybridChunkMap::ctor` | `openimg.cpp` | Modern record-size 0x14 chunk map (one of three modern-format flavours) |
| `0x08983090` | `DiskChunkMap::ctor` | `openimg.cpp` | Modern disk-level chunk map |
| `0x089839b0` | `ExtraFileChunkMap::ctor` | `openimg.cpp` | Modern file-level chunk map (the one we already had cracked) |
| `0x08ad1290` | `RemovePoints::Create` | `remove_points.cpp` | **Map-type dispatch** for slice-removal (and by composition, for chained reads): `*piVar7 == 0` → SequentialChunkMap; `==1` → Hybrid; `==2` → Disk |
| `0x08adba60` | `RemovePoints` body (sniffer) | `remove_points.cpp` | Branches on stream-instance flag at byte offset `+0x65` to choose Hybrid vs (anonymous Modern) opener at the slice level |
| `0x091f6780` | `ConvertFromLegacyFormat` | `container_convert.cpp` | **Different (even older) legacy** — converts ancient containers in-place. Gate: `version==1`, `+0x1c==0x1000`. **Does NOT apply to TI 2014/miner1**. |
| `0x082160c0` | `CheckVolumeHeader` | `archive_struct_helper.cpp` | Validates one of three magic words; **no version-based dispatch** |
| `0x089974c0` | TLV-tag lookup | (inline in metadata reader) | The `tag_present?` query used by the dispatcher |
| `0x08999130` | matrix-transpose | (inline) | Same helper used by both Sequential and Extra chunk-map decoding |

The four `BackupImageOpener::*ChunkMap` classes have name strings at
`0x0956bc34..0x0956bc70`:

```
0x0956bc34  "ExtraFileChunkMap"
0x0956bc48  "DiskChunkMap"
0x0956bc58  "HybridChunkMap"
0x0956bc70  "SequentialChunkMap"
```

…with full mangled typeinfo names at `0x0956bca0..0x0956bd60`. This
quartet is the canonical list of sector-mode chunk-map flavours in TI
2018+'s codebase. There is no fifth, ancient-er flavour — files older
than what `SequentialChunkMap` handles route through
`ConvertFromLegacyFormat` (a separate translation unit) before they hit
the openimg.cpp readers at all.

---

## Confidence levels

| Finding | Source |
|---|---|
| Format dispatcher = TLV tag 0x9b | **Decompiled** (FUN_08973290) |
| Sequential/Hybrid/Disk/ExtraFile = the four chunk-map classes | **Decompiled** + string anchors |
| Legacy chunk-map records are 12-byte zigzag-delta with same transpose | **Decompiled** (FUN_08982090) |
| `ConvertFromLegacyFormat` is a SECOND legacy tier targeting older files | **Decompiled** (FUN_091f6780) |
| Miner1 is read via SequentialImageStream, not ConvertFromLegacyFormat | **Decompiled** + empirical (header values fail ConvertFromLegacy gate) |
| 8-byte preamble, 64-cluster blocks | **Empirical** (miner1 first block decompresses cleanly) |
| Clusters-per-block stored in TLV tag 3 | **Decompiled** (FUN_08982090 stores tag 3 at stream `[0xC]`, which is the bitmap multiplier) |
| Mini-trailer layout (16 B before mirror, no 0x94E18A2B magic) | **Empirical** (miner1 trailer dump) |
| metaDataOffset at trailer +8 = blob-region file offset | **Inferred** from the field's plausible value (~187 MB) and matches the blob-region density profile; not byte-validated end-to-end |
| Chunk map size ~60 KB at end of miner1 file | **Empirical** (1KB-bucket density profile) |
| Chunk map records compressed with zlib | **Inferred** (raw 12B records would be 384 KB, compressed dense region is ~60 KB; ratio matches) — not byte-decoded in this pass |
