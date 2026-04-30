# Acronis True Image `.tib` (sector-mode) — legacy variant (TI 2014/2015/2016)

Companion to `FORMAT.md`, which describes the modern (TI 2018+) sector-mode
layout. This document is the consolidated user-facing spec for the **legacy**
sector-mode `.tib` format that TI 2018+ retains read-only support for.

Empirically validated against `/path/to/legacy_example.tib`
(8.78 GB, January 2014, Acronis True Image 16 build 6514) and cross-checked
against decompilation of `product.bin`'s `SequentialImageStream` /
`SequentialChunkMap` constructors.

For the play-by-play of how this format was reverse-engineered, see the
historical investigation notes in `docs/legacy/`:

- `FORMAT_LEGACY_BLOCKS.md` — empirical block-stream walk
- `FORMAT_LEGACY_METADATA.md` — TLV decode of the trailing metadata blob
- `FORMAT_LEGACY_TAIL.md` — post-block-stream MD5 dedup manifest
- `FORMAT_DISK_CHUNKMAP.md` — DiskChunkMap (whole-disk-image variant)

For even-older files (TI 2010-2013), see `FORMAT_VERY_LEGACY.md`.

---

## Identifying a legacy `.tib`

The volume header is **identical** to the modern format: same magic
`0xA2B924CE`, same `header_length=0x20`, same Adler32 layout. The variant is
**not** identifiable from the header alone.

The discriminator lives in the trailing metadata blob: presence/absence of
**TLV tag `0x9b`**.

```
modern  : metadata blob contains tag 0x9b  (whose body is the chunk-map locator)
legacy  : metadata blob does NOT contain tag 0x9b
```

`product.bin`'s `FUN_08973290` (the `ImageStream` dispatcher) routes on this
exact test:

```c
if (tag_present(metadata_blob, 0x9b)) {
    new HybridImageStream(...);   // modern: 16B preamble + 128 cpb
} else {
    new SequentialImageStream(...); // legacy: 8B preamble + 64 cpb
}
```

A reader's practical detection: try to find the modern 13-byte chunk-map
locator signature `06 V[6] 01 00 03 S[3]` in the metadata blob. Present →
modern; absent → legacy. (See `tibread.chunkmap_locator.detect_format_era`.)

---

## File-level layout

```
+0x00  [volume header]            32 bytes  (same as modern)
+0x20  [block stream]              ~99% of the file
         block + block + ... + [inline metadata #1] + ... + [inline metadata #N]
       [post-block-stream tail]   ~3 MB on the test file
         [MD5 dedup manifest]     16-byte hash per stored block
         [residual region]        partial / undocumented streams (small)
       [metadata blob]            921 bytes (TLV) on the test file
       [sector trailer]           37 bytes (TLV)
       [size + magic]              8 bytes (u32 trailer_size, u32 0x94E18A2B)
       [padding]                  ~130 bytes (zeros)
       [volume footer]            48 bytes (16B sliceSize64 + 32B mirror)
```

Outer skeleton (footer, `[size][magic]` framing, 48-byte volume footer with
`sliceSize64` at +8) is **the same as modern**. Differences from modern:

- Block geometry: 8-byte preamble + 64-cluster blocks (vs. 16B + 128).
- Chunk map: split into multiple **inline `SequentialChunkMap` records**
  interleaved with the block stream (vs. a single dedicated post-data stream).
- Trailing metadata: 921-byte blob with embedded zlib streams (vs. 780-byte
  blob + a separate 7-stream post-data region).
- Trailer body: 37 bytes (vs. 41).
- Post-block-stream tail: ~3 MB of MD5 dedup manifest + a small residual
  region (vs. ~42 MB region with chunk map, MD5 manifest, cuckoo filter,
  LDM, XML, mini-descriptors).

---

## Volume header

Identical to modern; see `FORMAT.md`. The `version` field at +0x06 is `0` for
Windows-source legacy archives (same as modern Windows). It is **not** what
triggers the legacy reader — that's the missing TLV tag `0x9b`.

The Adler32 at +0x18 is computed and validated identically.

---

## Block stream

Each block:

```
[8-byte preamble]  64-bit cluster-presence bitmap (LSB-first within each byte)
[zlib stream]      The present clusters, concatenated, deflated (78 01)
```

- Preamble bit `i` is set iff cluster `(block_idx * 64 + i)` is stored.
- Decompressed payload size = `popcount(preamble) * 4096` bytes.
- Zlib mode is `78 01` ("no compression preset").
- Block size when fully populated: 64 × 4096 = **256 KiB**.

Blocks are back-to-back with no padding except for the inline-metadata records
described below.

### Empirical statistics (example)

| Metric | Value |
|---|---|
| Block count | 70,709 |
| Full blocks (popcount = 64) | 96.69% |
| Partial blocks | 3.31% |
| All-zero preamble blocks | 0 (sparse is encoded by clearing bits, never by emitting empty blocks) |
| Compression ratio | 47.95% (~2.1× deflated) |

---

## Inline `SequentialChunkMap` records

The legacy chunk map is **split into multiple inline records interleaved with
the block stream**, each describing the blocks **preceding** it. There is no
single dedicated chunk-map region.

### On-disk format of one inline record

```
[u8 L]                  TLV section length (1 byte!)
[L bytes]               TLV records (Acronis u16-LE-tag grammar)
[zlib stream]           One zlib stream → (count × 12) bytes inflated
                        → matrix-transposed (column-major → row-major, N×12)
                        → 12-byte records: { u64 zigzag-delta file_offset, u32 length }
                        → zigzag-delta accumulator carries across records
```

The zlib + matrix-transpose + zigzag-delta encoding is **structurally
identical to the modern `ExtraFileChunkMap`** (`FORMAT.md` Stream 0). Acronis
uses the same matrix-transpose helper (`FUN_08999130`) for both.

Zigzag decode: bit 0 of the 64-bit raw word is the sign; magnitude is the
remaining 63 bits (`raw >> 1`). Negative deltas use plain `-mag`, **not**
`-mag-1`.

### TLV tag dictionary (in the L-byte preamble)

Tags read by `SequentialChunkMap::ctor` (`FUN_08982090`):

| Tag    | Meaning                          | example value |
|--------|----------------------------------|---|
| `0x02` | sector size (bytes/sector)       | `0x200 = 512` |
| `0x03` | sectors per cluster              | `0x08 = 8` |
| `0x04` | **clusters per block**           | `0x40 = 64` |
| `0x05` | (optional; semantics unconfirmed — likely compression alg id) | absent |
| `0x06` | record count (12-byte records)   | 135 / 259,108 |
| `0x07` | (optional; transient / unconfirmed) | absent |
| `0xD4` | boolean flag (length-0 = "set")  | absent |

Derived geometry: cluster size = `tag2 × tag3` = 512 × 8 = 4096 B. Block
payload = `tag2 × tag3 × tag4` = 256 KiB.

> **Note**: an earlier draft of this document mis-mapped tag 3 as
> "clusters per block". The correct mapping (confirmed by both
> decompilation and example byte-decode) is **tag 4 = clusters per block,
> tag 3 = sectors per cluster, tag 2 = bytes per sector**.

### Sample record locations (example)

```
inline #1 @ file offset 10,431,214
   L=0x11; TLV: tag2=512, tag3=8, tag4=64, tag6=135
   zlib: 338 bytes compressed → 1,620 bytes inflated (135 × 12)
   covers 135 blocks, concat range [0x685, 0x9eeb1a]

inline #2 @ file offset 8,773,374,742
   L=0x13; TLV: tag2=512, tag3=8, tag4=64, tag6=259108
   zlib: 316,334 bytes compressed → 3,109,296 bytes inflated (259108 × 12)
   covers 259,108 records up to concat = (inline_offset - data_start) exactly
```

(Records 12-byte width applies; the 259,108 figure dominates because TI 2014
flushes most of the chunk map only at end-of-stream. The "12 bytes × 70,709
blocks ≠ 259,108" disparity is because each record is per-LCN-batch, not
per-block — the chunk map indexes by partition-block index across the full
volume, including sparse runs.)

### Locating inline records when reading

1. Start at `data_start = 32`. Each step: read 8 bytes (preamble), then a
   zlib stream (use `decompressobj` and stop at `eof`).
2. After each zlib stream, peek the next byte. If it is a small u8 in
   `[8..32]` and a `78 01` zlib magic appears within ~24 bytes, the record
   is an inline `SequentialChunkMap`: parse `[u8 L][L bytes TLV][zlib]`,
   inflate, decode records, advance past the inline record.
3. Otherwise treat the next byte as the start of another block preamble.

Validation: any candidate preamble must decompress cleanly to a multiple of
4096 bytes ≤ `popcount(preamble) × 4096`.

In practice, a reader can either walk sequentially (gathering all inline
chunk maps as it goes) or — once the geometry and the file size of the
block-stream end is known — seek directly to the LAST inline record (which
is just before the post-block-stream tail) and pull the cumulative chunk
map from there. `tibread.chunkmap_legacy.discover_inline_chunkmaps_legacy`
does the latter.

---

## Post-block-stream tail (~3 MB on example)

After the last inline `SequentialChunkMap` record, the file contains a
**MD5 dedup manifest** followed by a small **residual region**, then the
metadata blob.

### MD5 dedup manifest

A flat array of 16-byte MD5 digests, one per stored block, in storage order.
Each digest = `MD5(preamble || decompressed_block)` — same construction as
the modern format, just with the legacy 8-byte preamble.

This region was **mistakenly identified as encrypted** in early RE notes
because it contains many repeats of `e9e66cc...` — that hash is the canonical
"all-zero block" digest:

```python
hashlib.md5(b'\xff'*8 + b'\x00'*(64*4096)).hexdigest()
# 'e9e66ccfeac74dfd4040aedc086a29b0'
```

The MD5 manifest in the tail is **contiguous** and covers **all stored
blocks 0..N-1** in storage order. There is **no** inline MD5 fingerprint
batch — the inline records earlier in the file serve a different purpose.

Inline records #1 and #2 are **split SequentialChunkMap fragments**, not
MD5-fingerprint batches. Each has the structure
`[u8 L][L-byte TLV header][zlib stream of 12-byte chunk-map records]`
(e.g. on example: TLV tags `0x02=512`, `0x03=8`, `0x04=64`, `0x06=record_count`).
Inline #1 = 356 bytes on disk → 135 chunk-map records; inline #2 → 259,108
chunk-map records. Together they index all 259,243 stored extents — they
are an *extent map*, not a hash batch.

### Residual region

The remaining ~1.9 MB after the manifest is a multi-stream container with
high-entropy blobs separated by small TLV records. Structurally analogous
to (but not identical to) the modern format's post-data region.
Contents are **not yet fully decoded**; documented in
`FORMAT_LEGACY_RESIDUAL.md`. Not load-bearing for reading the block
stream — `tibread` ignores it.

The legacy format does **not** have the modern format's cuckoo filter.

---

## Metadata blob (921 bytes, TLV)

Located between the residual region and the trailer body. Structure:

```
blob_off  contents
0..17     pre-zlib TLV (start-of-blob marker + section delimiters)
18..38    embedded ZLIB stream #1 → 20 bytes (3 LE u32 + padding)
                                      [0]=0x1644d128 hash/CRC (?)
                                      [1]=0x00000004
                                      [2]=0x0000e4e4 = chunk-map zlib comp_size
39..236   embedded ZLIB stream #2 → 239 bytes <metainfo> XML
237..272  36 bytes opaque (likely encryption-recovery / hash region)
273..end  main TLV stream: ~63 records (volume info, GUIDs, partition list)
```

The `<metainfo>` XML carries product version + task_id GUID:

```xml
<metainfo>
  <productinfo name="True Image">
    <version major="16" minor="0" />
    <build number="6514" />
  </productinfo>
  <task_id id="C1133A11-4824-4C42-8DD6-8A7264522492" />
</metainfo>
```

(Modern stores this XML in a separate post-data stream; legacy embeds it
inside the trailing metadata blob.)

The blob also contains a 1-record `DiskChunkMap`-style descriptor in
embedded ZLIB stream #1: `(file_offset = last_block_start, length =
last_block_compressed_size, extra = 0)`. This is a "last-block bookmark"
marker, not a usable random-access map.

### TLV grammar quirks specific to legacy

The standard tag/sub/length grammar applies (see `tibread.metadata`), with
**one variant**:

> If the **sub byte equals `0x05`**, the record is exactly **7 bytes long**:
> `tag + 0x05 + 5-byte payload` with **no length byte**. The `0x05` doubles
> as a sub-tag indicator and an implicit "5-byte fixed payload" hint.

This `(tag, 0x05)` form is used for 5-byte LE timestamps/offsets.

Tags **absent** in legacy that are present in modern:

- `0x9B` — modern format presence flag (the discriminator)
- `0x9C`, `0xD2` — modern stream geometry
- `0xA8` — computer GUID
- `0xA9` — LDM disk-group name
- The 13-byte chunk-map locator `06 V[6] 01 00 03 S[3]` is **never** present.

---

## Trailer body (37 bytes, TLV)

5-byte length-prefix grammar. Five records:

| Offset | Tag    | Meaning |
|---|---|---|
| 0  | `0x00`     | metaDataOffset (5-byte LE; in concat coords) |
| 8  | `0x01`     | unknown u16 |
| 13 | `0x00.80`  | partition size (5-byte LE) |
| 21 | `0x01.80`  | mirror of `0x00.80` |
| 29 | `0x07.80`  | self-pointer (= metaDataOffset value, points past the embedded zlib streams) |

Followed by:

```
[u32 trailer_size = 37]   (LE)
[u32 0x94E18A2B]          sector-mode magic — present and identical to modern
```

> **Correction**: an early RE note claimed the legacy file had no
> `0x94E18A2B` magic and a 16-byte mini-trailer + 32-byte footer. **That
> was wrong.** The end-of-file structure is the same as modern; only the
> trailer body length and metadata blob contents differ.

---

## Reading algorithm summary

1. Parse volume header (32 B at offset 0). Validate Adler32.
2. Read 48-byte volume footer. `sliceSize64` is at footer offset +8 (u64 LE).
3. Read 8 bytes at `data_start + sliceSize64 - 8` to get
   `(trailer_size, magic)`. Magic must be `0x94E18A2B`.
4. Read trailer body (`trailer_size` bytes). Parse the 5-byte
   length-prefix grammar to get `metaDataOffset`.
5. Read the metadata blob from `data_start + metaDataOffset` to the start
   of the trailer body.
6. Search the blob for the 13-byte modern locator
   `06 V[6] 01 00 03 S[3]`:
   - **Present → modern.** Hand `(V, S)` to the `ExtraFileChunkMap` decoder.
   - **Absent → legacy.** Walk back through the file from the metadata
     blob and locate the LAST inline `SequentialChunkMap` record. Decode
     it for the chunk map of the bulk of the block stream; combine with
     any earlier inline records for the front of the stream.
7. With the chunk map in hand, random-access reads are O(1).

For full restore (no random access required), a sequential walk of the
block stream — collecting inline records as it goes — is also sufficient
and avoids the chunk-map decode entirely.

---

## Index file format used by `tibread`

`tibread`'s on-disk index for legacy files uses `TIBIDX03` (geometry-explicit
header):

```
[b"TIBIDX03"]                                     8 B
[u64 tib_size][u64 data_start][u64 data_end]
[u64 block_count]
[u32 clusters_per_block][u32 preamble_len][u64 reserved_flags]
block_count × { u64 file_offset, preamble_len-byte preamble, u32 comp_len }
```

For example: `clusters_per_block=64`, `preamble_len=8`. The modern format
continues to use the older `TIBIDX02` (fixed 16-byte preamble, 128 clusters
per block) for backward compatibility.

The legacy build is slow on first open — it has to walk most of the block
stream to discover the inline chunk maps. ~4 minutes for an 8 GB file. The
index is cached as a sidecar `.idx` next to the `.tib`; subsequent opens are
instant.

---

## Confidence summary

| Finding | Source |
|---|---|
| Format dispatcher = TLV tag `0x9b` | Decompiled (FUN_08973290) |
| 8-byte preamble + 64-cluster blocks | Empirical + decompilation (TLV tag 4 = 64 in example) |
| TLV tag 4 = clusters/block (NOT tag 3) | Empirical (corrected from earlier draft) |
| Chunk map records are 12-byte zigzag-delta + matrix transpose + zlib | Decompiled + empirical (135/135 + 259108/259108 records validated against block-stream offsets) |
| Chunk map lives INLINE in the block stream | Empirical (corrected from earlier draft) |
| Same 48-byte footer + `0x94E18A2B` trailer magic as modern | Empirical (corrected from earlier draft) |
| MD5 dedup manifest in the post-block-stream tail | Empirical (200/200 sampled block hashes match) |
| Canonical zero-block hash `e9e66cc...` = `MD5(0xFF*8 || 0x00*64*4096)` | Empirical |
| 5-byte length-prefix grammar for trailer body & blob | Empirical + decompilation |
| `(tag, 0x05)` = 7-byte fixed-length record (no length byte) | Empirical (decoded 921-byte blob to 63 records, 0 leftover bytes) |
| No cuckoo filter in legacy | Empirical (bit-density and byte-frequency stats rule it out) |
| Tag 5 / tag 7 / tag 0xD4 semantics | Decompiled (read by ctor) but not seen in test sample |

---

## product.bin Ghidra anchors

| Address | Symbol | Source |
|---|---|---|
| `0x08973290` | (anonymous) `ImageStream` dispatcher | `image_stream.cpp` |
| `0x08977a70` | `SequentialImageStream::ctor` | `image_stream_sequential.cpp` |
| `0x08982090` | `SequentialChunkMap::ctor` | `openimg.cpp` ~ line 0x60 |
| `0x08983090` | `DiskChunkMap::ctor` | `openimg.cpp` line 0xba |
| `0x089839b0` | `ExtraFileChunkMap::ctor` (modern) | `openimg.cpp` ~ line 0x140 |
| `0x089974c0` | TLV tag lookup | (inline in metadata reader) |
| `0x08999130` | matrix-transpose helper | (inline; shared with modern) |
| `0x08ae2b30` / `0x08ae49e0` | `ZLibDecompressor` (zlib 1.2.8) | `compress/zlibdf_d.cpp` |
| `0x091f6780` | `ConvertFromLegacyFormat` (very-legacy migration; NOT used for TI 2014) | `container_convert.cpp` |
