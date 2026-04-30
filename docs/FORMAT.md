# Acronis True Image `.tib` (sector-mode) — format specification

**Generation covered**: Acronis True Image v23.x (Acronis True Image 2018+).
Verified against build 17750. Older generations (TI 2014, TI 2018 early
builds) are similar but may differ in trailer encoding; see "Format variants".

This spec captures the on-disk layout sufficient to read a sector-mode `.tib`
without any Acronis software. It's the consolidated output of about 25
reverse-engineering sub-investigations (see `RE_HISTORY.md`).

## File-level layout

```
+0x00  [volume header]      32 bytes  (Mac: 36)
+0x20  [block stream]        ~99% of the file
       [post-data region]    42.5 MB on a typical 1 TB backup
         [stream 0]                Chunk map               (compressed)
         [stream 1]                Preamble mirror         (compressed)
         [stream 2]                LDM primary             (compressed)
         [stream 3]                LDM mirror              (compressed)
         [stream 4]                XML metainfo            (compressed)
         [mini-descriptor 1]                              20 bytes
         [mini-descriptor 2]                              20 bytes
         [37 MB MD5 manifest]      Per-block MD5 array
         [3.16 MB cuckoo filter]   Cross-archive dedup filter
         [3.16 MB tail terminator] 51 bytes
       [metadata blob]       780 bytes (TLV)
       [sector trailer]       41 bytes
       [size + magic]          8 bytes (u32 trailer_size, u32 0x94E18A2B)
       [padding]              52 bytes (zeros, alignment)
       [volume footer]        48 bytes (byte-reversed mirror of header + sliceSize64)
```

## Volume header (32 bytes)

```
0x00  u32   magic           = 0xA2B924CE   (sector-mode .tib)
0x04  u16   header_length   = 0x20 (Win) / 0x24 (Mac)
0x06  u16   version         = 0 (Win) / 1 (Mac)
0x08  u64   archiveId       LE; matches Master_.archiveId_ in the catalog DB
0x10  u32   volumeId        LE; matches Volume_.volumeId_ in the catalog DB
0x14  u32   sequence        1-based volume index for multi-volume splits (1 = single-volume)
0x18  u32   adler32         zlib.adler32 over header[:hdr_len] with [0x18..0x1C] zeroed
0x1C  u32   block_align     32 on Windows
```

`archiveId` + `volumeId` are catalog identifiers, NOT random nonces. Two `.tib`
files with the same `archiveId` belong to the same backup chain. (Older RE
notes called these "archive_key" / "slice_key" / "volume_key" — they're not
keys.)

The four alternative magics `CheckVolumeHeader` accepts:

| Magic        | Meaning                                                |
|--------------|--------------------------------------------------------|
| `0xA2B924CE` | Sector-mode `.tib` (this spec)                         |
| `0x44686EB4` | Filesystem-mode v2 `.tib` (different layout — TODO)    |
| `0x8F5C36C6` | Filesystem-mode v1 `.tib` (older — TODO)               |
| (footer)     | `0x179631B4` for tape-archive variants                 |

`.tibx` (Acronis True Image 2020+) is a **different container format** entirely
— first 4 bytes are `41 01 00 00` (`0x141`), with ASCII `QARCH` at offset 7.
It uses an SQLite-backed archive layout instead of the volume-header-then-
block-stream model documented here, and is **not** decodable by this reader.

## Block stream

Each block:
```
[16-byte preamble]  128-bit cluster-presence bitmap (LSB-first)
[zlib stream]       The present clusters, concatenated, deflated
```

The zlib payload size for a "stored" block is `popcount(preamble) × 4096 +
overhead`, where overhead is:
- **62 bytes** when popcount < 128 (8 deflate STORED sub-blocks)
- **67 bytes** when popcount = 128 (9 deflate STORED sub-blocks — needed for the
  trailing 8 bytes that don't fit in 8 × 65535)

99.22% of stored blocks have popcount = 128 (fully populated). 15.35% are
zlib-compressed proper (BTYPE=10, dynamic Huffman) instead of literal STORED;
this happens for blocks with highly redundant content like NTFS MFT-zone
zero-fill.

Block boundaries are back-to-back with no padding.

## Sparse-block decision (backup-time algorithm)

`region_sparser.cpp::SparsedRegions` is an rb-tree of `<start, end>` byte-ranges
representing what's omitted as sparse. It starts as one range covering the
whole partition; the orchestrator `Exclude()`s "live" extents:
- For NTFS partitions, eight regions are always included: the primary
  file-data extent + 7 metadata files (`$MFT`, `$MFTMirr`, `$LogFile`,
  `$Volume`, `$AttrDef`, `$Bitmap`, `$Boot`).
- `Exclude()` is 4 KB-page-aligned and merges adjacent ranges within 64 KB.
- Empirically: a typical 1 TB user volume has ~400 sparse runs covering
  millions of partition_blocks (vs. millions of independent runs if it were
  per-cluster).

Within a stored partition_block, the 16-byte preamble bitmap encodes the
intra-block sparseness (consulted from the source NTFS `$Bitmap`). 99.22%
of stored blocks have all 128 bits set.

## Post-data region (42.5 MB on a 1 TB backup)

Discovered positionally by walking from the metadata blob's chunk-map locator
backwards. There's no offset table in the header — each stream has a 18- or
20-byte preamble identifying its size, and they pack back-to-back.

### Stream 0 — chunk map (the critical one)

The authoritative `partition_block → file_offset` table. Without this you
can't random-access the block stream because Acronis stores blocks slightly
out of order (~4% of blocks are pairwise-swapped due to backup-time parallel
compressor pool).

**Encoding** (innermost first):
1. 12-byte records `{u64 enc_offset_delta, u32 length}`. `length=0` ⇒ sparse.
2. **Zigzag-delta** on the offset: each record stores the delta from the
   previous record's `(offset + length)`, zigzag-encoded so small ± values
   pack into few bytes.
3. **Byte-wise matrix transpose** — the N×12 byte array is transposed
   column-major → row-major before deflate. This groups all "byte-0 of every
   record" together, etc., dramatically improving deflate's compression
   ratio (10×+ on this data).
4. **zlib outer wrapper** (deflate).

For the test 1 TB `.tib`: 5,722,918 records (one per 64 KB partition_block),
2.3M stored, 3.4M sparse, 1.84 MB compressed → 68 MB plaintext.

The chunk-map's location and size are encoded in the 780-byte metadata blob
by a 13-byte signature `06 <V:6 LE> 01 00 03 <S:3 LE>`, where `V` is the
chunk-map TLV start in concat coords and `S` is total region size including
its own preamble. See `chunkmap_locator.py` for the parser.

### Stream 1 — preamble mirror

A redundant copy of every stored block's 16-byte preamble bitmap, concatenated.
Defense-in-depth in case the inline preambles are damaged. Size: stored_block_count × 16.

### Streams 2 + 3 — Windows LDM primary + mirror

The Windows Logical Disk Manager (dynamic-disk) database from the source.
Each is 264 KB plaintext, encoded as 512 disk sectors of 516 bytes each
(`u32 LBA + 512B sector body`). After unwrapping, parses as standard LDM
(TOCBLOCK + VMDB + VBLK records).

For a basic-disk source, this stream is mostly zeros. For a dynamic-disk
source (RAID-1 mirror, RAID-0 stripe, spanned volume, etc.), it captures
disk-group GUID, per-disk GUIDs, volume GUID, mirror/stripe topology, drive
letter — information that's otherwise unrecoverable from the collapsed NTFS
image.

### Stream 4 — XML metainfo

778 bytes plaintext UTF-8 XML. Contains:
- Acronis True Image build number and version
- task_id GUID (chain identifier)
- computer_id GUID (source machine)
- file-category statistics (pictures / music / video / documents / system / other)
- compression and encryption flags

Useful as ground truth for chain membership cross-validation.

### 40 MB MD5 manifest

A flat array of 16-byte MD5 digests, one per stored block, in storage order
(NOT partition order). Each digest = `MD5(preamble || decompressed_block)`.
Used for:
1. Cross-archive dedup: when an incremental backup runs, blocks are MD5'd
   on read; matches against this manifest are stored as back-references
   instead of fresh data.
2. Integrity audit: verify backup is unmodified.

The 4,465 occurrences of `8d65beed7b7a6a9a0fd84512ec85ba17` are the canonical
"zero block" hash (`MD5(0xFF*16 || 0x00*524288)`).

### 3.16 MB cuckoo filter

An 8-bit fingerprint cuckoo filter (790,843 buckets × 4 slots × 8 bits) used
as a fast tier-1 dedup filter for the next incremental backup. The actual hash
function couldn't be statically reverse-engineered (custom mixer with per-archive
seed, lives in `ChunkMapAndHashImpl::PreviousBackupDedup::FindHashByKey`);
runtime instrumentation would close it.

### Mini-descriptors

Two 20-byte zlib-compressed descriptor records between streams 2/3 and 3/4.
Format: `[u32 fingerprint][u16 0x0214][u16 0][u32 prev_compsize][8 zero bytes]`.
Cross-check between streams.

## Metadata blob (780 bytes, TLV)

Three interleaved encodings:
1. 80-byte fixed header (4 × 16-byte GUID/hash quad, opaque)
2. `0x004D` 96-byte container = encryption-recovery / verifier (32-byte SHA256
   verifier + offset records + version 541 timestamp)
3. Generic TLV records: `tag(u16 LE) + length(u8 short ≤127, or extended:
   ((b0 & 0x7F) << 8) | b1, BE) + payload`

About 62 distinct tags, including:
- Computer GUID (`0x00A8`), volume GUID (`0x006A`), per-disk GUIDs (`0x06.80`)
- Drive letter (`0x006B`), volume label UTF-16 (`0x00CB`), backup type (`0x00BA`)
- Three (offset, size) pairs pointing to post-data streams
- Bridge region with the chunk-map locator (per agent A's discovery)

The TLV grammar is implemented in `metadata.py`.

## Sector trailer (41 bytes) + size/magic

Right before the volume footer:
- 41-byte trailer body (TLV-ish, contains metaDataOffset and fullSize)
- `u32 trailer_size`
- `u32 0x94E18A2B` — sector-mode magic (`0x94E18A2C` for filesystem-mode)

## Volume footer (48 bytes)

Byte-reversed mirror of the volume header in the last `header.length` bytes
(NOT bit-reversed — the mirror is `header[::-1]`). The other bytes encode
`sliceSize64` (uncompressed slice payload size).

## Multi-volume splits

When a single `.tib` file would exceed a configurable size threshold (the
`split_size` archive option), Acronis splits across multiple files named
`<archive>_<TYPE>_b<B>_s<S>_v<V>.tib` with V = 1, 2, 3, ...

Each `_v<N>.tib` is a self-contained file with the standard 32-byte header
+ 48-byte footer; only `sequence` and `adler32` differ between volumes.
The `archiveId` and `volumeId` are constant.

**All post-data streams (chunk map, MD5 manifest, cuckoo filter, LDM, XML,
trailer, metadata blob) live ONLY in the LAST volume.**

A reader handling a multi-volume backup must:
1. Detect: read `sequence` at offset 0x14. If > 1, multi-volume is certain.
   If = 1, enumerate sibling `_v*.tib` files to determine the maximum.
2. Open the LAST volume to discover the chunk map.
3. Concatenate the block streams of all volumes (back-to-back, no padding).

## Chains (incremental / differential)

`.tib` files have NO embedded parent pointer. Chain relationships live in a
sidecar SQLite catalog (`local-archives.db` / `mms.db`) with a `Slice_` table
containing `parentId_` and `sliceType_` (`BASE`/`INCREMENTAL`/`DIFFERENTIAL`/
`EDITED`/`CDP`).

Without the catalog, third-party readers reconstruct chains by:
1. Filename grammar `<archive>_<TYPE>_b<B>_s<S>_v<V>.tib`
2. Cross-validate `task_id` / `computer_id` from each `.tib`'s metainfo XML
   (stream 4) — same task_id ⇒ same chain.

## Encryption

When `encryption != none`:
- AES-128 / AES-192 / AES-256 in CBC mode (NO XTS, NO GCM in the binary).
  GOST 28147-89 is also supported as an alternative cipher.
- Three KDF options:
  - SHA256-stretch × 1000 iterations
  - PBKDF2-HMAC-SHA256, iterations = `1 << N` (N is one TLV byte)
  - scrypt with TLV-encoded `(N, r, p)`
- 16-byte plaintext verifier + 4-byte truncated tag = `SHA256-stretch-1000(AES(pt, key) ‖ pt)[:4]`
- RSA-cert recovery (type 3) exists for corporate scenarios
- Block payloads + post-data streams + MD5 manifest are wrapped in 16 KiB CBC
  windows with a 0xE0 frame prefix.
- Plaintext (always): volume header, per-block preambles, sector trailer,
  encryption-recovery TLV.

A skeleton decoder with all three KDFs is in `decrypt_tib.py`. Needs a sample
encrypted `.tib` to nail down the last 2-3 envelope bytes.

## Integrity model

Three primitives:
1. Volume-header Adler32 (4 bytes, computed over header[:hdr_len] with
   [0x18..0x1C] zeroed).
2. Per-block zlib Adler32 (built into deflate's stream wrapper).
3. Per-block MD5 in the 37 MB manifest.

There is NO separate per-block CRC, no chunk-map checksum, no metadata-blob
self-checksum. The footer is just a byte-reversed mirror, not an independent
integrity primitive.

## Cloud Storage

The cloud-side `.tib` is **byte-identical** to the local-side `.tib`. Acronis's
cloud splitter chops the local-archive byte stream into 128 MB pieces; each
piece becomes one file in a custom binary RPC ("FES" = File Engine Server)
over a long-lived TLS connection. Auth is mutual-TLS only (no OAuth, no
passwords, no API keys).

Third-party recovery from raw cloud blob storage is highly feasible — just
concatenate the 128 MB pieces in order and the result is a normal `.tib`.

## Universal Restore, Notary, Mobile Backup

These are separate products / services from the local archive format:
- **Universal Restore** (driver injection for dissimilar hardware) lives in a
  separate Windows binary (`UniversalRestore.exe` / `arm.exe`).
- **Notary** (blockchain-backed integrity) is a thin IPC client to a separate
  daemon `NotarizationSequencer`. The actual fingerprint hashing + Merkle
  batching + blockchain RPC is in that daemon, not in the .tib file.
- **Mobile Backup** uses an entirely different file format.

None of these affect a sector-mode `.tib`'s on-disk bytes; you can ignore
them when reading.

## References

- Acronis source paths discovered in `product.bin`:
  - `k:/8029/resizer/backup/openimg.cpp` — `ExtraFileChunkMap` (chunk-map decoder)
  - `k:/8029/resizer/backup/region_sparser.cpp` — sparse-block algorithm
  - `k:/8029/archive/ver2/block_sparser.cpp` — block-stream encoding
  - `k:/8029/archive/ver2/hash_chunk_reader.cpp` — MD5 dedup pipeline
  - `k:/8029/archive/ver2/file/crypto.cpp` — encryption (AES-CBC)
  - `k:/8029/products/imager/archivedb/impl/database_sql*.cpp` — catalog DB
  - `k:/8029/network/astorage/client/` — cloud storage protocol
- See `RE_HISTORY.md` for the full reverse-engineering play-by-play.
