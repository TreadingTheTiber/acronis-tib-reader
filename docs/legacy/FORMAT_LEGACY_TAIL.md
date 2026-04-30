# FORMAT_LEGACY_TAIL.md - Post-block-stream tail of TI 2014-era `.tib` files

Companion to `FORMAT_LEGACY.md` and `FORMAT_LEGACY_BLOCKS.md`. This document
describes the bytes between **the end of the block stream** (= end of inline
metadata #2's zlib payload) and **the start of the structured trailer**
(`[u32 size][u32 magic 0x94E18A2B]` framing the 37-byte TLV trailer body).

Empirically derived from `/mnt/e/miner1_default_full_b1_s1_v1.tib`.

> **TL;DR**: The "AES-ECB-on-uniform-plaintext ciphertext" region the block-walk
> agent identified is **NOT encrypted**. It is the legacy MD5 dedup manifest,
> directly analogous to the modern format's 37 MB MD5 manifest already decoded
> by agent C. The repeating 16-byte block
> `e9e66ccfeac74dfd4040aedc086a29b0` is just `MD5(0xFF*8 || 0x00*64*4096)` --
> the canonical "all-zero block" MD5 for legacy 8-byte-preamble + 64-cluster
> geometry, exactly mirroring the modern `8d65beed...` zero-block hash.

---

## File-offset map (miner1)

```
+-------------------------------------+ off 8,773,374,742
|  Inline metadata #2 (TLV+zlib)      |  316,354 bytes
+-------------------------------------+ off 8,773,691,096  <- TAIL_START
|                                     |
|   POST-BLOCK-STREAM TAIL            |  3,107,417 bytes
|   (subject of this document)        |
|                                     |
+-------------------------------------+ off 8,776,798,513  <- TRAILER_BODY_START
|  Trailer body (37 B TLV)            |  37 bytes
+-------------------------------------+ off 8,776,798,550
|  [u32 size=37][u32 0x94E18A2B]      |  8 bytes  <- yes, the legacy file DOES
+-------------------------------------+ off 8,776,798,558      have this magic
|  Padding zeros (with embedded       |
|   archiveId fragment near end)      |  130 bytes
+-------------------------------------+ off 8,776,798,688
|  Volume footer (32 B mirror)        |  32 bytes
+-------------------------------------+ off 8,776,798,720  EOF
```

> **Correction to FORMAT_LEGACY.md**: that document claimed the legacy format
> has *no* `0x94E18A2B` trailer magic and only a "16-byte mini-trailer + 32-byte
> mirror" before EOF. That is **wrong**. The bytes interpreted there as a
> "16-byte mini-trailer" (`00000000 236f4906 3e51230b 02000000`) are actually
> the last 16 bytes of the **130-byte zero-padding region** that follows the
> `0x94E18A2B` magic, with the trailing 8 bytes (`23 6f 49 06 3e 51 23 0b
> 02 00 00 00`) being a TLV fragment of the archive ID (`15878547e53ed64d`
> ends with `e5 3e d6 4d` -- those bytes appear in big-endian-encoded form
> elsewhere in the trailer). The 32-bit value `0x0b23513e` interpreted there
> as `metaDataOffset` is meaningless: that file offset (~178 MB) lands in the
> middle of the high-entropy block stream, not in any metadata region. The
> true trailer body sits at filesize-207..filesize-170 (37 bytes) followed by
> the standard 8-byte `[size][magic]` pair.

The post-block-stream tail (3,107,417 bytes) decomposes into two regions:

```
+---------------------------------+ off 0          (= file 8,773,691,096)
|  MD5 dedup manifest             |  1,129,744 B  (~1.08 MB)
|  70,609 x 16-byte hashes        |
+---------------------------------+ off 1,129,744  (= file 8,774,820,840)
|  Residual region                |  1,977,673 B  (~1.89 MB)
|  (mostly opaque - see below)    |
+---------------------------------+ off 3,107,417  (= file 8,776,798,513)
```

---

## 1. MD5 dedup manifest (1,129,744 B)

**Identical purpose** to the modern format's 37 MB MD5 dedup manifest.

| Property | Legacy (TI 2014, miner1) | Modern (TI 2018+, agent C's 1 TB STORAGE.tib) |
|---|---|---|
| Manifest size | 1,129,744 B (1.08 MB) | 37,157,840 B (37 MB) |
| Entry size | 16 B (MD5 digest) | 16 B (MD5 digest) |
| Entry count | 70,609 | 2,322,365 |
| Blocks covered | reader_block 100 .. N-1 | reader_block 0 .. N-1 |
| Blocks 0..99 stored where? | inline metadata #1 (1,620 B = 20 + 100*16 at file offset 10,431,214) | n/a -- modern format puts ALL hashes here |
| Hash function | MD5(preamble[8B] || decomp_block) | MD5(preamble[16B] || decomp_block) |
| Block ordering | ~storage order, with reorderings of -1..+3 (see verify) | storage order |
| Zero-block hash | `e9e66ccfeac74dfd4040aedc086a29b0` | `8d65beed7b7a6a9a0fd84512ec85ba17` |
| Zero-block hash entry count | 1,427 (2.02% of 70,609) | 4,465 |

The canonical zero-block hash is the smoking gun:

```
>>> import hashlib
>>> hashlib.md5(b'\xff'*8 + b'\x00'*(64*4096)).hexdigest()
'e9e66ccfeac74dfd4040aedc086a29b0'
>>> hashlib.md5(b'\xff'*16 + b'\x00'*(128*4096)).hexdigest()
'8d65beed7b7a6a9a0fd84512ec85ba17'
```

For a "full" block (preamble = 0xFF*8, all 64 clusters present and zero-filled
e.g. unallocated NTFS extents), the 8-byte preamble is followed by 64*4096
zero bytes. MD5 of that exact 8 + 262,144 = 262,152-byte sequence is the
constant `e9e66cc...`. Every empty-but-fully-stored block has this hash, so
they all collide, producing the `>=70 repeats` AES-ECB-on-uniform-plaintext
signature the block-walk agent observed.

### Verification

`decode_legacy_tail.py verify 200` (seed=42):

```
direct match (rec_idx == reader_block - 100):  89/200 (44.5%)
nearby match (within +/-7):                   193/200 (96.5%)
not found in manifest:                          0/200 (0.0%)
```

**Every randomly sampled block hash exists somewhere in the manifest** -- there
are 0 "not found" cases out of 200. The 55% of cases that aren't a direct
match are the result of small reorderings (+/-1..+/-3 in 76% of mismatches,
+/-7 in 96.5%). This is consistent with the modern format where Acronis writes
blocks slightly out-of-order due to its parallel-compressor pipeline. The
chunk-map sorts records by file_offset, but the manifest may sort by an
intermediate "compression batch" order. Exact ordering scheme not chased to
ground in this pass; **the structural identification (manifest = MD5 dedup
table) is unambiguous**.

### Why blocks 0..99 are excluded

Inline metadata record #1 (at offset 10,431,214 in miner1) decompresses to
1,620 bytes = `20 + 100 * 16`. That layout is identical to a 20-byte chunk
header followed by 100 x 16-byte MD5 digests. Per `FORMAT_LEGACY_BLOCKS.md`,
this is "Stream 1 / per-block dedup tracking metadata" for the first 100
blocks. The terminal manifest in the post-block-stream tail picks up where
inline #1 left off.

This is a difference vs the modern format, which puts ALL block hashes in a
single contiguous post-data manifest. The legacy format apparently flushes a
small fingerprint batch shortly after starting a backup so a partial archive
is recoverable, then accumulates the rest into the terminal manifest.

---

## 2. Residual region (1,977,673 B)

After the 70,609-entry manifest, the remaining 1,977,673 bytes are
structurally divided into **multiple sub-regions**:

```
offset    size      content
+0        16 B      header: u32 LE 0x80000000 | u32 LE 0x00485fc8 (4,743,624) | 8 zero bytes
+16       4080 B    zero padding
+4096     ~14 KB    sparse-bitmap-like region (mostly 0xFF runs, bits cleared)
+18432    2 KB      transition (medium entropy)
+20480    1,865,728 B  HIGH-ENTROPY BLOB #1 (~1.78 MB)
+1886208  3 KB      zero gap
+1889280  2 KB      transition (small TLV-like records)
+1891328  26 KB     all zeros (alignment gap)
+1917952  57,344 B  HIGH-ENTROPY BLOB #2 (~56 KB)
+1975296  ~2 KB     TLV partition info (UTF-16 'Devicehardisk Volume4')
+1977344  329 B     trailer-adjacent metadata
+1977673  EOR
```

### Header (16 B)

```
00 00 00 80   c8 5f 48 00   00 00 00 00   00 00 00 00
^^ u32 LE = 0x80000000      ^^ u32 LE = 0x00485fc8 = 4,743,624
   "high bit" flag             unknown count/size field
```

The value `4,743,624` doesn't match block_count (70,709), implied cluster
count (4,525,376), or any other obvious file-level constant. Possibly a
combined-archives running counter (this is a primary backup, but the
manifest+filter structure is designed to be carried forward to incremental/
differential backups; see modern format's "PreviousBackupDedup" usage).

### Entropy profile

```
state    range (in residual)         size       bytes
low      [    0 ..   4096)               4096   mostly zeros + 16B header
medium   [ 4096 ..   5120)               1024   sparse-bitmap dense region
low      [ 5120 ..   8192)               3072   sparse-bitmap with 0xFF
medium   [ 8192 ..   9216)               1024
low      [ 9216 ..  18432)               9216
medium   [18432 ..  20480)               2048
HIGH     [20480 .. 1886208)          1,865,728  *** main blob ***
low      [1886208 .. 1889280)            3072
medium   [1889280 .. 1891328)            2048
low      [1891328 .. 1917952)           26624   alignment zeros
HIGH     [1917952 .. 1975296)           57344   *** secondary blob ***
medium   [1975296 .. 1976320)            1024   TLV partition info
HIGH     [1976320 .. 1977344)            1024
medium   [1977344 .. 1977673)             329
```

### Bit/byte statistics for the residual

```
bit density:        49.59%   (nominally Bloom-filter-like, but...)
0x00 frequency:      2.155%  (uniform = 0.391%; 5.5x over)
0xFF frequency:      1.105%  (uniform = 0.391%; 2.8x over)
top non-trivial byte: 0xe7 at 0.397% (close to uniform)
```

**The residual is NOT a cuckoo filter** like the modern format's 3.16 MB
trailing region. The cuckoo-filter signature requires:

- 0x00 markers (empty slot) at ~11.6% (here: 2.2% -- 5x lower)
- 0xFF markers at ~0.8%-1.1% (here: 1.1% -- matches, but isolated)
- Total bytes divisible by `slots_per_bucket * fp_bytes` (typically 4 for 1B fp;
  legacy residual `1,977,673 / 4 = 494418.25`, NOT integer)

Bit density of ~50% combined with low 0x00 over-representation suggests the
high-entropy blobs (which occupy 1,865,728 + 57,344 = 1,923,072 bytes, 97.2%
of the residual) are either:

1. AES-encrypted bytes (genuine encryption with non-uniform plaintext, hence
   no AES-ECB signature like the manifest), or
2. compressed bytes with no recoverable zlib magic, or
3. some packed structure that happens to look pseudo-random.

The non-divisibility into a clean grid argues against a per-bucket fixed-
record filter structure. The two separate high-entropy blobs (1.78 MB and
56 KB) plus the small medium-entropy interleaves more closely resemble a
**multi-stream container** (like the modern format's 7 post-data streams) where
each stream is independently compressed/encrypted.

### What's in there?

Probable contents based on structural shape and parity with the modern format:

| Modern post-data stream | Legacy equivalent? | Evidence |
|---|---|---|
| Chunk-map (zlib) | Lives at file offset ~ filesize-62KB per FORMAT_LEGACY.md | Earlier blob, NOT in this residual |
| MD5 dedup manifest | Manifest region above | YES |
| Cuckoo dedup filter | -- | NOT present (no signature) |
| Preamble mirror | Possibly the small bitmap-like region [4096..18432] | Partial: only ~14 KB out of 565,672 needed for 70,709 8-byte preambles. So either compressed, or not the full mirror, or unrelated |
| LDM info | Possibly inside one of the high-entropy blobs | Unverified |
| XML metadata | -- | UTF-16 'Devicehardisk Volume4' string IS present near end, but no XML envelope visible |
| Two mini-descriptors | -- | Unidentified |

### Partition-info TLV (last ~2 KB)

The very tail of the residual (just before the 37-byte trailer body) contains
recognisable TLV partition records ending with the UTF-16 LE string
`Devicehardisk Volume4` and the `\Volume4` device path. This is exactly the
same kind of "partition info" tail seen in the modern format and in the
"60 KB chunk-map region" mentioned in `FORMAT_LEGACY.md`.

The TLV records here are dense and visible; a parser specialising on this
last ~2 KB could extract:

- Device path (`\Device\Harddisk[N]\Volume[M]`)
- Partition GUID(s)
- Filesystem type strings

This is the same TLV grammar as documented in `METADATA_BLOB_TLV.md` (length-
prefix-encoded varints). Not parsed end-to-end here; it isn't load-bearing
for block decoding.

---

## Verdict

| Question | Answer |
|---|---|
| Is the legacy "encrypted tail" actually encrypted? | **No.** The repeating 16-byte block is `MD5(0xFF*8 \|\| 0x00*64*4096)`, not ciphertext. |
| Is it the MD5 dedup manifest? | **Yes** for the first 1.08 MB (70,609 entries). The remaining 1.89 MB is a "residual region" -- structurally analogous to but NOT the same as the modern format's 3.16 MB cuckoo filter. |
| Does the legacy format have a cuckoo filter equivalent? | **No.** Bit-density and byte-frequency statistics rule out a fixed-bucket cuckoo filter. The legacy residual contains two high-entropy blobs separated by zero-alignment gaps, plus a small partition-info TLV at the end. Likely a multi-stream container (chunk-map / preamble-mirror / partition info / etc.) but the per-stream framing has not been recovered. |
| Same data structure across versions? | **Partially.** The MD5 manifest is structurally identical (16-byte hashes of `preamble \|\| decomp_block`, in storage-ish order, with the matching canonical zero-block hash). The trailing dedup-acceleration filter exists only in the modern format. The legacy format predates that optimisation. |

The block-walk agent's "AES-ECB-on-uniform-plaintext ciphertext" identification
was **incorrect** in the same way as agent G/J's modern-format misidentification
was: the repeating 16-byte block is a constant MD5 hash, not a constant cipher
output. Same root cause (MD5 of the canonical "all-zero block" appearing many
times), same fix (recognise the constant). With this correction, the post-
block-stream tails of the modern and legacy formats are confirmed to share
the same MD5 dedup-manifest substrate, with format-specific extensions on top
(modern adds the cuckoo filter; legacy ends with a small multi-stream blob).

---

## Tools

- `/home/colin/tibread/decode_legacy_tail.py` -- analyser/dumper.
  - `python3 decode_legacy_tail.py map` -- print structural map.
  - `python3 decode_legacy_tail.py verify [N]` -- sample-verify N block hashes
    against the manifest (default 200).
  - `python3 decode_legacy_tail.py dump <manifest.bin> <residual.bin>` --
    extract the two regions to separate files.

## Key constants (miner1)

```
TIB file:                /mnt/e/miner1_default_full_b1_s1_v1.tib
file size:               8,776,798,720
block stream end:        8,773,374,742  (start of inline #2 TLV)
inline #2 zlib end:      8,773,691,096  (== TAIL_START)
trailer body start:      8,776,798,513  (== TAIL_END)
trailer body size:       37  (TLV)
trailer magic offset:    8,776,798,554  (0x94E18A2B)
volume footer offset:    8,776,798,688  (32-byte mirror)
tail region size:        3,107,417  (~2.96 MB)
manifest size:           1,129,744  (= 70,609 entries x 16)
residual size:           1,977,673  (~1.89 MB)
canonical zero hash:     e9e66ccfeac74dfd4040aedc086a29b0
                       = MD5(0xFF*8 || 0x00*262144)
```
