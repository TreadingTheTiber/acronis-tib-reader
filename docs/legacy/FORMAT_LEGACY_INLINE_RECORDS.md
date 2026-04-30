# Legacy `.tib` inline metadata records — byte-level decode

Companion / cross-check to `FORMAT_LEGACY.md` (the user-facing legacy spec).
Specifically resolves a now-disproven working hypothesis from the block-walk
investigation that the first inline metadata record was a "20-byte chunk
header + 100 × 16-byte MD5 fingerprints".

It is not. **Both** inline records in miner1 are `SequentialChunkMap`
fragments, exactly matching the format already documented in
`FORMAT_LEGACY.md` § "Inline `SequentialChunkMap` records".

Test artifact: `/mnt/e/miner1_default_full_b1_s1_v1.tib` (8.78 GB,
TI 16 build 6514).

---

## Inline #1 @ file offset 10,431,214

Bytes at the offset (first 60):

```
11 02 00 02 00 02 03 00 01 08 04 00 01 40 06 00
01 87 78 01 e3 fa f8 8c 81 00 78 12 5a 40 48 09
c3 9f b3 73 37 24 6f 62 f8 c4 c0 c3 0a e4 11 04
15 53 19 64 7e 30 54 81 15 ca 31 94 ...
```

Decoded as `[u8 L][L bytes TLV][zlib]`:

| Field | Value |
|---|---|
| L | `0x11` (17) |
| TLV tag `0x0002` (sector size) | 512 |
| TLV tag `0x0003` (sectors/cluster) | 8 |
| TLV tag `0x0004` (clusters/block) | 64 |
| TLV tag `0x0006` (record count) | 135 |
| zlib compressed length | 338 bytes |
| zlib inflated length | 1,620 bytes (= 135 × 12) |
| Total record size on disk | 1 + 17 + 338 = **356 bytes** |

Note: 1,620 inflated bytes is what the block-walk agent observed; their
"20-byte chunk header + 100 × 16 fingerprints" arithmetic happens to also
equal 1,620, which is what made the wrong hypothesis numerically tempting.
The correct decomposition is **1 + 17 (TLV) + 338 (deflated stream); the
338 deflates to 1,620 = 135 × 12 byte chunk-map records**.

### Disproof of the "20 + 100×16 MD5" hypothesis (confirmed via byte-decode)

`MD5(8B preamble || decompressed block 0)` for the actual block 0 of the
file is the canonical all-zero hash:

```
e9e66ccfeac74dfd4040aedc086a29b0
```

The would-be "first hash" at inflated offsets [20:36] of the inline #1
payload is:

```
000000000000000000000000000000e4
```

These do not match. They cannot be aligned by any reasonable framing —
the inflated payload is column-major matrix-transposed chunk-map data,
not a hash array. The 20-byte header structure proposed by the brief
**does not exist**.

---

## Inline #2 @ file offset 8,773,374,742

Same structure, larger payload:

| Field | Value |
|---|---|
| L | `0x13` (19) |
| TLV tag `0x0002` | 512 |
| TLV tag `0x0003` | 8 |
| TLV tag `0x0004` | 64 |
| TLV tag `0x0006` (record count) | 259,108 |
| zlib compressed length | 316,334 bytes |
| zlib inflated length | 3,109,296 bytes (= 259,108 × 12) |
| Total record size on disk | 1 + 19 + 316,334 = **316,354 bytes** |

The earlier note in the brief that inline #2 "might be 70,709 × 44-byte
CBT records" or "SequentialChunkMap-like" — the latter is correct, the
former is ruled out. 3,109,296 / 44 = 70,665.8 (non-integer); 3,109,296 /
12 = 259,108 (clean) and TLV tag6 reports exactly 259,108.

The 259,108 record count vs. 70,709 block count discrepancy is explained
in `FORMAT_LEGACY.md`: SequentialChunkMap records are per-LCN-batch (one
per stored extent, a.k.a. "concat run"), not per-block. A single block
can produce many records, and an empty extent produces none.

---

## Are there more inline records?

**No, only two.** Confidence: **high (inferred from format, plus prior
exhaustive scans)**.

Reasoning:

1. The format requires that an inline `SequentialChunkMap` record be
   followed by either another block preamble or by EOF-of-block-stream.
   The reader's discriminator (`FORMAT_LEGACY.md` § "Locating inline
   records when reading") is "is this a small u8 in [8..32] followed
   within ~24 bytes by `78 01`?" — a very tight, deterministic test.
2. Earlier scans (`scan_miner1.py`, the block-walk agent's exhaustive
   walk, and the `tibread.chunkmap_legacy.discover_inline_chunkmaps_legacy`
   sequential walker) all converge on exactly two inline records.
3. The cumulative chunk-map record count is **135 + 259,108 = 259,243**,
   which exhausts the stored extents in the file. There is nothing left
   for additional inline records to describe.
4. The brief's worry about "smaller inline records (e.g. < 100 bytes)
   that the block-walk missed" does not apply: an inline record's
   minimum on-disk size is `1 + L_min + zlib(record_count*12)`. With
   `L_min ≈ 13` (tags 2/3/4/6 + minimum value lengths) and zlib's ~12-byte
   minimum stream, the absolute floor is roughly 30 bytes — but tag 6 (the
   record count) is required, and a record count < ~6 would compress to a
   stream still distinguishable from a block preamble. No such candidate
   was found in any scan.

**Confirmed via byte-decode:** the two inline records' chunk-map records
together cover the entire block stream from offset 0 (relative to
`data_start = 32`) up to the start of inline #2.

---

## Where the MD5 fingerprints actually live

The brief conflated two different on-disk regions:

| Region | What it actually is | Bytes |
|---|---|---|
| Inline #1 (off 10,431,214) | `SequentialChunkMap` fragment, 135 records | 356 B |
| Inline #2 (off 8,773,374,742) | `SequentialChunkMap` fragment, 259,108 records | 316,354 B |
| Post-block-stream tail | **MD5 dedup manifest** (16 B per stored block) + small residual region | ~3 MB |

Per `FORMAT_LEGACY.md` § "Post-block-stream tail" and
`FORMAT_LEGACY_TAIL.md`, the MD5 manifest in the tail covers **all stored
blocks 0..N-1**, not "100..N-1". The "blocks 0..99 are tracked by inline
metadata #1 (a 1620-byte = 20 + 100×16 zlib stream)" sentence in
`FORMAT_LEGACY.md` line 235-237 is the **same misreading** that the brief
inherited and is internally inconsistent with the rest of that document
(which correctly describes inline records as 12-byte chunk-map records on
lines 132-149, 174-184). It should be corrected; see "Recommended fix"
below.

---

## Coverage of miner1's bytes

With the inline records correctly identified as chunk-map fragments,
miner1's byte-level coverage is:

| Range | Description | Status |
|---|---|---|
| `[0, 32)` | Volume header | decoded |
| `[32, 10,431,214)` | Block stream segment 1 (preamble + zlib per block) | decoded |
| `[10,431,214, 10,431,570)` | Inline `SequentialChunkMap` #1 (356 B) | decoded |
| `[10,431,570, 8,773,374,742)` | Block stream segment 2 | decoded |
| `[8,773,374,742, 8,773,691,096)` | Inline `SequentialChunkMap` #2 (316,354 B) | decoded |
| `[8,773,691,096, ~end - ~1KB)` | MD5 dedup manifest + residual region | decoded (manifest) / partial (residual) |
| trailer + footer + framing | Trailer body, size+magic, padding, volume footer | decoded |

The only piece **not** at 100% byte-decode is the legacy "residual region"
(documented in `FORMAT_LEGACY.md` § "Residual region" as ~1.9 MB of
multi-stream container). That is a separate workstream and unrelated to
the inline records.

So with this finding, **miner1 inline-record coverage is at 100%, fully
consistent with the existing legacy spec**. The brief's "ONLY remaining
unidentified piece" was based on a misreading of `FORMAT_LEGACY.md`'s
own internal inconsistency.

---

## Recommended fix to `FORMAT_LEGACY.md`

Lines 235-239 of `dist/docs/FORMAT_LEGACY.md` say:

> The manifest covers blocks 100..N-1; blocks 0..99 are tracked by inline
> metadata #1 (a 1620-byte = 20 + 100×16 zlib stream describing them
> individually). The legacy format apparently flushes a small fingerprint
> batch shortly after starting a backup so a partial archive remains
> recoverable.

This contradicts lines 132-149 and 174-184 of the **same document**, which
correctly describe inline records as `[u8 L][L bytes TLV][zlib]`
SequentialChunkMap fragments with `record_count × 12` byte payloads. The
quoted paragraph should be removed/replaced with:

> The manifest covers all stored blocks 0..N-1. The two inline records
> in the block stream are `SequentialChunkMap` fragments (described
> above), not MD5 fingerprint batches.

---

## Confidence summary

| Finding | Source |
|---|---|
| Inline #1 = `[u8 L=0x11][17B TLV][338B zlib → 1620B → 135×12B records]` | byte-decode (this script) |
| Inline #2 = `[u8 L=0x13][19B TLV][316,334B zlib → 3,109,296B → 259,108×12B records]` | byte-decode (this script) |
| The "20-byte header + 100 MD5" framing does not exist | byte-decode (block 0 hash mismatch) |
| Only two inline records in miner1 | inferred from prior exhaustive scans + format constraints |
| MD5 manifest in the tail covers 0..N-1 (not 100..N-1) | inferred (cross-check needed against `decode_legacy_tail.py`) |
| Inline-record placement strategy: one early flush + one final flush | inferred from miner1; not yet cross-checked against other legacy archives |

---

## Reproduction

```bash
python3 /home/colin/tibread/decode_inline_records.py
```

Output matches the tables above.
