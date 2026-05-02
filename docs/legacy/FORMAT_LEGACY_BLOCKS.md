# TI 2014-Era (Legacy) .tib Block Format

Empirically derived from `/path/to/legacy_example.tib`
(8,776,798,720 bytes, dated 2014-01-17, magic `0xA2B924CE`, version 0).

Compare with `FORMAT.md` (newer 2018+ variant) — the legacy variant differs
mainly in **block-preamble width** (8 bytes vs 16 bytes) and the placement /
size of inline metadata records.

---

## High-level file layout

```
+---------------------------+ off 0
|  Volume header (32 B)     |   magic, archiveId, volumeId, sequence, adler32
+---------------------------+ off 32
|                           |
|  Block stream             |   periodically interleaved with inline metadata
|                           |
+---------------------------+
|  Inline metadata #1       |   (1620 B decomp, after first 100 blocks)
+---------------------------+
|                           |
|  Block stream (continued) |
|                           |
+---------------------------+
|  Inline metadata #2       |   ~3 MB decomp; per-block tracking + tail
|                           |   ENDS the block stream
+---------------------------+
|  Encrypted footer         |   ~3 MB of AES-ECB-like ciphertext
|                           |   (16-byte cipherblocks repeat where plaintext
|                           |    is uniform — same signature as TI 2018+'s
|                           |    8 KB encrypted region)
+---------------------------+ off 8,776,798,558  (= concat_end)
|  Trailer body (zero-pad)  |   117 zero bytes
+---------------------------+ off 8,776,798,675
|  Footer (45 B)            |   adler32 + sequence + volumeId + archiveId +
|                           |   header_len + magic   (echoes volume header)
+---------------------------+ off 8,776,798,720  (= EOF)
```

## Block format (legacy)

Each data block:

```
+--------+----------------+
| 8B     | zlib stream    |
+--------+----------------+
  ^         ^
  |         |
  preamble  payload (mode 0x78 0x01, "no compression preset")
```

* **preamble (8 bytes)** — 64-bit cluster-presence bitmap, **LSB-first** within
  each byte. Bit `i` set iff cluster `(block_idx * 64 + i)` is stored in this
  block. Decompressed size = `popcount(preamble) * 4096`.
* **zlib stream** — standard `78 01` zlib (no-compression preset). Stream end
  is detected by `decompressobj.eof`. Decompresses to exactly the present
  clusters concatenated in LCN order.

This contrasts with the newer 2018+ format which uses a **16-byte preamble**
covering 128 clusters per block.

## Inline metadata records

Periodically, the block stream is interrupted by an **inline metadata record**:

```
+---------------+----------------+----------------------------+
| TLV header    | zlib stream    | trailing pad/cipher tail   |
| (18 or 20 B)  |                | (varies, only between blocks)
+---------------+----------------+----------------------------+
```

The TLV header begins with `0x11` or `0x13`, followed by tag-length-value
fields, terminating with the zlib magic `78 01` somewhere in the first ~24
bytes. Empirically two forms observed:

| Form | TLV header bytes (hex)                                 | length |
|------|--------------------------------------------------------|--------|
| A    | `11 02 00 02 00 02 03 00 01 08 04 00 01 40 06 00 01 87` | 18     |
| B    | `13 02 00 02 00 02 03 00 01 08 04 00 01 40 06 00 03 24 f4 03` | 20     |

Both forms have the prefix `… 02 03 00 01 08 04 00 01 40 06 00 …`. The trailing
field varies — appears to be a length or count related to the metadata payload
that follows.

### Empirical inline records in example

| # | abs offset       | TLV len | md_zlib_comp | md_decomp | tail_pad | role                              |
|---|------------------|---------|--------------|-----------|----------|-----------------------------------|
| 1 | 10,431,214       | 18      | 338          | 1,620     | 2,319    | per-block(0..99) tracking?        |
| 2 | 8,773,374,742    | 20      | 316,334      | 3,109,296 | n/a      | per-block(all) tracking + footer  |

* Inline #1 decompresses to **1,620 bytes = 20 + 100 × 16** — looks like a
  20-byte chunk header followed by 100 × 16-byte per-block fingerprints, of
  which 34/100 are non-zero. Closely resembles "Stream 1" in the newer format
  (per-block dedup / incremental tracking metadata).
* Inline #2 is the **terminal record**: it sits right after the last data
  block and is followed only by encrypted/integrity footer bytes (no further
  blocks). Its 3,109,296 decompressed bytes scale roughly with total block
  count (70,709). Specific per-entry semantics not decoded here.

### Encrypted footer

After inline #2's zlib ends (offset 8,773,691,096), there are **3,107,462
bytes** of opaque data ending at `concat_end = 8,776,798,558`. Within this
region the same 16-byte ciphertext block (`e9e66ccfeac74dfd4040aedc086a29b0`)
repeats 70+ times, the smoking-gun signature of **AES-ECB on uniform
plaintext** (same plaintext block → same ciphertext). Same cipher pattern as
documented in the 2018+ format's 8 KB tail.

## Trailer

The final 162 bytes of the file:

* 117 zero bytes (padding)
* `23 6f 49 06 3e 51 23 0b` (8B; possibly hash digest tail)
* `02 00 00 00 00 00 00 20` (5B-length-prefix `0x02` + suffix length tag `0x20`?)
* `a4 2a 07 1e` (adler32 — **matches volume header's adler32**)
* `00 00 00 01` (sequence = 1)
* `06 49 6f 23` (volumeId = 0x06496f23)
* `15 87 85 47 e5 3e d6 4d` (archiveId = 0x158785_47e53ed64d)
* `00 00 00 20` (header length = 32)
* `a2 b9 24 ce` (magic = 0xA2B924CE)

The footer is essentially the volume header echoed back, big-endian-encoded.
The 5-byte length-prefix differs from the 6-byte one in the newer format —
consistent with smaller offsets in the smaller files of this era.

---

## Empirical scan results — example

Scanner: `/path/to/tibread/scan_example.py`
Index:   `/path/to/tibread/example_blocks.idx`
Log:     `/path/to/tibread/scan_example_full.log`

* **scan elapsed:** 85.8 s on WSL drvfs (~825 blocks/s end-to-end)
* **block stream range:** `[32 .. 8,773,374,742)`
* **block stream size:** ~8.17 GiB (8,773,374,710 bytes)
* **blocks parsed:** **70,709**
* **anomalies:** **0**
* **inline metadata records:** 2 (one early at offset 10,431,214, one terminal
  at offset 8,773,374,742; see table above)
* **trailing region** (after terminal inline + zlib): 3,107,462 bytes of
  AES-ECB-like ciphertext + 162-byte trailer with footer.

### Popcount distribution (clusters present per 64-cluster block)

* `pop=64` (full): 68,370 (96.69 %)
* `pop<64` (partial): 2,339 (3.31 %)
* `pop=0` (empty): **0** — same invariant as the newer format ("no all-zero
  preamble blocks exist on disk"; sparse clusters are encoded by clearing
  bits, not by emitting empty blocks).

The non-full popcount tail is well-distributed across many values
(40–63 dominate) with no obvious quantization.

### Partition geometry (implied)

* total clusters in image = `block_count * 64` = **4,525,376**
* implied raw partition size = `4,525,376 * 4096` = **18,535,940,096 bytes**
  (~17.26 GiB)
* present clusters: 4,466,489 (98.70 %)
* sparse clusters: 58,887 (1.30 %)

### Compression

* sum decomp bytes:  18,294,738,944
* sum zlib bytes:     8,772,806,363
* zlib / decomp ratio: 47.95 % (≈2.1× compression)

---

## Verdict on sequential scan

**YES — sequential scan reliably enumerates every data block** for this file.

Method:

1. Walk `[8B preamble][zlib stream]` records starting at offset 32.
2. When the next byte at the current position is `0x11` or `0x13` AND a `78 01`
   appears within the next ~24 bytes (and not at offset +8 — that would be a
   regular preamble starting with that byte), treat the record as **inline
   metadata**: skip the TLV header, decompress its zlib, then scan forward in
   the next ~64 KiB for the next valid block preamble (validated by
   attempting decompression).
3. If no valid preamble is found after an inline record, that inline was the
   **terminal** one — the block stream ends at the start of that inline.

Important pitfall: the encrypted footer contains random-looking bytes that
occasionally match the `78 01` pattern. Naïve preamble search will produce
false positives. Validate any candidate preamble by attempting to decompress
its zlib payload and checking that the decompressed length is a positive
multiple of 4096 ≤ `popcount(preamble) * 4096`.

## Index format

The generated index uses the existing **TIBIDX02** layout (28-byte records)
unchanged for ABI compatibility:

```
header  : b"TIBIDX02"               # 8 B
        + u64 tib_size
        + u64 data_start            # = 32 (after volume header)
        + u64 data_end              # = end of last block in file
        + u64 block_count           # = 70,709 for example
records : block_count × {
            u64 file_offset         # absolute byte offset of this block in .tib
            u8  preamble[16]        # legacy: first 8 B real bitmap, last 8 B = 0
            u32 comp_len            # 8 B preamble + zlib bytes (the "block")
          }
```

### Padding choice (TIBIDX02 vs new TIBIDX03)

For the legacy 8-byte preamble we **pad the upper 8 bytes with zeros** so the
on-disk record layout stays at 28 bytes. Rationale:

* Keeps `INDEX_REC_SIZE = 28` constant; no reader-side branching by index
  version is needed.
* The legacy reader interprets only the lower 8 bytes (low 64 bits) as the
  bitmap and **ignores the upper 8** — a future unified reader can detect
  legacy by asserting that the upper 8 bytes are zero across all records, OR
  by an external hint (file magic / volume version field).
* No information is lost; round-trip is faithful.

If the upper 8 bytes are ever needed by some future format, that variant
should bump the index magic to `TIBIDX03`. For now, `TIBIDX02` with the
"zeroed-tail" convention is sufficient.

### Reader compatibility

The existing `tibreader.TibReader` will load this index but does the
following math against it:

```
CLUSTERS_PER_BLOCK = 128
partition_size = block_count * BLOCK_SIZE   # 524288 = 128 * 4096
```

This is **wrong for legacy**: each legacy block covers 64 clusters, not 128.
`reader.partition_size` would compute 4× too large. Either:

1. Add a `clusters_per_block` field to TIBIDX02 (would need TIBIDX03), OR
2. Have the reader detect "legacy" via the zeroed upper-8B convention and
   switch geometry, OR
3. Add a flag bit to the index header (e.g. repurpose a high bit of
   `data_start`).

For now, downstream code consuming this index must override
`CLUSTERS_PER_BLOCK = 64` and `PREAMBLE_LEN = 8` — see the variant flag
hypothesis in the scanner module.

## Files

* `/path/to/tibread/scan_example.py` — scanner (modes: `--stats`,
  `--build-idx`).
* `/path/to/tibread/example_blocks.idx` — built index (TIBIDX02, 70,709
  records, ~1.98 MB).
* `/path/to/tibread/scan_example_full.log` — full scan log.
