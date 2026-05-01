# RESEARCH: `.tibx` LSM-tree Index — Page Layout

Source archive used for empirical decode: `/mnt/e/Jmicron 0102.tibx`
(54 GiB, 13,347,630 pages, ATI 2024-format archive3).

Confidence convention:
- **[CONFIRMED]** — verified by parsing the actual bytes of the test
  archive.
- **[INFERRED]** — derived from cross-references to the
  `archive3.dll` strings dump or the LSM tree-purpose conventions.
- **[OPEN]** — explicit unknowns flagged for next pass / Ghidra.

---

## 1. Index region overview **[CONFIRMED]**

The trailing 932 pages of the file form the LSM index region:

| Pages                       | Count | Type byte | Inner magic | Role                                       |
|-----------------------------|------:|-----------|-------------|--------------------------------------------|
| 13,346,698 .. 13,347,627    |   907 | `0x03`    | `LEAF`      | LSM tree leaf nodes                        |
| (interspersed)              |     7 | `0x04`    | `LDIR`      | LSM tree interior / directory nodes        |
| 13,347,605 .. 13,347,615    |    11 | `0x05`    | *(none)*    | LSM blob (golomb / encrypted ctree run)    |
| 13,347,534, 13,347,626, 13,347,629 | 3 | `0x02`  | `ARCI`     | Commit-Index pages                         |
| 13,347,624, 13,347,625, 13,347,627, 13,347,628 | 4 | `0x01` | `ARCH` | Archive-header chain (latest at 13347627) |

LDIR pages (in this archive): **13,347,112, 13,347,113, 13,347,114,
13,347,115, 13,347,532, 13,347,604, 13,347,623**.  The first four
contiguous LDIRs are the interior nodes of the largest tree; the
isolated LDIRs are roots of smaller trees.

The 11 contiguous `0x05` pages live just before the ARCI/ARCH chain
and contain high-entropy bytes with no ASCII magic.  Hypothesis:
**Acronis Golomb-coded dedup filter (introduced in v7)** or the
serialized c0 spill of one of the LSM trees. **[OPEN]**

---

## 2. LEAF / LDIR page body layout **[CONFIRMED via byte parsing]**

Both `0x03` LEAF and `0x04` LDIR pages share the same body layout:

```
+0x00  4   magic       "LEAF" or "LDIR"
+0x04  1   ver         0x01 (constant in every observed page)
+0x05  1   reserved    0x01
+0x06  1   encoding    0x00 / 0x01 / 0x02 (cell-stream encoder variant)
+0x07  1   count       1-byte cell count (3..205 observed)
+0x08  4   total_len   BE u32 — uncompressed cell-area size; for LEAF
                       pages this is ~0x29NN (10720..10940), exceeding
                       the page body size, which means the cell stream
                       is **bit-packed and decompressed to the larger
                       'total_len' bytes**.
+0x0C  4   payload_len BE u32 — encoded byte length on this page
                       (~0x0F8X for LEAF; close to 4088 - 0x35 = 4035)
+0x10  4   key_param   BE u32 — appears to be a key-prefix length used
                       by the golomb encoder; constant 0x1B (27) for
                       most LEAFs, varying (0x02, 0x0a, 0x1a) for LDIRs.
+0x14  ?   first cell token byte + zero pad to +0x35
+0x35..        encoded cell stream (continues to body[4088])
```

**Encoding-byte distribution in `Jmicron 0102.tibx`** (page-type → encoding):

| Page type | Encoding | Count |
|-----------|---------:|------:|
| `LEAF` (0x03) | 0x00 | 539 |
| `LEAF` (0x03) | 0x01 | 362 |
| `LEAF` (0x03) | 0x02 |   6 |
| `LDIR` (0x04) | 0x00 |   6 |
| `LDIR` (0x04) | 0x01 |   1 |

The fact that 0x00 dominates suggests it is the most efficient cell
encoder; 0x01/0x02 are likely fallbacks for pages whose key/value
distribution doesn't compress well.

### Cell stream **[OPEN]**

Per the `archive3.dll` strings dump:
- `lsm_decompress_leaf` logs *"LZ4 decompression failed at %s"* — so
  cells should be **LZ4 raw-block compressed**.
- `lsm_golomb.c` is the bit-stream encoder used by the dedup filter.

Empirical attempts to LZ4-decode the body at offsets 0x14, 0x35, 0x37,
and 0x3B all fail.  Possibilities:

1. The cell stream uses Acronis's custom golomb encoding (per
   `lsm_golomb.c`) rather than stock LZ4 — the `0x00`/`0x01`/`0x02`
   encoding byte selects between three custom variants.
2. The first cell token at `+0x14` is a *header extension* (e.g. a
   CRC-of-cells byte) and the LZ4 stream actually starts a few bytes
   later than I tried.
3. The pages are **dictionary-LZ4** with a per-archive dictionary
   stored in the archive metadata (page 1 or earlier).

**Next step:** decompile `ar_lsm_leaf_decompress` / `lsm_decompress_leaf`
in Ghidra and read the actual algorithm.

---

## 3. The 6 (actually 7) LSM trees **[CONFIRMED + INFERRED]**

The latest `ARCH` page body carries an **inline array of `L-SB`
(LSM superblock) records**, each prefixed by a 4-byte BE u32
``sb_size``.  In `Jmicron 0102.tibx` the latest ARCH lives at page
**13,347,627** (commit_seq 3229).

### L-SB record layout **[CONFIRMED]**

```
-0x04  4   sb_size      BE u32 — record length (excluding this prefix)
+0x00  4   magic        "L-SB"
+0x04  4   ver_block    e.g. 02 01 0a 00 / 02 02 0a 00 / 02 03 0a 00
+0x08  4   seq          BE u32 (commit sequence; 0 if c0-only)
+0x0C  4   field_b      BE u32  (purpose varies by ver_block — likely
                                 max_segment_size or nr_ctree)
+0x10  4   field_c      BE u32  (likely max_ext_len)
+0x14  4   field_d      BE u32  (likely c0_count)
+0x18  ?   ctree[]      array of {offset(u64), tree_nr(u64), tree_sz(u64)}
                        — empty slot has offset = 0xFFFFFFFFFFFFFFFF
after  ctree[]          inline c0 (memtable) blob, variable length, runs
                        to the byte at -0x04 + 4 + sb_size.
```

The exact semantics of `field_b/c/d` vary slightly with the `ver_block`,
which is why the parser in `lsm.py` uses a *structural* decoder
(scan ctree slots until they stop looking like plausible
`(file_offset, byte_size)` pairs) rather than relying on a count field.

### The 7 superblocks in `Jmicron 0102.tibx`

| #  | sb_size | ver_block    | seq  | root page  | tree_sz_bytes | inferred role        | confidence |
|---:|--------:|--------------|-----:|-----------:|--------------:|----------------------|------------|
| 0  | 0x2B2   | 02 01 0A 00  |    0 | (c0 only)  |             — | **name_map** *(c0 holds .meta/.slice/.ati paths and content hashes)* | **[INFERRED]** from c0 contents |
| 1  | 0x178   | 02 03 0A 00  |   27 | 13,347,115 |     0x1A2000 (~418 pg) | **data_map** | **[INFERRED]** from being the largest tree |
| 2  | 0x178   | 02 03 0A 00  |   26 | 13,347,532 |     0x1A1000 (~417 pg) | **segment_map** | **[INFERRED]** |
| 3  | 0x178   | 02 02 0A 00  |   10 | 13,347,604 |      0x47000 (~71 pg)  | **notary_map** (Merkle hashes) | **[INFERRED]** |
| 4  | 0x22B   | 02 01 0A 00  |    0 | (c0 only)  |             — | **unused_map** *(disk1/part1 path + c474... hash)* | **[INFERRED]** from c0 contents |
| 5  | 0x1E8   | 02 01 0A 00  |    0 | (c0 only)  |             — | **nlink_map** | **[INFERRED]** |
| 6  | 0x1B5   | 02 01 0A 00  |    2 | 13,347,623 |       0x8000 (~8 pg)   | **golomb dedup filter (v7)** | **[INFERRED]** |

**Total** confirmed on-disk LSM pages reachable from the L-SB array:
418 + 417 + 71 + 8 = **914 pages**, which is the LEAF (907) + LDIR (7)
count exactly.  ✓

### Cross-reference verification **[CONFIRMED]**

Every non-sentinel `offset` in every `L-SB` lands on an LDIR page
inside the index region:

| L-SB | ctree[0] offset | landing page | landing type | landing magic |
|------|-----------------|--------------|--------------|---------------|
| 1    | `0xCBA92B000`   | 13,347,115   | `0x04`       | `LDIR`        |
| 2    | `0xCBAACC000`   | 13,347,532   | `0x04`       | `LDIR`        |
| 3    | `0xCBAB14000`   | 13,347,604   | `0x04`       | `LDIR`        |
| 6    | `0xCBAB27000`   | 13,347,623   | `0x04`       | `LDIR`        |

---

## 4. Walking an LSM tree

Until the LEAF cell decoder is implemented, the safe interface is
:func:`tibread.tibx.lsm.walk_lsm_tree`, which walks the contiguous
LEAF pages adjacent to a tree root and yields one *placeholder* entry
per LEAF.  This is enough to confirm tree size end-to-end:

```python
from tibread.tibx import TibxReader
from tibread.tibx.lsm import read_lsm_superblocks, walk_lsm_tree

with TibxReader("/mnt/e/Jmicron 0102.tibx") as r:
    sbs = read_lsm_superblocks(r)
    target = sbs[1]              # data_map (biggest tree)
    n = 0
    for _k, _v in walk_lsm_tree(r, target.primary_root_page,
                                max_pages=500):
        n += 1
    print(f"{n} leaf pages walked")   # → 414
```

The **real** in-order key/value walk requires the cell decoder.

---

## 5. Tree key/value semantics (per `lsm_*_map.c` filenames)

These are **[INFERRED]** from filename and the c0 contents we *can*
read in plaintext; the exact byte layouts will be confirmed once
:func:`parse_leaf` decodes cells.

| Tree         | Inferred key                  | Inferred value                                     |
|--------------|-------------------------------|----------------------------------------------------|
| `name_map`   | item-name hash (or path)      | `{ item_id, parent_id, kind, mtime, size, ... }`   |
| `data_map`   | content hash (16 B SHA-256[:16]?) | `{ segment_id, offset_in_segment, length, ref_count }` |
| `segment_map`| segment_id (u64)              | `{ file_offset, size, comp_alg, key_id, ... }`      |
| `unused_map` | extent start (u64)            | `{ extent_len }` (free-space tracker)               |
| `nlink_map`  | item_id (u64)                 | `{ nlink_count, parent_links }`                     |
| `notary_map` | item_id or sub-tree id        | Merkle node `{ degree, hash_alg, hashes[] }`        |
| *(filter)*   | content-hash prefix           | golomb-coded presence bit (dedup probe)             |

---

## 6. Open items / next steps

1. **Decode the cell stream.**  The encoding byte at `+0x06` selects
   between three variants; we need to confirm whether it is stock LZ4
   raw-block, Acronis-golomb, or a custom variant.  Path: decompile
   `ar_lsm_leaf_decompress` / `lsm_decompress_leaf` in Ghidra
   (`archive3.dll`).
2. **Identify type-`0x05` pages.**  11 contiguous high-entropy pages
   immediately before the ARCH chain.  Likely the v7 golomb dedup
   filter (since L-SB[6] is the golomb tree and points to LDIR
   13,347,623 which sits right after the 0x05 cluster), but unconfirmed.
3. **Field_b/c/d in L-SB.**  The four 32-bit fields between `magic`+
   `ver` and the ctree[] array hold (in some order) `seq`,
   `nr_ctree`, `max_ext_len`, `c0_count` and possibly a
   max-segment-size cap.  The exact mapping varies with `ver_block`.
4. **Multi-volume + commit-chain.**  We selected the single ARCH page
   with the highest commit_seq.  An archive that's been compacted /
   replicated will have a chain of older ARCH+ARCI pairs that we
   currently ignore.
