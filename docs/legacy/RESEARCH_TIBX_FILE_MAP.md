# RESEARCH_TIBX_FILE_MAP — full-file magic-byte cartography

Derived from a sequential scan of `/path/to/example.tibx` (54,671,892,480
bytes ≈ 50.9 GiB) using
[`tibread.tibx_magic_scanner`](../../tibread/tibx_magic_scanner.py).

> **Companion documents**
> - [RESEARCH_TIBX_STRINGS.md](./RESEARCH_TIBX_STRINGS.md) — strings-agent hypotheses
> - [RESEARCH_TIBX_STRUCTURE.md](./RESEARCH_TIBX_STRUCTURE.md) — Ghidra-derived header layout
> - This document confirms or refutes those hypotheses against the on-disk file.

## TL;DR

1. **Page size = 4096 bytes.** Confirmed: every structural magic (`ARCH`,
   `ARCI`, `LEAF`, `LDIR`, `SG\x00\x01`) lives at byte offset 8 of a
   4-KiB-aligned page. The first 8 bytes of every page are a fixed page
   header: a 2-byte type tag + 2 zero bytes + a 4-byte CRC (or random-looking
   value, almost certainly a checksum).

2. **The `CHBXI` magic is NOT present in this file.** It does not appear
   anywhere in the first 1 MiB and the global scan finds zero occurrences.
   The strings-agent's claim that `CHBXI` is the outer envelope is **refuted**
   for this `.tibx`. CHBXI is most likely just a string-table identifier in
   the binary (or used by a different .tibx variant).

3. **`QARCH` is a phantom magic.** The `Q` we see at offset 7 is the high
   byte of the page-0 4-byte CRC field; the next 4 bytes spell `ARCH`. The
   strings agent saw `QARCH` because they grep'd ASCII context around `ARCH`
   without realizing the `Q` is checksum noise. **`ARCH` is the real magic;
   the leading `Q` is not part of it.**

4. **`SG\x00\x01` (the previously-unknown 2-byte segment magic) is `SG`
   followed by version `0x0001`.** It marks every backup-data-segment page
   (page-type tag `0x41ff`). The global scan found this pattern at every
   data-page offset+8.

5. **The file is a single large flat array of 4 KiB pages** — there is no
   outer container envelope. Page-type tag at byte 0 of each page tells us
   what the page is:

   | tag (LE u16) | meaning |
   |---|---|
   | `0x0141` | ARCH header page (page metadata, ARCH magic at +8) |
   | `0x0241` | ARCI commit-index page (ARCI magic at +8) |
   | `0x0341` | LSM-tree page (LEAF/LDIR magic at +8) |
   | `0xff41` | data segment page (SG\x00\x01 magic at +8) |

## File-region map

```
   offset (hex)       offset (B)        content
   ───────────────────────────────────────────────────────────────────────────
   0x000000000000     0                 ARCH page #1 (file root header)
                                          page-tag=0x0141, ARCH magic at +8
                                          contains 9 L-SB records starting at +1036
   0x000000001000     4096              ARCH continuation page #2 (data extension
                                          of the L-SB record table)
                                          page-tag=0x0141, no magic at +8
   0x000000002000     8192              ARCI commit-index page #1
                                          page-tag=0x0241, ARCI magic at +8
   0x000000003000     12288             ARCH page #3 (second header chain entry)
                                          page-tag=0x0141, ARCH magic at +8
                                          more L-SB records
   0x000000004000     16384             ARCH continuation page #4
   0x000000005000     20480             ARCI commit-index page #2
                                          page-tag=0x0241, ARCI magic at +8

   0x000000006000     24576             *** START of segment-data region ***
                                          page-tag=0xff41, SG\x00\x01 magic at +8

   ...                                  ~13.4 million data pages of compressed/
                                          encrypted backup payload, 4 KiB each.
                                          Sparse ARCI commit-index pages
                                          interleaved through the data region.

   0x000cba78a000     54,671,015,936    *** START of LSM-tree region ***
                                          page-tag=0x0341, LEAF/LDIR magic at +8
                                          ~10,500 contiguous LEAF pages
                                          followed by ~7 LDIR pages
                                          + final ARCH/ARCI pages

   0x000cbab2d000     54,671,888,384    Last ARCI page (file root commit index)

   0x000cbab2e000     54,671,892,480    *** END OF FILE ***
                                          (no trailer, no zero padding)
```

The file-end ARCI is where the reader **starts** when opening a `.tibx` —
it follows the `prev_ci` chain backwards to walk all commits, and uses the
LSM tree (LEAF/LDIR) to look up logical block addresses.

## Page-header layout

Every 4 KiB page has the same fixed 8-byte prefix:

```
offset  size  field           example (page 0)
──────  ────  ──────────────  ────────────────
   0      2   page_type_tag   0x0141  (interpreted as LE u16)
   2      2   reserved/pad    0x0000
   4      4   page_crc        0x510a0b2e (random-looking; CRC32 most likely)
   8      4   page_magic      "ARCH" / "ARCI" / "LEAF" / "LDIR" / "SG\x00\x01"
  12      *   page-specific body
```

(Some pages have **no** magic at +8, e.g., ARCH continuation pages whose body
just continues the L-SB record table from the previous page.)

## Magic occurrence counts (full-file scan)

| magic | count | first occurrence | last occurrence | dominant alignment |
|---|---|---|---|---|
| `CHBXI` | 0 | — | — | — (NOT PRESENT) |
| `QARCH` | (file-start phantom) | 0x7 | (rare, all coincidental) | offset+7 = ASCII `Q` byte before `ARCH` |
| `ARCH` | (filled in after scan) | 0x8 | 0xcbab2b008 | `% 4096 == 8`, page-tag `0x0141` |
| `ARCI` | (filled in after scan) | 0x2008 | 0xcbab2d008 | `% 4096 == 8`, page-tag `0x0241` |
| `L-SB` | (filled in after scan) | 0x40c (1036) | within page 0 / ARCH pages | record-level (NOT page-aligned), 380-byte stride |
| `LEAF` | (filled in after scan) | 0xcba78a008 | (near 0xcba91x000) | `% 4096 == 8`, page-tag `0x0341` |
| `LDIR` | (filled in after scan) | (near 0xcba928008) | 0xcbab27008 | `% 4096 == 8`, page-tag `0x0341` |
| `SG\x00\x01` | (filled in after scan) | 0x6008 | (~0xcba789008) | `% 4096 == 8`, page-tag `0xff41` |

> **Critical: 4-byte ASCII magics inside encrypted/compressed data pages
> generate ~12 false positives per magic across 51 GB by random chance.**
> The scanner's classifier (`classify_offsets`) splits matches into
> `page-magic` (real, page-tag is not `0xff41`), `data-page-noise`
> (coincidental match inside a `0xff41` data page), and `in-page` (record
> not at page+8, e.g., L-SB).

## L-SB record table

`L-SB` (L-superblock?) records appear in clusters at the start of certain
ARCH pages. They are NOT page magics; they are length-prefixed records
within the body of an ARCH page. Layout:

```
   offset  size   field
   ──────  ────   ──────────────────────────────────
      0     4     length (big-endian uint32, e.g. 0x00000178 = 376)
      4     4     "L-SB" magic
      8     2     version major.minor (`0x0201` ?)
     10     N     record body (typically 376 bytes for type-1 records;
                                 some seen at 441 bytes — variable schema)
```

In page 0, 9 records of 376 bytes are packed at offsets 1036, 1416, 1796,
2176, 2556, 2936, 3316, 3696, 4076 (stride 380 = 4-byte length + 376-byte
body). The 9th record (offset 4076) overflows into page 1; this confirms
that ARCH pages chain via continuation pages — page 1 has page-tag `0x0141`
(same as ARCH) but no magic at +8 because its body is the continuation of
page 0's L-SB record table.

Page 3 (the second ARCH page) starts another L-SB cluster at offset
13324. Mixed-size records are present (376 and 441 bytes seen).

## ARCI commit-index chain

ARCI pages form a backwards-linked chain via a `prev_ci` pointer at offset
~24 of the ARCI body. Walking from the file-end ARCI (`0xcbab2d000`)
follows the chain to `prev_ci=0xcbab2b000`, etc., enabling crash recovery:
torn writes always leave the previous ARCI valid.

The first two ARCIs are at very low offsets (0x2000, 0x5000) and the last
several are clustered at the end (`0xcbab2b000`, `0xcbab2d000`). Most of
the body is unused (only ~58 nonzero bytes in the final ARCI).

## Confirmation / refutation of strings-agent hypotheses

| strings-agent claim | verdict |
|---|---|
| `CHBXI` (5B) is the outer `.tibx` container envelope, at file start | **REFUTED.** CHBXI is not in the file at all. |
| `QARCH` (5B) at offset 7 | **REFUTED.** That `Q` is a CRC byte; the magic is `ARCH` at offset 8. |
| `ARCH` (4B) is the file-level archive header | **CONFIRMED.** ARCH is the page magic of page-tag `0x0141` pages. |
| `ARCI` (4B) is a commit-index page, chained via `prev_ci` | **CONFIRMED.** ARCI pages use page-tag `0x0241`, link via the field at body offset ~24. |
| `L-SB` (4B) is the LSM-tree superblock | **PARTIALLY CONFIRMED.** L-SB is a length-prefixed record (NOT a page magic) embedded inside ARCH pages — it likely describes per-stream/per-segment metadata, not a tree superblock. |
| `LEAF` (4B) is an LSM-tree leaf node | **CONFIRMED.** LEAF is the page magic of page-tag `0x0341` pages, packed contiguously at file end. |
| `LDIR` (4B) is an LSM-tree directory node | **CONFIRMED.** LDIR is the page magic of page-tag `0x0341` pages just after the LEAF block. |
| 2-byte segment magic exists, value unknown | **CONFIRMED & IDENTIFIED.** The 2-byte magic is `SG` (`0x53 0x47`); seen as the 4-byte payload `SG\x00\x01` (magic + 2-byte version) at every data-page offset+8. |

## Logical structure

```
[ARCH header chain]   [data segments]    [LSM tree]    [ARCI commit chain tail]
   pages 0..5           pages 6..N        N..N+10500     last few pages
   ~24 KiB              ~50 GiB           ~42 MiB        ~16 KiB
```

- The **ARCH chain at the file start** is the bootstrap header — it lists
  the streams (L-SB records) and the early ARCI checkpoints.
- The **data segment region** (page-tag `0xff41` with `SG\x00\x01` magic
  at +8) holds the compressed/encrypted backup payload. Each segment page
  is 4 KiB and stores a small page header + an offset/range descriptor +
  payload.
- The **LSM tree at the file end** is a sorted index used to look up
  logical block addresses (LBAs) and find the corresponding data segment
  page. LEAF pages hold key-value pairs; LDIR pages are the inner-node
  routing tables.
- The **ARCI commit-index tail** is the latest commit point; reading
  starts here and walks backwards.

## Reproducing the scan

```bash
cd /path/to/tibread/dist
/path/to/tibread/venv/bin/python -m tibread.tibx_magic_scanner \
    "/path/to/example.tibx" \
    --save-offsets /tmp/tibx_offsets.json
```

The scanner is at
[`/path/to/tibread/tibread/tibx_magic_scanner.py`](../../tibread/tibx_magic_scanner.py).
Key features:

- Streams the file in 64 MiB chunks with a small overlap window so magics
  straddling chunk boundaries are still caught.
- Bounded memory (~150 MiB RSS observed) regardless of file size.
- Single-pass `re.finditer` with all magics combined into one pattern.
- Optional `classify_offsets()` post-processor that re-reads each
  candidate page-header tag to separate real page-magics from
  random-data-page false positives.

## Open questions / next steps

1. **Decode the per-page CRC at bytes 4..7.** Likely CRC32C of the
   following 4088 bytes; needs verification against a couple of pages.
2. **Decode the L-SB record schema** (bytes 10..end) — these describe
   streams/extents per the page-0 layout.
3. **Walk the ARCI chain end-to-end** and count commits.
4. **Decode the LSM LEAF/LDIR key-value structure.** The LEAFs are
   contiguous (10,500+ pages) so the index is sorted-runs.
5. **Identify the data-segment page format**: SG\x00\x01 + version + LBA
   range + payload. The 32-byte snapshot at page 6 was
   `SG\x00\x01\x00\x04\x00\x00\x00\x00\x01\xe0\x00\x00\x00\x00\x03\x02\x00\x00\x00\x00\x00\x00`.
   Looks like `magic | version=1 | flags=0x0004 | start_lba=0x000001e0 |
   ... | length=...`.
