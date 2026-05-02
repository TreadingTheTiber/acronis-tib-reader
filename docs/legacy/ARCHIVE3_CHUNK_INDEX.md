# ARCHIVE3_CHUNK_INDEX — source-disk LBA -> segment lookup

How `.tibx` archives map a source-disk byte (LBA) to the segment that
holds its bytes, what was tried, what works today, and what's blocking
full random-access disk-image reads.

## TL;DR

* `.tibx` SG segments hold **variable-length blobs of source-disk
  content** (4 KiB to 512 KiB observed; mean ~210 KiB).  There is no
  fixed chunk size.
* The mapping `source_byte_offset -> (segment_id, offset_in_segment)`
  lives in the **`segment_map` LSM tree** (L-SB index 2 in
  `example.tibx`, root page 13,347,532, ~417 pages).
* The segment_map LSM tree's leaf-cell decoder is **not yet
  implemented**.  See `tibread/tibx/lsm.py` — `parse_leaf` returns
  the raw cell bytes; the Acronis Golomb / LZ4 codec from
  `lsm_golomb.c` still needs porting.
* Until the cell decoder lands, `TibxReader.read_lba_range()` only
  serves the **bootstrap region** `[0, 262_144)` of the source disk
  (the first SG segment, which is empirically the MBR plus the first
  256 KiB of disk content).  Anything past that raises
  `ChunkMapNotImplemented`.
* The end-to-end MBR-read demo works today and is asserted by
  `tools/tests/test_tibx_disk_image.py`.

## Refuting the "segment 3 is a u16 chunk-id index" hypothesis

An earlier exploratory pass observed that the 4th SG segment in
`example.tibx` (the 139,264-byte segment at page 9) decompresses
to bytes that *start* with the `u16` little-endian sequence
`0001 0002 0003 0004 ...`, and proposed that it was a flat
`u16[chunk_id] -> segment_id` index.  Closer inspection refutes this:

| Observation | Implication |
|---|---|
| The first 65,536 `u16` values form a near-identity ramp `0..96` then jump to `65..90` then `123..N`, then become a "doubled-pair" pattern (`x, x, x+2, x+2, ...`) starting near index 256. | A real chunk-id array would be strictly monotonic except where deduplication causes back-references; this looks more like NTFS-internal small-integer fields (file references, cluster IDs, etc.). |
| At decompressed-byte offset `0x20000` (= just past the 65,536 `u16` values), the bytes are `49 4E 44 58` = `"INDX"` followed by a valid NTFS index-buffer header (USA offset = 40, USA count = 9, allocated size = 4072). | This is an NTFS index buffer.  No chunk-id index would put a 4-KiB-aligned NTFS structure at exactly the 64K-entry boundary. |
| At decompressed-byte offset `0xa485` the bytes spell `"RCRD"`. | This is an NTFS `$LogFile` log-record marker. |
| The total decompressed length is 139,264 bytes — neither a power of two nor divisible by any plausible chunk count for a 51 GB archive. | A 51 GB archive at the empirically observed *maximum* segment size of 512 KiB would have ~100,000 chunks, not 65,536 or 69,632. |
| Scanning 3,493 SG segments shows lengths in `{4096, 8192, 12288, ..., 524288}` with **no fixed stride** (mean 209,610 bytes; max 524,288 bytes; min 4,096 bytes). | Segments are variable-length extents.  A flat fixed-stride chunk array is therefore architecturally impossible. |

The most likely actual identity of segment 3 is a piece of NTFS
metadata (probably a slice of `$MFT` or a piece of the
`$LogFile`/`$INDX` structures from the source disk's first
partition).  The leading "u16 ramp" is just NTFS internal data that
happens to look ordered.

## What the segment_map LSM tree contains

Per `tibread/tibx/lsm.py` and observed L-SB superblocks in
`example.tibx`:

| L-SB # | sb_size | root_page  | name (inferred)         | size       |
|--------|---------|------------|--------------------------|-----------|
| 0      | 0x2B2   | (c0 only)  | name_map                 | small      |
| 1      | 0x178   | 13,347,115 | data_map                 | ~418 pages |
| 2      | 0x178   | 13,347,532 | **segment_map**          | ~417 pages |
| 3      | 0x178   | 13,347,604 | notary_map               | ~71 pages  |
| 4      | 0x22B   | (c0 only)  | unused_map               | (no runs)  |
| 5      | 0x1E8   | (c0 only)  | nlink_map                | (no runs)  |
| 6      | 0x1B5   | 13,347,623 | golomb dedup filter (v7) | ~8 pages   |

**Tree #1 (`data_map`)** likely maps source-disk **byte ranges** to
**segment_ids + offsets** (since the data_map name and 418-page size
match the scale needed to index ~50 GiB of payload at one entry per
half-MiB extent).

**Tree #2 (`segment_map`)** likely indexes segments by some integer key
(segment_id?) and stores their *file*-byte offset, length, and
metadata.

These are the two trees that, together, replace what `.tib`'s
`chunk_map` did.  Walking either requires the LEAF/LDIR cell decoder
which is not yet implemented (see `lsm.py: parse_leaf` — it currently
returns header-only placeholder entries because the Golomb / LZ4 cell
codec hasn't been ported).

## Segment 3's actual content (best guess)

Of the 22 SG segments scanned in pages 6..200:

| # | Page | Length    | `file` output                                            |
|---|------|-----------|---------------------------------------------------------|
| 0 | 6    | 262,144   | DOS/MBR boot sector — MS-MBR Windows 7 (full MBR + first 256 KiB) |
| 1 | 7    | 4,096     | NTFS boot sector (\$MFT cluster 29866, BOOTMGR, sysreserved partition) |
| 2 | 8    | 8,192     | (NTFS metadata)                                          |
| 3 | 9    | 139,264   | NTFS metadata — `INDX` records at 0x20000/0x21000 + `RCRD` ($LogFile) at 0xa485 |
| 4 | 42   | 20,480    | PE32+ (DLL) — likely a Windows boot driver/DLL           |
| 9 | 49   | 77,824    | PE32 (DLL) — Intel 80386 Windows DLL                     |

The pattern is consistent with a per-partition backup strategy:
segment 0 is the whole-disk MBR plus first 256 KiB; segments 1..3 are
NTFS metadata for the first partition; later segments hold individual
files (PE binaries) and registry hives (`hbin` magic).

## The bootstrap path that works today

`tibread.tibx.disk_image.read_lba_range(reader, start_lba, length)`:

1. Validates arguments (`start_lba >= 0`, `length > 0`, byte range
   inside `[0, 262_144)`).
2. Locates the first SG segment by scanning pages 0..63 with
   `reader.find_segments()` and taking the first hit.
3. Decompresses that segment via `reader.decompress_segment()`.
4. Slices `[start_lba * 512, start_lba * 512 + length)` and returns it.

Reads outside the bootstrap region raise
`ChunkMapNotImplemented` with a message pointing at
`segment_map` / `parse_leaf`.

The same logic is exposed as `TibxReader.read_lba_range()` for
convenience.

## Verification (confirmed via byte inspection)

| Claim | Evidence |
|---|---|
| Segment 0 contains the source-disk MBR | `seg0[510:512] == b"\x55\xaa"`, `seg0[0]==0x33` (MS-MBR boot code), and `file(1)` reports `MS-MBR Windows 7` with two NTFS partitions starting at LBAs 2048 and 718848 |
| Segment 0 covers source-disk bytes `[0, 262144)` | The segment's `length` field is 262,144 and the MBR boot code at offset 0 confirms LBA-0 alignment |
| `read_lba_range(0, 16384)` returns 16,384 bytes ending in the 0x55AA MBR mark at offset 510 | `tools/tests/test_tibx_disk_image.py::test_first_16k_starts_with_mbr_boot_code` |
| Segments are variable-length (4 KiB to 512 KiB) | Histogram over 3,493 segments shows 15 distinct length buckets, all multiples of 4 KiB |
| Segment 3 contains NTFS metadata, not a chunk index | NTFS `INDX` headers parse cleanly at offsets `0x20000`, `0x21000`; `RCRD` magic at `0xa485` |
| Max value in seg-3 leading u16 array is `0xFFFF` (saturating, not a real cap) | Only one occurrence of `0xFFFF` exists, at exactly index 65535, then values *decrease* to `20041, 22596, 40, 9, ...` immediately after — clearly NTFS structure data, not array entries |

## Inferred (not yet byte-verified)

* L-SB tree #1 = `data_map`, indexing source-disk byte ranges to
  `(segment_id, offset)` — inferred from name ordering and page count.
* L-SB tree #2 = `segment_map`, indexing segments themselves.
* The Acronis Golomb codec (`lsm_golomb.c`) is what the LSM cells use
  — confirmed by string analysis but not by byte-level decode.

## What to do next

To finish this work, the missing pieces are (in order):

1. **Decode LEAF cells.**  `tibread/tibx/lsm.py: parse_leaf` currently
   returns the raw cell-payload bytes.  Port the Acronis Golomb / LZ4
   codec from `archive3.dll: lsm_decompress_leaf` (or re-derive it
   from `lsm_golomb.c` strings).
2. **Walk the `segment_map` LSM tree** from its root page (13,347,532
   for `example.tibx`).  Each leaf cell will yield a
   `(key, value)` pair where `key` likely encodes either a
   source-byte offset or a segment_id, and `value` encodes the
   target.
3. **Implement `lookup_chunk_via_segment_map()`** in
   `tibread/tibx/disk_image.py` (currently a stub raising
   `ChunkMapNotImplemented`).
4. **Generalise `read_lba_range()`** to use the lookup for any range,
   handling the case where a single read spans multiple segments.

Once steps 1–4 land, the bootstrap special-case in
`disk_image.read_lba_range()` can be removed and the function becomes
a true random-access disk-image read.
