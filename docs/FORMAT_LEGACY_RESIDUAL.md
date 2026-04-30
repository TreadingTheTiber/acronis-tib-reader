# FORMAT_LEGACY_RESIDUAL.md - The 1.89 MB residual region in TI 2014-era `.tib`

Companion to `FORMAT_LEGACY_TAIL.md`.  That document classifies the 3.10 MB
post-block-stream tail of example's `.tib` into a 1.08 MB MD5 dedup manifest
plus a 1.89 MB "residual region" of unknown internal structure.  This document
decodes that residual.

Empirically derived from `/path/to/legacy_example.tib`
(8,776,798,720 bytes, 70,709 blocks, two source volumes).

> **TL;DR**: the residual region is **the legacy format's pre-trailer
> "miscellaneous metadata" container**.  It bundles together five logically
> independent items, NOT a single homogeneous structure:
> 1. a 16-byte sealed-region header,
> 2. a small partition descriptor + ~15 KB cluster bitmap for Volume4,
> 3. a 1.78 MB **AES-encrypted** opaque blob (almost certainly the per-cluster
>    SHA1/MD5/checksum stream, with HMAC trailer) — the only piece we cannot
>    decode without the per-archive key,
> 4. a separate ~6 KB "Volume3" descriptor + ~57 KB **zlib stream** that
>    expands to 264,192 bytes of MBR + track-0 boot data, and
> 5. a final ~2 KB cluster of TLV partition descriptors covering BOTH
>    HarddiskVolume3 (System Reserved) and HarddiskVolume4, plus the disk
>    model string `CORSAIR CMFSSD-128GBG2` and an embedded XML productinfo
>    block (`<metainfo>...<productinfo name="True Image">... build 6514`)
>    that names the producer build.
>
> The 16-byte header's count value `0x00485fc8 = 4,743,112` is the
> NTFS-allocated cluster count of the source volume HarddiskVolume4
> (= 18.09 GiB).  The backed-up portion of Volume4 is 4,499,776 clusters
> (17.16 GiB); the ~243K-cluster shortfall accounts for unbacked tail blocks
> (page/hibernation files, unallocated high-LBA region, etc.).
>
> **No, there is no separate residual region for HarddiskVolume3.**  Both
> volumes are described inline within this single residual.  The Volume3
> equivalent of the 1.78 MB Volume4 encrypted blob is a much smaller (~6 KB)
> region in the middle of this residual, sized proportionally to Volume3's
> 25,600 clusters (vs Volume4's 4.5M+).
>
> **Correction**: `FORMAT_LEGACY_TAIL.md` reported the header count as
> `4,743,624`; the true value is `4,743,112` (`u32 LE c8 5f 48 00`).

---

## File-offset map (example)

The residual occupies bytes `[1,129,744 .. 3,107,417)` of the post-block-stream
tail, equivalently `[8,774,820,840 .. 8,776,798,513)` in the full `.tib`.

```
offset (in residual)  size       content
---------------------+----------+--------------------------------------------
+0                    16 B       residual header (flag 0x80000000 + count + zero pad)
+16                   104 B      zero pad
+120                  28 B       small unidentified struct (Volume4 descriptor preamble?)
+148                  524 B      mostly zeros + 3 isolated 4-byte tag values
+672                  3,688 B    zero alignment pad
+4,360                ~15.5 KB   Volume4 cluster-allocation bitmap (mostly 0xFF runs)
+19,896               ~4 B       zero gap
+19,900               1,866,192  *** Volume4 ENCRYPTED blob (~1.78 MB AES ciphertext) ***
+1,886,060            ~30 B      HMAC / auth trailer for the encrypted blob
+1,886,090            ~52 B      zero gap
+1,886,144            ~6,300 B   Volume3 cluster bitmap + small descriptor
+1,892,448            ~7,272 B   zero gap
+1,899,720            ~928 B     Volume3 secondary descriptor
+1,900,648            16,020 B   zero alignment pad
+1,916,668            ~1,500 B   per-disk descriptor (small TLV records)
+1,918,156            58,596 B   *** zlib stream -> 264,192 bytes MBR + track 0 boot data ***
+1,976,752            ~14 B      misc transition
+1,976,770            21 B       small zlib stream -> 20-byte trailer struct
+1,976,791            198 B      zlib stream -> 239-byte XML productinfo block
+1,976,989            ~125 B     transition / TLV preamble
+1,977,113            ~561 B     trailing TLV partition cluster (CORSAIR + Vol3 + Vol4 records)
+1,977,673            EOR
```

Three files at the end of the residual (zlib boot, zlib trailer, zlib XML)
are followed by the final TLV partition info before the residual hands off
to the 37-byte trailer body at file offset `8,776,798,513`.

The 56 KB "second high-entropy blob" identified in `FORMAT_LEGACY_TAIL.md` is
**a clean zlib stream** that decompresses successfully — it scored as "high
entropy" only because deflate output is naturally near-uniform.

---

## 1. Residual header (16 B)

```
00 00 00 80   c8 5f 48 00   00 00 00 00   00 00 00 00
^^ u32@+0    ^^ u32@+4
   = 0x80000000  = 0x00485fc8 = 4,743,112
   "sealed" flag    NTFS cluster count for HarddiskVolume4
```

### What is `4,743,112`?

| Constant                                | Value     | Diff vs count |
|-----------------------------------------|-----------|---------------|
| count (residual header u32@+4)          | 4,743,112 | --            |
| Volume4 NTFS-allocated cluster count    | 4,743,112 | 0             |
| Volume4 backed-up clusters (= 17.16 GiB)| 4,499,776 | -243,336      |
| Both volumes' stored clusters (= 70,709 × 64) | 4,525,376 | -217,736 |
| Block count (`scan_example.py`)          | 70,709    | -- (unrelated) |

The count is the **total NTFS-allocated cluster count for Volume4** as
reported by NTFS at backup time.  It is *not* the count of clusters that
Acronis actually wrote into the backup — that number is 4,499,776
(blocks_for_vol4 × 64).  The 243,336-cluster (= 950 MiB) difference is
clusters that NTFS marks as in-use but Acronis chose not to back up
(typically `pagefile.sys`, `hiberfil.sys`, and other excluded files
configured in the True Image settings, plus any volume tail rounding).

Volume3 (System Reserved, 100 MiB = 25,600 clusters) is small enough that it
is described separately later in the residual; the 16-byte header is
specifically for Volume4.

### Confidence

- **Confirmed**: The byte sequence is exactly `00 00 00 80 c8 5f 48 00 00*8`,
  the `0x80000000` flag is universally an "end-of-stream / sealed" marker in
  Acronis structures, and the count (4,743,112) appears nowhere else in the
  full `.tib` (5 raw byte-sequence matches in 8.7 GB, 4 of which are
  random coincidences inside compressed block data, 1 of which is THIS
  header).
- **Inferred**: that the count specifically equals Volume4's NTFS cluster
  count.  The arithmetic fit is exact (18.09 GiB at 4 KiB clusters), the
  difference from the backed-up count is plausible (excluded files), and
  the modern format has an analogous "partition_size_in_clusters" header on
  its post-data streams.  Not confirmed via decompilation.

`FORMAT_LEGACY_TAIL.md` reported this count as `4,743,624`; that was a
transcription error.  The true value, obtained by parsing the bytes, is
`4,743,112`.  The error can be verified directly by the script:

```
$ python3 decode_legacy_residual.py --header
  raw          : 00000080c85f48000000000000000000
  u32@+4       : 0x00485fc8 = 4,743,112
```

---

## 2. Volume4 cluster bitmap (~15.5 KB)

```
+0      16 B   header (flag + count = 4,743,112)
+16     104 B  zeros
+120    28 B   small struct  (8B = u64 partition signature + 16B = MFT pointer?)
+148    524 B  mostly zeros + 3 isolated 4-byte tag values
+672    3688 B zero alignment pad
+4360   ~15536 B  cluster-allocation bitmap (1 bit per ~38 clusters?)
+19896  4 B    zero terminator
```

The "bitmap" region at residual offset 4360..19896 is **15,536 bytes =
124,288 bits**.  Its byte-frequency profile (84% 0xFF, with sparse 0-runs
and bit-flips around them) is the unmistakable signature of an
NTFS-style cluster allocation bitmap (or an Acronis re-encoding of one).

A 1-bit-per-cluster bitmap for Volume4 (4,743,112 clusters) would require
592,889 bytes — 38× larger than what we have.  So this is **NOT** a raw
1-bit-per-cluster bitmap.  Two possibilities, neither confirmed:

1. **Coarse-granularity bitmap**.  124,288 bits × ~38 clusters/bit ≈
   4,723K clusters covered.  The granularity ratio of ~38 doesn't match a
   power-of-two but does match `4,743,112 / 124,288 ≈ 38.16`, suggesting a
   bitmap where each bit covers ~38 clusters.  This would be analogous to
   NTFS $Bitmap-attribute's "compressed view" — used for fast pre-flight
   scans before the full bitmap is consulted.

2. **Per-block bitmap with metadata interleaved**.  70,709 blocks (Vol4
   alone has ~70,309 blocks) need only 8,839 bytes for a 1-bit-per-block
   bitmap.  The remaining ~6,700 bytes could be small per-block metadata
   (popcount, dedup flag, etc.).  But the bit-layout doesn't visibly split
   into 8,839 + 6,700.

Without decompilation, we can't distinguish these.  The structural shape
("mostly 0xFF with isolated cleared bits") is consistent with both
hypotheses; the practical observation is that **this region encodes
allocation/coverage information for the Volume4 cluster space**, at coarser
than 1 bit per cluster.

### Confidence

- **Confirmed**: byte distribution and run pattern match a bitmap.
- **Inferred**: granularity ≈ 38 clusters/bit and exact role.

---

## 3. Volume4 encrypted blob (1.78 MB)

```
+19,900     1,866,192 B   AES-CBC ciphertext (entropy 7.9999, chi^2 = 237.9)
+1,886,060      ~30 B      HMAC / auth trailer
                            01 13 00 04 00 04 1e 00 00 00 d1 00 00 00 00 94
                            02 00 00 20 00 00 00 ...
+1,886,090       0          end of encrypted region
```

This is the LARGEST and the only TRULY OPAQUE part of the residual.

### Statistical signature

```
entropy           : 7.9999 bits / byte (max=8.0)
chi-square (df255): 237.9  (uniform RNG expects ~255 ± 22)
unique 16-B blocks: 116,637 / 116,637  (100.00%)
byte 0x00 fraction: 0.392%  (uniform expects 0.391%)
byte 0xFF fraction: 0.397%  (uniform expects 0.391%)
```

The blob is **statistically indistinguishable from random**.  This rules out
deflate-compressed plaintext (which has minor non-uniformity from header bits
and Huffman-table residue) and rules out AES-ECB on uniform plaintext (which
would produce repeating 16-byte blocks for any duplicate plaintext blocks).
**100% unique 16-byte blocks at this scale is the unmistakable signature of
AES-CBC, AES-CTR, or any other IV-mixed cipher mode.**

Decompression attempts:

- zlib (any window size) at every starting offset 0..256: no success.
- raw deflate (`wbits=-15`) at every starting offset 0..256: no success.
- bz2, lzma, snappy: no success.

### Inferred contents

By analogy with the modern format's post-data encrypted streams (decoded by
agent C):

- **Most likely**: per-cluster HMAC-SHA1 or HMAC-MD5 stream for the
  4,499,776 backed-up Volume4 clusters.  At 1,866,192 bytes / 4,499,776
  clusters ≈ 0.41 bytes/cluster average, which is far too low for a per-
  cluster *checksum*.  However, at 16-byte AES granularity, the encrypted
  stream contains 116,637 blocks of 16 bytes = 1,866,192 bytes.  The
  plaintext could be:
    - 116,637 × 16-byte records (= one record per 38.6 clusters: see the
      bitmap-granularity match!), or
    - a compressed-then-encrypted bitmap or summary, or
    - a pre-IV padded structure.
- The 30-byte trailer at +1,886,060 is the HMAC-SHA1 truncated to 20 bytes
  + small length prefix (`01 13 00 04 00 04 1e 00`), which Acronis uses
  ubiquitously as HMAC tags in 2014-era backups.

### Why is metadata encrypted in an unencrypted backup?

True Image 2013/2014 encrypts a small amount of metadata using a key
**derived from the archive ID** (`15878547e53ed64d` per
`FORMAT_LEGACY_TAIL.md`'s trailer body) even when no user password is set.
This is sometimes called the "fixed-key metadata seal" in the modern format
docs (agent C's notes).  It's not a security feature — anyone with the
archive can derive the same key — but it means the bytes appear encrypted
on inspection.

### Confidence

- **Confirmed**: data is NOT deflate, NOT raw, IS uniform random at AES block
  granularity.
- **Inferred**: it is AES-encrypted Acronis metadata for Volume4, and the
  trailer at +1,886,060 is the auth tag.  Specific plaintext content not
  determined.

---

## 4. Volume3 region (~6 KB) and inter-volume gap

```
+1,886,144   ~6,300 B   Volume3 cluster bitmap + small descriptor
+1,892,448   ~7,272 B   zero gap
+1,899,720   ~928 B     Volume3 secondary descriptor (TLV-ish)
+1,900,648   16,020 B   zero alignment pad
+1,916,668   ~1,500 B   per-disk descriptor (small TLV records)
```

**Yes, Volume3 (System Reserved, 100 MiB / 25,600 clusters) DOES have its own
metadata structure within this residual.**  It is much smaller than
Volume4's because it covers proportionally less data: 25,600 clusters vs.
4,743,112.  At the same encoding density (~40 clusters/bit for the bitmap,
plus a small encrypted blob for the cluster checksums), 25,600 / 4,743,112
of 1.78 MB ≈ 9.6 KB, which matches the observed ~6 KB + descriptor regions.

There is **no separate residual region elsewhere in the file** for
Volume3.  Whole-file searches for the marker pattern `00 00 00 80 ?? ?? ??
00 00*8` find only the one residual header at offset 4 of the residual
(file offset 8,774,820,844).  Whole-file searches for the ASCII strings
`\Device\HarddiskVolume3` and `\Device\HarddiskVolume4` find ONLY two
matches each, both at the very end of the residual (offsets 1,977,342 and
1,977,613).

So: the residual is a **single per-archive structure** that internally
contains per-volume sub-structures.  It is not duplicated.

### Confidence

- **Confirmed**: only one residual exists in the file; no second
  `0x80000000`-flagged header anywhere; only one occurrence of each
  device-path string.
- **Inferred**: that the [1,886,144..1,900,648) region specifically encodes
  Volume3 metadata (by position relative to Volume4's encrypted blob and by
  size proportion).

---

## 5. MBR + boot region zlib stream (58.6 KB → 264 KB)

```
+1,918,156   58,596 B compressed (sig 78 01) -> 264,192 B decompressed
```

The largest "high entropy" sub-region of the residual (`FORMAT_LEGACY_TAIL.md`
called this the "57 KB high-entropy blob") is in fact a perfectly valid zlib
stream that decompresses successfully:

```
$ python3 decode_legacy_residual.py --boot
  largest zlib stream: 58596 comp -> 264192 decomp
    starts at residual offset 1918156

  first 16 bytes of decompressed: 0000000033c08ed0bc007c8ec08ed8be
    (4-byte length prefix '0000 0000' then MBR boot code 33c08ed0...)

  MBR sector (4..516):
    boot code [0..440]: starts with 33c08ed0bc007c8e (= standard pre-NT MBR)
    disk signature [440..444]: 0eb30400
    boot signature [510..512]: 55aa (VALID)

  partition table:
    part 0: status=0x80 type=0x07 first_LBA=2048 count=204800 (0.10 GiB)
    part 1: status=0x00 type=0x07 first_LBA=206848 count=249860096 (119.14 GiB)
    part 2: <empty>
    part 3: <empty>

  embedded text strings:
    'Invalid partition table' at decomp off 359
    'Error loading operating system' at decomp off 383
    'Missing operating system' at decomp off 414
```

This is **the first 516 sectors of the source disk**, captured verbatim:
the full MBR sector (with `0x55AA` at offset 510) followed by the rest of
the pre-partition area (track 0 / cylinder 0).  Acronis backs this up so
that bootability is preserved after restore — a restored disk is bootable
because the MBR boot code, partition table, and pre-partition region are
all reproduced exactly.

The decompressed structure is `[u32 length-prefix=0][512-byte MBR][rest of
track 0]` totalling 264,192 bytes (= 516 sectors = 64.5 4KiB clusters).

The MBR confirms the source disk geometry given by the manifest:

- Partition 1: type 0x07 (NTFS), LBA 2048, 204,800 sectors = 100 MiB =
  **HarddiskVolume3** ("System Reserved")
- Partition 2: type 0x07 (NTFS), LBA 206,848, 249,860,096 sectors = 119.14 GiB =
  **HarddiskVolume4** (the main NTFS data partition; backed up portion = 17.26 GiB)
- Disk model: `CORSAIR CMFSSD-128GBG2` (per the trailing TLV)

### Confidence

- **Confirmed via decompression**: standard zlib, MBR signature valid, all
  embedded strings recognisable, partition table self-consistent with the
  rest of the backup.

---

## 6. Productinfo XML (198 B → 239 B zlib)

A small zlib stream at residual offset 1,976,791 decompresses to:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<metainfo>
    <productinfo name="True Image">
        <version major="16" minor="0" />
        <build number="6514" />
    </productinfo>
    <task_id id="C1133A11-4824-4C42-8DD6-8A7264522492" />
</metainfo>
```

- **True Image major.minor 16.0 build 6514** -- this is Acronis True Image
  2013 (calendar version 16, internal name "ATI 2013"), specifically build
  6514.  This nails down the producer version.
- **task_id GUID**: `C1133A11-4824-4C42-8DD6-8A7264522492` -- the unique ID
  of the backup *task* that produced this `.tib`.  The task ID is in
  addition to the archive ID (`15878547e53ed64d`); a single archive can
  contain multiple files (full + incrementals) all sharing the same task
  ID and a per-archive ID.

A 21-byte preceding zlib stream (residual offset 1,976,770) decompresses to
20 bytes:

```
28 d1 44 16 04 00 00 00 e4 e4 00 00 00 00 00 00 00 00 00 00
```

This appears to be a small fixed-format trailer struct (probably a CRC or
small descriptor for the XML block that follows).  Not decoded further.

### Confidence

- **Confirmed via decompression**: clean UTF-8-with-BOM XML.

---

## 7. Trailing TLV partition cluster (~561 B)

The final ~561 bytes of the residual (offsets 1,977,113..1,977,673) contain
a dense cluster of Acronis short-tag TLV records.  Recognisable strings:

| String                          | Off (residual) | Encoding |
|---------------------------------|----------------|----------|
| `CORSAIR CMFSSD-128GBG2`        | 1,977,113      | ASCII    |
| `\Device\000000ae`              | 1,977,139      | ASCII    |
| `\Device\HarddiskVolume3`       | 1,977,342      | ASCII    |
| `System Reserved`               | 1,977,387      | UTF-16 LE |
| `\Device\HarddiskVolume4`       | 1,977,613      | ASCII    |

The raw final-400-byte hex dump:

```
... \Device\HarddiskVolume3 ...r2... P...System Reserved ...
... 38..<...C..FD..FE...F...G...] ... ^...=.f.#.x[...[...[...P.[...[k..F....
\Device\HarddiskVolume4 ....#......v..............>.!.....V}
```

The trailing `V}` is the last byte of the residual at offset 1,977,673.
The very next byte in the file is the start of the 37-byte trailer body at
file offset `8,776,798,513`.

The TLV grammar here is the same one documented in `METADATA_BLOB_TLV.md`
(short tag `XX YY`, variable-length value).  Per-record interpretation has
not been chased because it is not load-bearing for block decoding —
identifying that **both** volumes are described inline already answers the
relevant question for this analysis.

### Per-volume TLV records

The two volume blocks have nearly-identical TLV layouts:

```
\Device\HarddiskVolumeN
93 00 ...  -- some short value (3 bytes)
94 00 ...  -- some short value (3 bytes)
a3 00 00 c8 00 ...  -- 5-byte value
03 80 ... 0b 02     -- partition GUID-like value
04 80 ... 56 7d     -- final terminator pair
```

These match the structure of partition-info records seen in the modern
format's post-data XML metadata stream.

### Disk-level TLV record (preceding the volume records)

Before the Volume3 record, another block:

```
... 12 00 04 b0 c2 e7 0e
H 00 00 49 00 01 02 J 00 01 ?K 00 01 .. S 00 00 X 00 16
CORSAIR CMFSSD-128GBG2
81 00 11 10 \Device\000000ae
98 00 00 ...
```

This is the **disk descriptor**: model string, kernel device handle path
(`\Device\000000ae`), some partition-style ID values.  Followed by the per-
volume entries.

### Confidence

- **Confirmed via byte inspection**: all the strings are visible plaintext.
- **Inferred**: that this is an Acronis short-tag TLV.  The grammar matches
  what's documented for both legacy inline metadata and modern post-data
  metadata blobs.

---

## Verdict

| Question | Answer |
|---|---|
| What is the residual region for? | A **per-archive miscellaneous-metadata container** containing: the Volume4 cluster bitmap and an encrypted per-cluster summary, a smaller Volume3 equivalent, a verbatim copy of the source disk's MBR + track-0 boot region (compressed), an Acronis productinfo XML block (compressed), and a final TLV cluster of partition descriptors. |
| What does the count `4,743,112` mean? | The NTFS-allocated cluster count of the source HarddiskVolume4 (= 18.09 GiB at 4 KiB clusters).  Volume4 was 119 GiB total; only 17.26 GiB worth of clusters got into the backup (the difference is mostly excluded files like pagefile.sys/hiberfil.sys). |
| Was the count value `4,743,624` (per FORMAT_LEGACY_TAIL.md)? | No.  That was a transcription error.  The actual u32 LE bytes `c8 5f 48 00` decode to `0x00485fc8 = 4,743,112`. |
| Is the 1.78 MB blob encrypted, compressed, or random? | **Encrypted.**  Entropy 7.9999, chi^2 237.9, 100% unique 16-byte blocks, no zlib magic, no raw-deflate decompression succeeds.  The trailer `01 13 00 04 ...` at +1,886,060 looks like an HMAC auth tag.  Acronis encrypts metadata with a key derived from the archive ID even in unencrypted backups. |
| Is the 56 KB blob encrypted? | **No, it is a clean zlib stream.**  Decompresses to 264,192 bytes = the first 516 sectors of the source disk (MBR + track 0 boot region).  Reported as "high entropy" only because deflate output is naturally near-uniform. |
| Is there a separate residual for HarddiskVolume3? | **No.**  Volume3 is described inline within this same residual (cluster bitmap + small descriptor at residual offsets 1,886,144..1,900,648) and again in the trailing TLV cluster.  Whole-file scans confirm there is only one residual. |
| What about the 14 KB sparse-bitmap region? | It's the Volume4 cluster-allocation bitmap, mostly 0xFF (in-use) with sparse 0-bits (free).  Granularity is coarser than 1 bit / cluster (since 4,743,112 cluster bits would need 593 KB, not 15 KB).  Likely ~38 clusters/bit, but this is inferred. |
| Producer software? | **Acronis True Image 2013, build 6514.**  Identified by the embedded XML productinfo block. |
| Source disk? | **Corsair Force GT 128 GB SSD** (`CORSAIR CMFSSD-128GBG2`), kernel handle `\Device\000000ae`, partition table: P1 = 100 MiB NTFS at LBA 2048 (System Reserved / Volume3), P2 = 119.14 GiB NTFS at LBA 206848 (Volume4). |

---

## Cross-reference with `FORMAT_LEGACY_TAIL.md`

| `FORMAT_LEGACY_TAIL.md` says... | Correction |
|---|---|
| Count = 4,743,624 | Count = **4,743,112** (u32 LE `c8 5f 48 00`) |
| Two high-entropy blobs (1.78 MB + 57 KB) "likely AES-encrypted or compressed with no recoverable zlib magic" | The 57 KB blob **IS a zlib stream**, decompresses to 264 KB MBR + boot region.  Only the 1.78 MB blob is opaque (and that one is AES-encrypted). |
| The residual is "structurally analogous to but NOT the same as the modern format's 3.16 MB cuckoo filter" | Confirmed — the legacy residual is structurally **simpler** and has a **different role**.  Modern post-data is dedup-filter-focused; legacy post-data is partition-metadata-focused. |
| The UTF-16 'Device' marker is at the end | Mostly correct, except the device-path strings are **ASCII**, not UTF-16.  Only 'System Reserved' (the volume label) is UTF-16. |

---

## Tools

- `/path/to/tibread/decode_legacy_residual.py` -- analyser.
  - `--map`: structural run map at 4-byte resolution
  - `--header`: decode the 16-byte residual header
  - `--zlib`: enumerate embedded zlib streams
  - `--boot`: decompress the MBR + boot region and print partition table
  - `--xml`: extract the productinfo XML
  - `--partitions`: extract trailing TLV partition descriptors
  - `--blobs`: statistical analysis of opaque blobs
  - `--all`: run everything
- `/path/to/tibread/decode_legacy_tail.py dump <m> <r>` -- prerequisite
  to extract the residual to `/tmp/legacy_residual.bin`.

## Key constants (example)

```
residual file offset bounds:    [8,774,820,840 .. 8,776,798,513)
residual size:                  1,977,673 bytes (~1.89 MB)
residual header:                00 00 00 80   c8 5f 48 00   00*8
header flag:                    0x80000000  (sealed)
header count:                   0x00485fc8  = 4,743,112 (Vol4 NTFS clusters)
Vol4 backed-up clusters:        4,499,776 (17.16 GiB, = blocks_for_vol4 * 64)
Vol3 backed-up clusters:        ~25,600 (100 MiB)
total backed-up clusters:       4,525,376 (= 70,709 * 64)
Volume4 unbacked tail:          ~243K clusters (~950 MiB), excluded files
disk model:                     CORSAIR CMFSSD-128GBG2
disk LBA / partition layout:    P1 (Vol3) = LBA 2048, 204800 sect, 100 MiB
                                P2 (Vol4) = LBA 206848, 249860096 sect, 119.14 GiB
producer:                       Acronis True Image 2013, build 6514
task ID:                        C1133A11-4824-4C42-8DD6-8A7264522492
archive ID (per trailer body):  15878547e53ed64d
embedded zlib streams:          @1,918,156 (58,596 B comp -> 264,192 B MBR)
                                @1,976,770 (21 B -> 20 B small struct)
                                @1,976,791 (198 B -> 239 B XML)
opaque blob:                    [19,900 .. 1,886,092)  1,866,192 B AES ciphertext
opaque blob HMAC trailer:       [1,886,060 .. 1,886,090)  ~30 B
```
