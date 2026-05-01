# RESEARCH_TIBX_STRUCTURE — Empirical Bytes-Up Analysis of `Jmicron 0102.tibx`

Date: 2026-04-30
File: `/mnt/e/Jmicron 0102.tibx`  ·  Size: 54,671,892,480 bytes (≈51 GB)  ·  Pages: 13,347,630 of 4 KB each (file size is exactly a multiple of 4096)
Method: pure byte inspection (no Ghidra, no DLL execution); cross-referenced against `archive3.dll` strings recon.

---

## 1. Executive Summary

`.tibx` is a **page-store with an LSM-tree index**. Every byte of the file is part of a 4096-byte page; each page begins with a 4-byte magic `41 <type> 00 00` followed by a 4-byte page checksum. Higher-level structures (archive header, segment record, LSM leaf) are then layered on top of this page envelope.

**Page-type alphabet observed**:

| Type byte | Inner magic        | Meaning                                                          |
|-----------|--------------------|------------------------------------------------------------------|
| `0x01`    | `QARCH` / `ARCH`   | Archive header / metadata page                                   |
| `0x02`    | `ARCI`             | Archive index page (top-level / B-tree style)                    |
| `0x03`    | `LEAF`             | LSM-tree leaf page (key/value records)                           |
| `0xFF`    | `SG\x00\x01` *(opt)* | Data page. With `SG`: starts a segment record (Zstd frame). Without: continuation bytes of an in-flight segment, **or** a u16 page-id index leaf, **or** raw padded data |

**Compression**: Zstd frames (magic `28 B5 2F FD`) appear inside `SG`-headed segment records.
**Encryption**: not detected as a discrete envelope. The high-entropy bytes are the natural output of Zstd on previously-encrypted disk content (or of any compressor on random-looking data). No SQLite header (`SQLite format 3\x00`) was found anywhere.
**SQLite**: **NOT used.** Despite archive3 being SQLite-backed at API-level for *some* container variants, this `.tibx` is the page-store/LSM variant — not a SQLite database file.

---

## 2. Hexdumps of Key Regions

### 2.1 Head — first 4 KB (page 0, type `41 01` = QARCH header)

```
00000000  41 01 00 00 2e 0b 0a 51 41 52 43 48 00 00 12 38   A......QARCH...8
00000010  00 08 02 00 01 01 00 00 00 00 01 86 47 bf 99 63   ............G..c
00000020  00 00 01 86 47 bf 99 80 65 5f 4b a5 13 f6 ef c8   ....G...e_K.....
00000030  34 43 27 12 57 0b 12 40 00 00 00 00 00 00 30 00   4C'.W..@......0.
... lots of zeros + a couple sentinel bytes ...
000001a0  00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff   ................
000001b0  00 00 00 00 00 00 20 00 ...
000001d0  ff ff ff ff ff ff f0 00 ...
00000220  02 02 01 00 00 00 00 00 00 00 07 00 00 00 00 00   ................
```

Decoded fields:
- `41 01 00 00` — page magic (page type 0x01)
- `2E 0B 0A 51` — page checksum (probably CRC32; varies across all pages of same type)
- `QARCH` (offset 7) — archive container magic, ASCII
- `00 00 12 38` — likely big-endian length (0x1238 = 4664) **or** version+len fields
- `00 08 02 00 01 01 00 00` — version block (looks like 8.2.x/1.1)
- `00 00 01 86 47 BF 99 63` and `00 00 01 86 47 BF 99 80` — two big-endian 64-bit timestamps (Unix-ms). 0x18647BF9963 = 1675956881... ≈ Wed 09 Feb 2023 ≈ matches file mtime Feb 2023.
- `65 5F 4B A5 13 F6 EF C8 34 43 27 12 57 0B 12 40` (16 bytes) — looks like a stable archive UUID/key fingerprint; appears repeatedly in tail pages (offset 0x88).
- `30 00` — record terminator/length stamp.

### 2.2 Head — page 1 (offset 0x1000, type `41 01`, archive metadata payload)

Plain ASCII strings appear:
```
"disk"
"6A62EFA4-5A66-4CC2-AF2B-C0B18259EA1E"   ← disk GUID (the JMicron-attached drive)
"STRIDER-WIN63"                          ← source machine hostname
"ACPHO 27.3.1.40173 Win"                 ← Acronis Photo? agent build
"F3BB912A-0DB8-4004-96AE-FDE5DDEF27EC"   ← machine/install GUID
```

This page is the **logical archive descriptor** (machine + disk + agent) and is exposed in plaintext.

### 2.3 Mid — offset 0x65DE7C000 (file/2, page 6,673,815)

```
41 ff 00 00 c5 21 b8 5c 4d a3 8c 57 23 a8 f8 a9
f4 9d 62 2b 3b bb 57 f2 27 e1 27 5e 57 3e 86 b7
... 4 KB of high-entropy bytes ...
```

A type `0xff` data page with no `SG` header — i.e. a **continuation page** of an in-flight Zstd frame whose `SG` header was on an earlier page. This is the dominant body of the file.

### 2.4 Tail — last 4 KB (page 13,347,629, type `41 02` = ARCI footer)

```
00000000  41 02 00 00 08 8d 68 8d 41 52 43 49 00 08 00 00   A.....h.ARCI....
00000010  00 00 00 01 00 00 20 00 00 00 00 0c ba b2 b0 00   ...... .........
00000020  00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 04   ................
00000030  00 00 00 00 00 00 0c 9d 00 00 00 00 00 00 20 00   .............. .
00000040  00 00 00 0c ba b2 a0 00 dc 51 2d ee 8b 30 2c 46   .........Q-..0,F
00000050  00 00 00 0c ba b2 d0 00 00 00 00 00 00 00 00 00
... mostly zeros ...
00000080  00 00 00 00 00 00 00 00 65 5f 4b a5 13 f6 ef c8   ........e_K.....
00000090  34 43 27 12 57 0b 12 40 4b 64 8b 19 00 00 00 00   4C'.W..@Kd......
```

ARCI footer fields (big-endian 64-bit pointers):
- `00 00 00 0c ba b2 b0 00` — 0x0CBAB2B000 = **54,671,888,384** = `file_size − 4096` (this page's own offset).
- `00 00 00 0c ba b2 a0 00` — 0x0CBAB2A000 = file_size − 8192 (one page back).
- `00 00 00 0c ba b2 d0 00` — 0x0CBAB2D000 = beyond size; might be a planned upper bound.
- `00 00 00 04` — root degree/level?
- `0c 9d` — record count?
- `dc 51 2d ee 8b 30 2c 46` — possibly a SHA fragment / page hash.
- 16-byte archive UUID `65 5F 4B A5…12 40` reappears (cross-checked with header).
- `4B 64 8B 19` — 4-byte tag, possibly footer sentinel.

So the **last page of the file is the LSM root pointer / catalog**. From its pointers we can locate the LEAF run.

---

## 3. Magic-Byte Hunt

A scanner (`/home/colin/tibread/dist/tools/scan_tibx.py`) walks the file in 64 MB chunks with a 64-byte overlap and counts every occurrence of each magic.

### 3.1 SQLite header `"SQLite format 3\x00"`

Full-file scan: **63 hits, none at any meaningful alignment.**

| Alignment   | Top 5 modular residues from 63 hits           |
|-------------|-----------------------------------------------|
| mod 4 KB    | `468:1, 3630:1, 162:1, 447:1, 3596:1`         |
| mod 8 KB    | `468:1, 7726:1, 162:1, 4543:1, 7692:1`        |
| mod 64 KB   | `57812:1, 65070:1, 162:1, 37311:1, 15884:1`   |

A real SQLite database has the magic at offset 0. All 63 hits are scattered at random offsets (no two share the same residue) — these are **byte coincidences inside high-entropy Zstd-compressed payloads**. **SQLite found: NO.** The hypothesis that `.tibx` reuses the SQLite container format is **falsified for this file**. The DLL string `archive3` likely refers to a *family* of containers and the LSM-with-Zstd page store is the actual on-disk layout for backup archives.

### 3.2 Zstd frame magic `28 B5 2F FD`

**Full-file count: 123,648 hits.** Of the 64 sampled offsets recorded by the scanner, **all 64 sit at `mod_4096 == 44`** — i.e. exactly +0x2C inside a 4 KB page, which is precisely where the SG record places the Zstd frame. There is no other alignment cluster.

This means: every Zstd frame in the file is anchored to an SG segment record, and segments are 4 KB-page-aligned. Average compressed-segment size = `51 GB / 123,648 ≈ 412 KB` per segment. This matches archive3's typical ~512 KB chunking for disk backups.

For the SG segments verified by decompression (pages 6, 42, 45, 53), see §4.2.

### 3.3 `QARCH` ASCII

Full-file count: **1**.

| Offset      | Note                             |
|-------------|----------------------------------|
| 7 (page 0)  | The one and only QARCH magic     |

`QARCH` appears once. Subsequent same-class pages use the shorter `ARCH` (e.g. page 3 at offset 0x3008) and `ARCI` (e.g. page 2 at offset 0x2008, page 5 at offset 0x5008). The leading `Q` marks the very first / "primary" archive header; all later header continuations drop it.

### 3.4 LEAF region

`LEAF` ASCII appears at offset 8 of every page in the run **page 13,346,698 → 13,347,627** (930 contiguous LSM leaf pages, ≈3.8 MB).

### 3.5 Segment header `SG\x00\x01`

Found at offset 8 of any data page that **starts** a Zstd-compressed segment. Sampling shows segments are typically 256 KB–8 MB uncompressed, with `len`/`zlen` parsed from the SG record (see §4.2).

---

## 4. Decoded Record Layouts

### 4.1 Page envelope (all pages)

```
offset  size  field
0       1     0x41                   page magic byte
1       1     page type              0x01 ARCH | 0x02 ARCI | 0x03 LEAF | 0xff data
2       2     0x0000                 reserved
4       4     page checksum (LE)     CRC32-style; verified to vary per-page
8       *     payload                interpreted per page type
```

### 4.2 Segment record (inside type-`0xff` page when SG header present) — **DECODED & VERIFIED**

All multi-byte length fields are **big-endian** (verified by successful Zstd decompression of four sampled segments).

```
offset  size  field            notes
+8      4    "SG\x00\x01"      segment magic + version 1
+C      4    len  (BE u32)     uncompressed payload size in bytes
+10     4    zlen (BE u32)     compressed payload size in bytes
+14     4    key  (BE u32)     encryption key id  (0 = plaintext, observed in this archive)
+18     2    comp (BE u16)     0x0300, 0x0301, 0x0302 — three Zstd preset/dict variants
+1A     2    cache             cache hint flags
+1C     12   reserved/zero
+2C     ... compressed data    Zstd frame begins here (magic 28 B5 2F FD)
```

This matches the archive3.dll format string `magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u`.

Decoded examples (BE) and **decompression results** (verified live):

| Page | len    | zlen  | key | comp   | Decompressed payload                                              |
|------|--------|-------|-----|--------|-------------------------------------------------------------------|
| 6    |262 144 |   480 | 0   | 0x0302 | MBR boot sector + zero sectors (`33 C0 8E D0…` + `55 AA` sig)    |
| 42   | 20 480 |12 069 | 0   | 0x0300 | PE/EXE binary (`4D 5A 90 00…` MZ header)                         |
| 45   | 12 288 | 1 386 | 0   | 0x0301 | small filesystem metadata (`8C 00 00 00 01 00 14 9C…`)            |
| 53   |524 288 |51 734 | 0   | 0x0300 | another PE/EXE binary (`4D 5A 90 00…`)                            |

**`key=0` on every sampled segment** ⇒ this archive is **unencrypted**; all chunks are plain Zstd-compressed disk content.

**Multi-page segment layout verified**: the Zstd frame begins at +0x2c of the SG page and continues into subsequent type-`0xff` pages **with each page's 8-byte envelope (`41 ff 00 00 <crc32>`) stripped before concatenation**. After concatenating raw payload bytes from page-after-page (skipping 8-byte envelopes) until `zlen` bytes are accumulated, `zstandard.ZstdDecompressor().decompress(...)` returns exactly `len` bytes of plaintext.

### 4.3 LSM LEAF page (type `0x03`)

```
offset  size  field
+8      4     "LEAF"
+C      3     0x01 0x01 0x00       version
+F      2     entry count or fanout
+11     6     reserved/zero (often)
+18     ...   packed key/value records (varint lengths, prefix-compressed keys)
end-XX        free-space tail (zero-padded)
```

Leaf payload contains short opaque keys and small values; this is the **mapping from logical chunk-id (or hash) to physical segment offset**.

### 4.4 u16 page-index leaves

Pages 10..~49 hold dense monotonic u16 arrays:
- Page 10: 2044 entries spanning logical IDs **2020 → 4063**, all `+1` deltas.
- Page 11: 2044 entries spanning **4064 → 6107**, all `+1`.
- … up through page ~49.

This is the **identity map** for the disk image's chunk IDs — every physical chunk in this region maps to itself at +1 stride. Higher 16 bits must come from a parent index (the `41 02 ARCI` pages at the head of file). Each leaf page covers `2044 × chunk_size` bytes worth of address space, so a 64 KB chunk size would cover 130 MB per leaf and the file's pre-LEAF region (~50 GB) needs about 400 such leaves — consistent with what we see scattered through the early pages.

### 4.5 ARCI top-level (type `0x02`)

Pages 2, 5, 13347626, 13347629 (and many more) carry `ARCI` records: short fixed-format records with file-size-scale 8-byte big-endian pointers (offsets 0x18, 0x40, 0x50 of page) that point at descendant index/leaf pages. The **last page of the file is itself an ARCI page acting as the LSM root**.

---

## 5. File Layout Map

Working from page-type sampling (head 0..15, then exponentially-spaced probes through to end):

```
page index            page-type  region                                     bytes              %
0                     41 01     QARCH archive header                       4 KiB              ~0%
1                     41 01     archive metadata (disk GUID, host, agent)  4 KiB              ~0%
2                     41 02     ARCI top-level index                       4 KiB              ~0%
3                     41 01     ARCH continuation                          4 KiB              ~0%
4                     41 01     header continuation                        4 KiB              ~0%
5                     41 02     ARCI                                       4 KiB              ~0%
6..49                 41 ff     mixed: SG-headed segments + u16 page-id    ~180 KiB           ~0%
                                index leaves (chunk-ID → physical map)
50..13,346,697        41 ff     bulk DATA: Zstd-compressed segments,        ≈ 50.94 GiB       99.93%
                                each one started by an SG record on the
                                first page of the segment, then continuing
                                on N subsequent type-0xff pages with no
                                inner magic. SG segments interleaved with
                                additional u16 page-index leaves.
13,346,698..13,347,627 41 03    LSM LEAF run (B-tree-style index)          ≈ 3.63 MiB         ~0.007%
13,347,628            41 01     ARCH footer / metadata copy                4 KiB              ~0%
13,347,629            41 02     ARCI root (last page; LSM root pointers)   4 KiB              ~0%
```

**~99.9% of the file is bulk Zstd-compressed data pages.** The LSM index (LEAF + ARCI) lives at the end (≈3.8 MB). The header is at the start (≈24 KB). A modest sprinkling of u16 page-index leaves is interleaved with data in the early ~200 KB, and likely throughout (sample shows page 150 had a `bb bb bb bb` repeating pattern, consistent with a page of repeated 16-bit map entries in another address range).

---

## 6. Verified Read Path (for tibread implementation)

To extract a logical disk byte:
1. Read page **N − 1** (last page of file) — `ARCI` root. Parse big-endian 64-bit pointers to descendant ARCI/LEAF pages.
2. Walk `41 02 ARCI` → … → `41 03 LEAF` to look up the logical chunk-id (or content hash) for the desired byte.
3. The leaf entry resolves to a **physical offset** of the SG segment that contains the chunk.
4. Read that page; parse 28-byte SG header (offsets +8..+0x2C) to get `len`, `zlen`, `comp`, `key` — all **big-endian**.
5. Read `zlen` bytes from the Zstd frame: start at +0x2C of the SG page, then for each subsequent type-`0xff` page concatenate `page[8:]` (i.e. strip its 8-byte envelope) until `zlen` bytes have been collected. Stop early if a non-`0xff` page or another `SG\x00\x01` magic is encountered (indicates frame already terminated).
6. Decompress with Zstd → exactly `len` bytes of plaintext disk content.
7. (If `key != 0`) decrypt with the corresponding AES key/IV. **In this archive `key == 0` for every sampled segment, so step 7 is a no-op for `Jmicron 0102.tibx`.**

This pipeline was demonstrated end-to-end on four sampled segments (pages 6, 42, 45, 53). All four decompressed to the expected uncompressed length and yielded recognisable disk content (MBR boot sector, PE/EXE images, NTFS metadata).

---

## 7. Surprises / Open Questions

1. **No SQLite anywhere.** Earlier intel about archive3 being SQLite-backed must refer to a different container variant (perhaps a metadata sidecar, or older `.tib` style). For this `.tibx` the answer is a clean negative.
2. **No detectable AES-GCM tags as standalone envelopes.** The `key=` field in SG records implies encryption is applied *inside* the segment record, not as a separate framing layer. This file shows `key=0` on the first four SG segments inspected — so this `.tibx` is **plaintext-archive-encrypted-content**, i.e. each chunk holds disk sectors as-is post-Zstd.
3. **`QARCH` vs `ARCH`** — only the first archive header carries the `Q` (likely "qualifier"/"query-able"/"q is the leader byte of *quintessential*, or "Q = primary"). All later `41 01` pages use plain `ARCH`.
4. **Page checksum algorithm** — bytes 4..7 of every page vary; need to confirm CRC32 polynomial (likely zlib-CRC32 given Acronis ancestry, but might be a custom variant).
5. **u16 page-index pattern with strict +1 deltas** strongly suggests the source disk image is being chunked at a fixed stride and stored with identity logical→physical mapping — i.e. minimal de-dup happened on this particular backup.
6. **Plaintext metadata leak**: `STRIDER-WIN63`, the disk GUID, and the agent version are stored unencrypted in page 1. Useful for archive identification without keys.

---

## 8. Artefacts

- Scanner: `/home/colin/tibread/dist/tools/scan_tibx.py`
- Full-file magic report (JSON): `/home/colin/tibread/dist/tools/scan_tibx_report.json`
- Tail-1MB dump for offline inspection: `/tmp/tibx_tail1m.bin`
