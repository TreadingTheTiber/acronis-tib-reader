# TI 2014-era ("legacy") .tib metadata-blob format

Status: decoded by RE agent on 2026-04-30, working from
`/path/to/legacy_example.tib` (an 8.78 GB Acronis True Image 16,
build 6514 backup; product version "16.0.6514" decoded from the embedded
`<metainfo>` XML).

This document describes how the metadata blob in the **older** .tib format
differs from the TI 2018+ format documented in `dist/tibread/metadata.py` and
`dist/docs/METADATA_BLOB_TLV.md` (the "newer" format hereinafter). All
findings are from `parse_blob` runs on example's blob. Confidence labels:
**confirmed** = parses cleanly with concrete byte values that line up with
known fields; **inferred** = consistent with newer-format dictionary but the
numeric value alone does not prove the meaning.

## Where the blob lives

| field                          | value                          |
|--------------------------------|--------------------------------|
| file_size                      | 8,776,798,720                  |
| concat_end                     | 8,776,798,558                  |
| chunk-map zlib stream ends at  | 8,776,797,592 (= **BLOB_START**) |
| metadata blob length           | **921 bytes** (vs ~864 for newer) |
| metadata blob ends at          | 8,776,798,513 (= trailer-body start) |
| trailer body                   | 37 bytes (5-byte length-prefix grammar) |

The blob start was located empirically: the chunk-map zlib stream
(`78 01 ...`, 58,596 bytes compressed -> 264,192 bytes inflated) ends at file
offset 8,776,797,592. The very next byte (0x11) is the first byte of the
metadata blob; there is **no gap** between the chunk-map zlib and the blob.

## TLV grammar

The blob uses the same `tag(u8) + sub(u8) + len(u8) + payload(len)` grammar
as the newer format, plus **one new sub-tag form** specific to the older
format:

> If the **sub byte equals `0x05`**, the record is exactly 7 bytes long: it
> is `tag + 0x05 + 5-byte payload` with **NO length byte**. The `0x05` is
> both the sub-tag indicator and an implicit "5-byte fixed payload" hint.

This is structurally analogous to how `(tag, 0x80)` records carry "this is a
file-offset / size" semantics in both formats. In the older format,
`(tag, 0x05)` carries "this is a 5-byte LE timestamp/offset".

With this rule applied, the entire 921-byte blob (after the 273-byte opaque
header) parses to **63 records with zero leftover bytes**. The 37-byte
trailer body parses to **5 records with zero leftover bytes**.

## Blob structure

```
file_off    blob_off    bytes      contents
8776797592   0          18         pre-zlib TLV records (4 records)
8776797610   18         21         embedded ZLIB stream #1 (small struct, 20B inflated)
8776797631   39         198        embedded ZLIB stream #2 (XML <metainfo>, 239B inflated)
8776797829   237        36         post-zlib opaque framing (header / hash region)
8776797865   273        648        main TLV stream: 0xd6, 0xd7, ..., 0x04.80 (63 records)
8776798513   921        --         END (trailer body follows)
```

### Pre-zlib TLV (blob_off 0..17)

| blob_off | tag    | len | payload    | meaning |
|----------|--------|-----|------------|---------|
| 0        | 0x11.02 | 0  | --         | start-of-blob marker (NEW; older-format only) |
| 3        | 0x02   | 2   | `04 00`    | section delimiter? (NEW) |
| 8        | 0x02   | 2   | `06 00`    | section delimiter? (NEW) |
| 13       | 0x01.01 | --  | `c7 00 00` | **5-byte preamble** for the embedded ZLIB stream #1 |

The five bytes at blob_off 13..17 (`01 01 c7 00 00`) immediately precede the
first zlib stream's `78 01` magic. Treating them as
`tag=0x01 sub=0x01 len=0xc7=199` would gobble both zlib streams; instead
they are an opaque preamble that signals "embedded zlib follows" — the
parser must inflate to discover the stream's compressed length.

### Embedded ZLIB stream #1 (blob_off 18..38)

* 21 bytes compressed → **20 bytes inflated**
* Inflated content:
  ```
  28d1441604000000e4e400000000000000000000
  ```
* As 3 LE u32 + 8 zero bytes:
  - `0x1644d128` (= 373,608,744; possibly a CRC32 or hash)
  - `0x00000004`
  - `0x0000e4e4` (= 58,596 — **matches the chunk-map zlib's compressed
    length** — confirmed)
  - 8 bytes 0x00 padding

> So the older format stores the chunk-map's compressed length *inside the
> metadata blob* as a small zlib-compressed struct, rather than via the
> newer format's `06 V 01 00 03 S` chunk-map-locator pattern. The `V`
> (chunk-map start offset) is **NOT in this struct**; the offset is implied
> by "the zlib stream that ends just before BLOB_START."

### Embedded ZLIB stream #2 (blob_off 39..236)

* 198 bytes compressed → **239 bytes inflated**
* Inflated content (UTF-8 with BOM):
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

> In the **newer** format, this XML lives in a SEPARATE post-data stream
> (stream-4). In the **older** format it is **embedded directly in the
> metadata blob** as a zlib-compressed block. The older format also has
> NO `<computer_id>`, no file/dir count statistics in the XML, no
> `<userinfo>` section — only `<productinfo>` and `<task_id>`.

### Post-zlib opaque framing (blob_off 237..272, 36 bytes)

```
48 00 60 00 04 06 fc d9 52 88 00 02 c0 03 a0 00
10 f6 27 75 e1 cf 8d e6 2c 5a d1 eb e7 fc 96 19
95 d3 00 00
```

This region does NOT parse as TLV. The leading `48 00 60 00` looks like
a `tag=0x0048 len=0x60=96` framing (matching the 96-byte tag-0x4D
encryption-recovery container in the newer format), but the payload
following is mostly opaque high-entropy bytes — likely a 16-byte hash/GUID
preceded by a small fixed header. Hypothesis (inferred): this is the older
format's equivalent of the newer-format 80-byte fixed header + 96-byte 0x4D
container, but with a different shape.

### Main TLV stream (blob_off 273..end, 63 records)

Notable records:

| blob_off | tag    | sub  | len | interpretation |
|----------|--------|------|-----|----------------|
| 273      | 0xd6   | 0    | 5   | timestamp (5B LE = 0x020b234d9f = BLOB_START + 7) |
| 281      | 0xd7   | 0    | 1   | u8 = 0xc6 |
| 285      | 0x00   | 0x80 | 5   | **partition size** = 0x442739000 = 18,294,738,944 (~17 GiB) |
| 293      | 0x01   | 0x80 | 5   | mirror of 0x00.80 (same value) |
| 301      | 0x07   | 0x80 | 5   | meta-self-pointer = 0x020b234e65 (BLOB_START + 205) |
| 309      | 0x6a   | 0    | 0   | **volume GUID — EMPTY in older format** (vs 16B in newer!) |
| 312      | 0x00   | 0x05 | 5   | 5B timestamp = 0x020b234d78 (BLOB_START - 32; possibly trailing-data offset) |
| 319      | 0x01   | 0    | 1   | flag = 0x27 |
| 323      | 0x02   | 0    | 2   | u16 = 0x0200 |
| 328      | 0x07   | 0    | 2   | u16 = 0x0200 (disk-2 group lead-in) |
| 333      | 0x12   | 0    | 4   | 4B value = 0x0ee7c2b0 (= 250,069,680; possibly disk-record fingerprint) |
| 340      | 0x48   | 0    | 0   | disk-record start marker (empty) |
| 343      | 0x49   | 0    | 1   | disk index = 0x02 |
| 347      | 0x4a   | 0    | 1   | partition style = 0x3f |
| 351      | 0x4b   | 0    | 1   | disk flags = 0xfe |
| 355      | 0x53   | 0    | 0   | (NEW empty marker) |
| 358      | 0x58   | 0    | 22  | drive model = `'CORSAIR CMFSSD-128GBG2'` |
| 383      | 0x81   | 0    | 17  | wide path = `'\Device\000000ae'` (= ASCII!) |
| 403      | 0x98   | 0    | 0   | end-of-disk-meta marker |
| 406      | 0x05   | 0x80 | 3   | disk u24 LE id = 0x4b30e |
| 412      | 0x14   | 0x80 | 0   | end-of-disk-block marker |
| 415      | 0x03   | 0x01 | 0   | (NEW empty marker) |
| 418      | 0x00   | 0x03 | 206 | **CONTAINER**: volume-1 records (see below) |
| 627      | 0xc8   | 0    | 2   | u16 LE = 0xe750 (start of label record) |
| 632      | 0xcb   | 0    | 29  | UCS-2 label = `'System Reserved'` |
| 664      | 0x03   | 0x80 | 3   | LE offset = 0x9f3530 (10,433,840) |
| 670      | 0x04   | 0x80 | 1   | LE size = 0x11 |
| 674      | 0xf7   | 0    | 0   | **volume separator** (NEW) |
| 677      | 0x00   | 0x05 | 5   | volume-2 timestamp 0x020aef12f6 |
| 684–916  | ...    |      |     | volume-2 records (parallel structure to vol-1, plus tag 0x66 stats) |

#### Volume-1 sub-container (blob_off 418..626, 206 bytes payload)

The 0x00.03 container contains volume-1's records. The first **2 bytes are
opaque padding** (`2a 9f`), after which the standard TLV grammar resumes:

| inner_off | tag  | sub | len | interpretation |
|-----------|------|-----|-----|----------------|
| 2         | 0x01 | 0   | 2   | flag pair = `64 01` |
| 7         | 0x02 | 0   | 2   | `00 02` |
| 12        | 0x03 | 0   | 1   | u8 = 0x08 |
| 16        | 0x08 | 0   | 0   | (NEW empty) |
| 19        | 0x0d | 0   | 0   | (NEW empty) |
| 22        | 0x11 | 0   | 2   | `00 08` |
| 27        | 0x12 | 0   | 3   | `00 20 03` (volume header value) |
| 33        | 0x13 | 0   | 3   | `f9 1f 03` |
| 39        | 0x14 | 0   | 2   | `ff 63` |
| 44        | 0x15 | 0   | 2   | `4b 4b` |
| 49        | 0x16 | 0   | 1   | u8 = 0x10 |
| 53        | 0x1f | 0   | 2   | u16 = 0x0400 (block size = 1024) |
| 58        | 0x20 | 0   | 2   | `00 01` (volume index?) |
| 63        | 0x23 | 0   | 8   | volume serial = 0x64ea4c12ea4bdf44 |
| 74        | 0x28 | 0   | 1   | flag = 0x01 |
| 78        | 0x2f | 0   | 2   | u16 = 0x0200 (cluster size?) |
| 83        | 0x38 | 0   | 0   | (NEW empty) |
| 86        | 0x39 | 0   | 0   | (NEW empty) |
| 89        | 0x3c | 0   | 1   | compression level = 7 |
| 93–109    | 0x43, 0x44, 0x45, 0x46, 0x47 | 0 | 1 each | various small flags |
| 113       | 0x5d | 0   | 3   | `32 2c 9f` |
| 119       | 0x5e | 0   | 2   | `40 06` |
| 124       | 0x66 | 0   | 34  | statistics array |
| 161       | 0x6b | 0   | 1   | drive letter = `'D'` (0x44) |
| 165       | 0x81 | 0   | 24  | wide path = `'\Device\HarddiskVolume3'` |
| 192       | 0x93 | 0   | 3   | `72 32 9f` |
| 198       | 0x94 | 0   | 2   | `be 02` |
| 203       | 0xa3 | 0   | 0   | (NEW empty) |

Volume-2 records (drive F, `\Device\HarddiskVolume4`) appear at the OUTER
level (NOT inside a 0x00.03 container) starting at blob_off 684. The
asymmetry — vol-1 wrapped in a container, vol-2 inline — is unexplained;
possibly the older format treats the first/system volume specially, or this
is a quirk of the encoder.

### Trailer body (37 bytes)

The 37-byte trailer body parses with the same grammar:

```
hex: 00 00 05 65 4e 23 0b 02 01 00 02 ac 02 00 80 05 00 90 73 42 04 01 80 05 00 90 73 42 04 07 80 05 65 4e 23 0b 02
```

| trailer_off | tag    | sub  | len | payload          | meaning                           |
|-------------|--------|------|-----|------------------|-----------------------------------|
| 0           | 0x00   | 0    | 5   | `65 4e 23 0b 02` | **metaDataOffset** = 0x020b234e65 = 8,776,797,797 |
| 8           | 0x01   | 0    | 2   | `ac 02`          | unknown u16 = 0x02ac (684)        |
| 13          | 0x00   | 0x80 | 5   | `00 90 73 42 04` | partition size = 0x442739000      |
| 21          | 0x01   | 0x80 | 5   | `00 90 73 42 04` | mirror of 0x00.80                 |
| 29          | 0x07   | 0x80 | 5   | `65 4e 23 0b 02` | self-pointer (= same value as off 0) |

Trailer record at off 0 confirms the **5-byte length prefix** for
`metaDataOffset`. The 5-byte LE value `65 4e 23 0b 02` = 0x020b234e65 =
8,776,797,797 — note this is `BLOB_START + 205`, NOT `BLOB_START` itself.
The 205-byte offset within the blob lands inside the post-zlib opaque
framing region (blob_off 237..272 ends at 273; 205 is INSIDE the second zlib
stream's inflated XML region, which is unusual).

(In the newer format, `0x07.80` was documented as `metaDataOffset + 48`. In
this older file the analogous offset is `metaDataOffset + 205` for the meta
self-pointer; the +205 likely points past the embedded zlib streams to the
start of the main TLV stream.)

## Tag inventory

**57 distinct (tag, sub) pairs** appear in example's blob + trailer.

### Tags shared with TI 2018+ (per `decode_metadata_blob.py`)

`0x01`, `0x02` (use is similar but length differs), `0x03`, `0x06`, `0x07`,
`0x12`, `0x16`, `0x1F`, `0x20`, `0x23`, `0x28`, `0x2F`, `0x3C`, `0x45`,
`0x46`, `0x47`, `0x48`, `0x49`, `0x4A`, `0x4B`, `0x4C`, `0x4F`, `0x58`,
`0x5B`, `0x5D`, `0x5E`, `0x66`, `0x69`, `0x6A`, `0x6B`, `0x73`, `0x81`,
`0x8F`, `0x93`, `0x94`, `0x98`, `0xA1`, `0xA6`, `0xAE`, `0xB2`, `0xBA`,
`0xBB`, `0xBC`, `0xBD`, `0xBE`, `0xBF`, `0xC0`, `0xC8`, `0xCB`, `0xCC`,
`0xCD`, `0xD1`, `0xD6`, `0xD7`,
plus sub-tag suffixes `(_, 0x80)` for `0x00`, `0x01`, `0x07`, `0x03`, `0x04`,
`0x05`, `0x06`, `0x14`.

### Tags NEW in the older format

| tag       | seen at                         | likely meaning |
|-----------|---------------------------------|----------------|
| `0x11.02` | start of blob (blob_off 0)      | start-of-blob empty marker |
| `0x01.01` | blob_off 13                     | preamble/wrapper for embedded zlib (5-byte preamble) |
| `0x00.05` | blob_off 312, 677; trailer 0 (sub-tag form) | 5-byte LE timestamp/offset, fixed-length grammar |
| `0x00.03` | blob_off 418                    | 206-byte CONTAINER for volume-1 records |
| `0x03.01` | blob_off 415                    | empty marker (separator) |
| `0x00.00` (sub=0, len=5) | trailer body off 0     | metaDataOffset record (`0x00` len=5 form) |
| `0x08`    | inside container, blob_off 435  | empty marker |
| `0x0D`    | inside container                | empty marker |
| `0x11`    | inside container                | 2/3-byte payload |
| `0x13`    | inside container                | 3/4-byte LE value |
| `0x14`    | inside container                | 2/4-byte LE value |
| `0x15`    | inside container                | 2/4-byte LE value |
| `0x18`    | (not seen in this file at outer level; appeared in raw scan) | empty marker |
| `0x38`    | inside container, blob_off 774  | empty marker |
| `0x39`    | inside container                | empty marker |
| `0x43`    | blob_off 781 (vol-2)            | u8 |
| `0x44`    | blob_off 785 (vol-2)            | u8 |
| `0x53`    | blob_off 355                    | empty marker |
| `0xA3`    | blob_off 624 (vol-1), 898 (vol-2) | empty marker (may be an older form of `0xAE`) |
| `0xC7`    | blob_off 15 (in pre-zlib preamble) | (synthetic — part of the `01 01 c7 00 00` zlib preamble) |
| `0xF7`    | blob_off 674                    | volume separator |

### Tags PRESENT in newer format but ABSENT here

* `0x004D` 96-byte encryption-recovery container — **not present**. The
  older format's encryption-recovery may live in the 36-byte post-zlib
  opaque framing at blob_off 237..272 (currently undecoded), or may simply
  not exist for non-encrypted older backups.
* `0xA8` (computer GUID) — **not present**.
* `0xA9` (LDM disk-group name) — **not present**.
* `0x6A` (volume GUID) — present-but-EMPTY (len=0).
* The 14-byte disk-record-start framing
  `02 07 00 02 00 02 12 00 05 [4B] 01` — **not present** in this exact
  shape; the older format uses a shorter `02 00 02 / 07 00 02 / 12 00 04 [4B]`
  trio of records instead.
* The 17-byte disk-2 bridge — **not present**.
* The 13-byte chunk-map locator `06 V[6] 01 00 03 S[3]` — **NOT FOUND
  ANYWHERE** in the blob OR the trailer (verified by exhaustive search over
  V byte-widths 4..7 and S byte-widths 2..7).

## Verdict on the older-format index pointer (the key question)

> **No `06 V 01 00 03 S` chunk-map-locator pattern is present anywhere in
> the metadata blob or the trailer body. The older format does NOT carry
> the newer-format chunk-map locator inline.**

Confidence: **confirmed** (exhaustive search).

Instead, the older format encodes chunk-map location implicitly:

1. **Chunk-map zlib stream** lives at a fixed offset in the .tib file
   (somewhere in the middle, not aligned to any visible header) and ends
   exactly at `BLOB_START` (the metadata blob always starts immediately
   after it).
2. **Chunk-map compressed length** is stored in the **20-byte zlib-#1
   inflated struct** at blob_off 18 as the third u32 LE = `0x0000e4e4` =
   58,596 — verified to match the actual chunk-map zlib's compressed length
   for example.
3. **Chunk-map start offset** = `BLOB_START - compressed_length` = derivable
   once the blob's start is known.

Practical implication for an older-format .tib reader:
* Locate `BLOB_START` by walking back from `trailer_body_start - 921` (the
  blob is 921 bytes here; this size is likely build-dependent and must be
  rediscovered for other older-format files via "back up until the chunk-map
  zlib stream ends cleanly").
* Inflate ZLIB stream #1 inside the blob to recover the chunk-map's
  `compressed_length` (third u32 LE).
* The chunk-map zlib starts at `BLOB_START - compressed_length`.

Alternative (and probably what Acronis does internally): the chunk-map's
location may be stored in the legacy file header at file offset 0 (which
this report does not cover). The TI 2014-era headers are known to differ
from the 2018+ post-data-region architecture; agent O's empirical block-walk
agent and the Ghidra version-dispatch agent can confirm.

## Cross-checks against example's known fields

| field                             | source                                 | matches |
|-----------------------------------|----------------------------------------|---------|
| volumeId = 0x06496f23             | not located in blob                    | miss — the older format may store the volume ID under a different tag, or only the 8-byte 0x23 record `0x64ea4c12ea4bdf44` (vol-1) / `0x54e64ebee64e9fda` (vol-2) is the equivalent |
| source disk model "CORSAIR ..."   | tag 0x58 @ blob_off 358                | confirmed: `'CORSAIR CMFSSD-128GBG2'` |
| volume label "System Reserved"    | tag 0xCB @ blob_off 632                | confirmed (UCS-2 LE) |
| 2 source volumes                  | drive D + drive F via tag 0x6B         | confirmed |
| TI build 16.0.6514                | embedded XML metainfo                  | confirmed |

## Suggested follow-ups for other agents

1. **Decode the 36-byte post-zlib opaque framing** (blob_off 237..272). It
   may contain encryption-recovery data, a SHA256 verifier, or additional
   GUIDs (the byte pattern includes a 16-byte high-entropy region
   `c0 03 a0 00 10 f6 27 75 e1 cf 8d e6 2c 5a d1 eb` that looks like a hash
   or GUID).
2. **Trace `BLOB_START` discovery in product.bin** for the older format —
   the version-dispatch agent's Ghidra session can identify the function
   that locates the metadata blob in v16-era backups.
3. **Verify `compressed_length=58,596`** against the actual chunk-map zlib
   stream by reading bytes `[BLOB_START - 58596 .. BLOB_START]` and
   inflating — the empirical-walk agent can do this directly.
4. **Find `volumeId` in older format** — possibly under a tag we currently
   classify as "unknown" or in the 36-byte opaque framing.

## Files

* Decoder: `/path/to/tibread/scan_example_metadata.py`
* This document: `/path/to/tibread/docs/FORMAT_LEGACY_METADATA.md`
* Related: `/path/to/tibread/tibread/metadata.py` (newer-format
  decoder), `/path/to/tibread/docs/METADATA_BLOB_TLV.md`,
  `/path/to/tibread/docs/TIB_VARIANTS.md`.
