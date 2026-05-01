# Archive3 Page Verification (`ar_page_verify`)

This document describes the on-disk page validation algorithm and the
single-bit error correction (FEC) used for archive3 pages.

Source: decompilation of `archive3.dll`:
- `ar_page_verify`        @ `0x180056cc0`  (export #110)
- `FUN_180056d50`         (inner CRC + FEC routine, called from above)
- `ar_page_fill_header`   @ `0x1800562d0`  (writer, export #100)
- `ar_page_parse_header`  @ `0x180056870`  (reader wrapper, export #103)

The CRC32 computation itself is provided by libpcs imports
`pcs_crc32(buf, len)` and `pcs_crc32up(seed, buf, len)`.

## Page layout

Every persistent archive3 page is exactly **4096 (0x1000) bytes** and
starts with an 8-byte preamble:

```
+0x00  uint8   page_magic[0]   = 'A'   (= 0x41)
+0x01  uint8   page_type       page-type tag (must be non-zero)
+0x02  uint16  reserved        = 0x0000
+0x04  uint32  crc32           big-endian CRC32 of the whole 4096 bytes,
                                computed with this field zero-filled
+0x08  uint8[0xff8] body       page-type-specific contents (4088 bytes)
```

The "page magic" is therefore `'A'  <type>  0x00 0x00`. The fixed-header
record's `'ARCH'` magic and the change-index `'ARCI'` magic are then
just specific values of `<type>` (`'R' 0x00 0x00` and `'I' 0x00 0x00`
respectively). The high byte of the page-magic word is always `'A'`,
the second byte selects the kind of body, and the upper two bytes are
always zero.

### Magic check (verifier entry)

`ar_page_verify` accepts the page if and only if:
```
buf[0] == 'A'  &&  buf[1] != 0  &&  buf[2] == 0
```
(Note: the third byte at `buf[3]` is *not* checked by `ar_page_verify`,
even though the writer always sets the full `uint16` at `+2` to zero.)

If this check fails, `ar_page_verify` returns `-0x139f` (= `0xffffec61`,
"bad magic"). If `param_4` (the "verify CRC" flag) is zero the function
returns `0` immediately, bypassing the CRC stage; otherwise it dispatches
to `FUN_180056d50` for the CRC + FEC pass.

## CRC variant

The CRC is computed by libpcs `pcs_crc32`. From the call shape
(seed-less single call over a 4 KB block, plus the incremental
`pcs_crc32up(seed, buf, len)` helper used during FEC), this is the
standard reflected **CRC-32 / IEEE 802.3** (zlib `crc32`,
polynomial `0xEDB88320` as reflected, init `0xFFFFFFFF`,
final XOR `0xFFFFFFFF`). It is **not** CRC32C (Castagnoli) — the
binary contains no CRC32C instructions or precomputed CRC32C tables and
the libpcs symbol name is the canonical `pcs_crc32` (= IEEE).

The CRC is stored on disk in **big-endian** byte order. Both the
writer (`ar_page_fill_header`) and the verifier byte-swap the 32-bit
field on read/write:

```c
// Writer:
*(uint32_t*)(buf + 4) = 0;
uint32_t c = pcs_crc32(buf, 0x1000);
*(uint32_t*)(buf + 4) = bswap32(c);          // store BE

// Verifier:
uint32_t stored = bswap32(*(uint32_t*)(buf + 4));
*(uint32_t*)(buf + 4) = 0;                   // zero before recompute
uint32_t computed = pcs_crc32(buf, 0x1000);
if (computed == stored) ok;
```

The CRC is computed over the **entire 4096-byte page** with the 4-byte
CRC field itself zero-filled. No other regions are excluded.

## Single-bit error correction (FEC)

If the CRC mismatches, `FUN_180056d50` attempts to correct a single
bit-flip anywhere in the 4096-byte page. There is **no separate FEC
field on disk** — correction is performed purely by exhaustive search,
exploiting the linearity of CRC32.

### Two cases

**Case 1: bit flip in the stored CRC field itself.**
If `(computed ^ stored) & ((computed ^ stored) - 1) == 0`, then
`computed XOR stored` has exactly one bit set, meaning the stored CRC
differs from the correct CRC by a single bit. The page payload is
therefore intact; only the on-disk CRC field has a bit error. The
function logs:
```
pg at %llu bit flip in crc: read %08x should be %08x
```
overwrites `buf+4` with the correct CRC (BE), and returns `1`
(corrected).

**Case 2: bit flip anywhere in the page body.**
The verifier walks the page in **8-byte words** (512 of them across
the 4 KB page). For each word index `w` (0..511) and each bit `b`
(0..63):

1. Compute `flipped_word = original_word XOR (1ULL << b)`.
2. Compute `crc' = pcs_crc32up(crc_of_words_before_w, &flipped_word, 8)`,
   then continue with `pcs_crc32up(crc', &word[w+1], (511 - w) * 8)`.
3. If `crc'` equals the stored CRC, this single-bit flip explains the
   error. Apply it, log
   `pg at %llu fix %d->%d bit %d in byte #%x`,
   restore the stored CRC field, and return `1`.

The "prefix CRC up to word `w`" is maintained incrementally between
outer-loop iterations: after exhausting all 64 bit positions of word
`w` without a match, the verifier folds the original word `w` into the
running prefix CRC via
`prefix' = pcs_crc32up(prefix, &original_word, 8)` and advances.

If no single-bit flip in any of the 512 words yields a matching CRC,
the verifier returns `-0x139f` (`0xffffec61`).

### Algorithm complexity

- **Best case (CRC matches):** one full-page CRC32 pass.
- **Bit-flip-in-CRC case:** one CRC32 pass + one popcount-style check.
- **Bit-flip-in-body case:** up to 512 × 64 = **32768 candidate**
  evaluations. Each candidate folds 8 modified bytes plus the
  remaining tail, so the total work is bounded by ~32 K incremental
  CRC32 invocations. The decompiled implementation is naive (no
  table-driven single-bit-flip XOR shortcut), but the algorithm is
  algebraically equivalent to one and could be optimised offline if
  needed.

The log format
```
pg at %llu fix %d->%d bit %d in byte #%x
```
prints, in order: the page offset (file-byte), the previous bit value,
the new bit value, the bit index within the byte, and the byte offset
within the page (calculated as `8*w + (b>>3)`).

## Decompiled core (truncated)

```c
// 0x180056d50   pcs_crc32 / single-bit FEC
uint32_t stored_be = *(uint32_t*)(buf + 4);
uint32_t stored    = bswap32(stored_be);
*(uint32_t*)(buf + 4) = 0;
uint32_t crc = pcs_crc32(buf, 0x1000);
if (crc == stored) {
    *(uint32_t*)(buf + 4) = stored_be;
    return 0;
}
uint32_t diff = crc ^ stored;
if ((diff & (diff - 1)) == 0) {            // single bit in CRC
    pcs_log(0, "pg at %llu bit flip in crc: read %08x should be %08x",
            page_off, stored, crc);
    *(uint32_t*)(buf + 4) = bswap32(crc);
    return 1;
}
uint32_t prefix = 0;
for (int w = 0; w < 512; w++) {
    uint64_t orig = ((uint64_t*)buf)[w];
    for (int b = 0; b < 64; b++) {
        uint64_t flipped = orig ^ (1ULL << b);
        uint32_t cand = pcs_crc32up(prefix, &flipped, 8);
        if (w != 511)
            cand = pcs_crc32up(cand, buf + 8*(w+1), 8 * (511 - w));
        if (cand == stored) {
            pcs_log(0, "pg at %llu fix %d->%d bit %d in byte #%x",
                    page_off, !!(orig & (1ULL<<b)), !(orig & (1ULL<<b)),
                    b & 7, 8*w + (b>>3));
            ((uint64_t*)buf)[w] = flipped;
            *(uint32_t*)(buf + 4) = stored_be;
            return 1;
        }
    }
    prefix = pcs_crc32up(prefix, &orig, 8);
}
*(uint32_t*)(buf + 4) = stored_be;
return -ec61;                              // unrecoverable
```

## Page-magic byte → page-type mapping

Confirmed page-type tags so far (high byte always `'A'`, low/byte at
`+0x01` carries the type letter):

| `+0x01` byte | Magic word | Meaning                  |
|--------------|------------|--------------------------|
| `'R'` 0x52   | `'ARCH'`   | Archive header (root)    |
| `'I'` 0x49   | `'ARCI'`   | Change-index (CI body)   |
| (others)     | `'A?\0\0'` | other LSM/data page kinds — to be enumerated by walking `archive_dump_all_pages` |

`ar_page_fill_header` writes the type byte from `*(uint8_t*)(arg+8)`,
which is set by the page allocator based on the page kind requested.
A future agent can enumerate all observed page-types by sampling pages
with `archive_dump_all_pages` (export #181 at `0x180008240`).

## Other per-page fields

There are **no** additional per-page fields beyond the 8-byte preamble.
There is no per-page sequence number, no timestamp, and no
checksum-of-checksum. Page versioning / sequencing is performed at the
LSM-tree level (each LSM tree carries its own commit sequence in the
LSM superblock).

## Suggested follow-up targets

1. **`pcs_crc32` confirmation**: the libpcs symbol is imported, so
   confirming the polynomial requires examining libpcs (or equivalently
   feeding a known input through a sample tibx page and verifying
   against zlib `crc32`). The naming and call shape strongly imply
   IEEE 802.3, but a single empirical check would close this out.
2. **Page-type byte enumeration**: scan a representative tibx file and
   collect the distinct second bytes following `'A'` to build a
   page-type catalogue. Cross-reference with the `archive_dump_all_pages`
   helper at `0x180008240` to label each kind.
3. **`ar_page_set_error`** (`0x180056??`) — used when verification
   fails and the archive is not in "ignore CRC errors" mode. Tells us
   how validation failures propagate to user-visible errors.
