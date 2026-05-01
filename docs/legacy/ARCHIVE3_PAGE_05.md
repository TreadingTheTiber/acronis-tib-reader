# Page type 0x05 — GOLOMB dedup filter

**Sources:**
- Reverse-engineered from `archive3.dll` via Ghidra MCP at
  `http://127.0.0.1:8089/?program=archive3.dll` — functions
  `golomb_encode_mod256` (0x1800417d0), `golomb_decode_mod256`
  (0x180041720), `golomb_index_create` (0x1800419e0),
  `golomb_index_find_mod256` (0x180041c40), `lsm_visit_golomb`
  (0x180046e40), `dedup_map_*` (0x180041170+).  Source-path string
  embedded in the binary:
  `c:\ja\workspace\pipeline\ab-backup-archive3\libarchive3\golomb.c`.
  Logged at archive open as `ar#%u: Upgrade ver.7: create golomb filter`.
- Empirical decode of the 11 contiguous instances at pages
  `13347605..13347615` in `example.tibx` (the only `0x05` pages in
  that 13.4 M-page archive).

## Identity (high confidence)

A page-`0x05` body is one **independent Golomb-Rice (M=256) bitstream**
that encodes a **delta-encoded sorted set of 32-bit hashes** — the
on-disk dedup filter built when an archive is upgraded to format
version 7 ("create golomb filter").

It is a **write-time optimisation** (negative-lookup short-circuit on
the dedup map and on each LSM ctree level).  **It is *not* required for
data recovery** — every hash in the filter also appears in the
authoritative LEAF/LDIR pages, so a reader that can decode LEAF pages
can ignore page-0x05 entirely.

## Page envelope (same as every other page type)

```
+0x00  1   0x41          PAGE_MAGIC_BYTE
+0x01  1   0x05          PAGE_TYPE_GOLOMB
+0x02  2   0x00 0x00
+0x04  4   crc32c BE     CRC of the 4096-byte page with bytes [4:8] zeroed
+0x08 4088  body         Golomb-Rice bitstream (see below)
```

CRC validation is identical to every other page type.

## Body layout — Golomb-Rice (M=256) bitstream

The 4088-byte body is a single bitstream, **MSB-first within each
byte**, decoded one value at a time.  No header, no length, no count
on the page itself: the length and value count are stored in the
**parent LDIR/ctree-descriptor** (`golomb_index_create` is called with
an explicit `param_2` element count and the bitstream length is
known).

### One-value decode (matches `golomb_decode_mod256` at 0x180041720)

```
read_bit()                    # 1 = continue, 0 = stop
quotient = unary_count_of_leading_1s_terminated_by_0  # max 7

if quotient == 8:
    quotient = read_bits(8)   # escape: 8-bit large quotient
remainder = read_bits(8)
value = quotient * 256 + remainder
```

The decoder bugs out (`pcs_bug_at`) if the unary quotient exceeds 8
without hitting the escape path — i.e. q ∈ {0..7} or q=8-then-8-more.

### Stream meaning (matches `golomb_index_create` at 0x1800419e0)

The decoded values are **deltas** in a sorted hash sequence:

```
running_total = 0
for i in range(N):
    delta = decode_golomb_value()
    running_total += delta
    yield running_total
```

`golomb_index_create` additionally sub-divides the stream into buckets
of `param_3` elements each, recording one (start_bit_offset, residual
hash) tuple per bucket so that `golomb_index_find_mod256` can binary-
search for a target hash without decoding the whole stream.  Those
bucket pointers live in **RAM**, not on disk — they are rebuilt every
time the page is loaded.

## Empirical verification

For the 11 0x05 pages in `example.tibx`:

| page      | values decoded | bits used / 32704 | bits/value | mean delta |
|-----------|---------------:|------------------:|-----------:|-----------:|
| 13347605  |            996 |   10751 (full prefix, then padding) | 10.79 | 460.8 |
| 13347606  |             98 |    1023 | 10.44 | 425.3 |
| 13347607  |           1870 |   20089 | 10.74 | 483.8 |
| 13347608  |            243 |    2689 | 11.07 | 493.2 |
| 13347609  |            167 |    1845 | 11.05 | 731.0 |
| 13347610  |           1762 |   18971 | 10.77 | 471.2 |
| 13347611  |           1084 |   11694 | 10.79 | 486.3 |
| 13347612  |           1327 |   14299 | 10.78 | 482.5 |
| 13347613  |           3041 |   32704 | 10.75 | 488.6 |
| 13347614  |            477 |    5076 | 10.64 | 463.8 |
| 13347615  |           3552 |   32704 |  9.21 | (full)  |

Every page's cumulative-sum sequence is **strictly monotonic** — the
defining property of a Golomb-coded sorted hash set — and the
bits-per-value is at the Golomb-Rice optimum for M=256
(theoretical ≈ 10 bits when each hash bucket of 256 holds about one
value).  Pages whose stream is shorter than 32704 bits hit the q>8
"overflow" guard once they begin chewing on the trailing zero
padding; the parent ctree node knows the true value count and stops
decoding before that happens.

## Statistical fingerprint (how to recognise the type)

- **Entropy ≈ 7.92 bits/byte** (essentially uniform); 256 distinct
  bytes per page; max byte run-length ≤ 3.  Visually
  indistinguishable from compressed/encrypted output.  *Exception:*
  trailing zero padding when the Rice stream is shorter than the
  page (very common, see table above).
- **Bit density very close to 50 %** (observed 0.507–0.519 for the
  data portion).  This is the giveaway for Golomb-Rice over a uniform
  hash distribution: every 9-bit group has ~1 leading 1-bit before
  the 0-stop and 8 random bits.
- No magic, no header, no in-band length field.

## Relevance to data recovery

**Skip them.**  The Golomb filter is a hint structure that lets the
write-path avoid pointless lookups; it carries no data that is not
also present in the LEAF pages.  A `tibread`-style reader should
treat page type 0x05 as opaque (count it, CRC-verify it, otherwise
ignore).  The constant lives in `tibread.tibx.format` as
`PAGE_TYPE_GOLOMB` and the inner name in `PAGE_TYPE_NAMES` is
`"GOLOMB"`.
