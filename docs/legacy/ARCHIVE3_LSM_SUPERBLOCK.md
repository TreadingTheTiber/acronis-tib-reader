# Archive3 LSM Superblock + Tree-Walk Format

This document describes the on-disk **LSM superblock** ("L-SB" record),
the LSM B-tree page envelope, and the per-tree key/value layouts used by
Acronis archive3 (`.tibx`) files.

Source: decompilation of `archive3.dll` (build `Acronis Archive3 v8`).
Cross-validated against `example.tibx` (54.6 GB sample, format
version 8). Confidence per fact is annotated `[CONFIRMED]` (verified
directly by decompilation of named functions and matched empirically
against bytes in the sample) or `[INFERRED]` (deduced but not
end-to-end exercised).

## Ghidra function anchors

| RVA          | Symbol                | Role                                                      |
|--------------|-----------------------|-----------------------------------------------------------|
| `0x180045e90`| `lsm_sb_read`         | Parse L-SB record from a TLV payload buffer               |
| `0x1800459f0`| `lsm_sb_create`       | Serialize an in-memory LSM tree set into a new L-SB record|
| `0x180044bc0`| `lsm_init`            | Initialize a per-tree control block (sets key/val sizes)  |
| `0x180048450`| `lsm_dmap_init`       | Specialise lsm_init for the `data_map` tree (key=31, val=10) |
| `0x180053f30`| `lsm_umap_init`       | Specialise lsm_init for the `umap` tree                   |
| `0x180045700`| `lsm_page_read`       | Read & validate one LSM tree page                         |
| `0x180045510`| `lsm_page_validate`   | (FUN_180045510) parse page header & dispatch by magic     |
| `0x1800452f0`| `lsm_page_decode`     | (FUN_1800452f0) decompress page payload, build mem-tree   |
| `0x180046530`| `lsm_page_check`      | (FUN_180046530) verify magic, version, encoding, sequence |
| `0x1800462f0`| `lsm_page_walk`       | (FUN_1800462f0) walk record area, LZ4-decompress, append  |
| `0x180043d10`| `lsm_records_to_tree` | (FUN_180043d10) parse byte stream into key/value pairs    |
| `0x180046790`| `lsm_lz4_decompress`  | (FUN_180046790) Acronis LZ4 stream wrapper                |
| `0x18004b760`| `lsm_lookup_core`     | (FUN_18004b760) per-ctree key search, calls FUN_180049fa0 |
| `0x18004b530`| `lsm_lookup_eq`       | Public: equality lookup                                   |
| `0x1800485d0`| `lsm_key2dmap_ext`    | data_map key (31 B) → struct (asserts param_1[1]==0x1f)   |
| `0x180048640`| `lsm_val2dmap_ext_info`| data_map value (10 B) → struct (asserts == 10)           |
| `0x1800533e0`| `lsm_key2segment_id`  | segment_map key (8 B) → u64 segment id                    |
| `0x1800537d0`| `lsm_val2segment_info`| segment_map value (32 B) → struct                         |
| `0x18004f9f0`| `lsm_key2link_key`    | nlink_map key (≥12 B; 4-byte prefix + suffix)             |
| `0x180053910`| `lsm_key2umap_ext`    | umap key (20 B)                                           |
| `0x180053860`| `lsm_alloc_umap_key`  | umap key allocator (key length = 20)                      |

Magic constants (`.rdata`):

| Address       | Bytes (hex)                        | ASCII   |
|---------------|------------------------------------|---------|
| `0x1800b22d4` | `4c 2d 53 42 00 00 00 00`          | `L-SB`  |
| `0x1800b2304` | `4c 2d 53 42 00 00 00 00`          | `L-SB`  (alt symbol) |
| `0x1800b19f0` | `4c 45 41 46 00 00 00 00`          | `LEAF`  |
| `0x1800b19f8` | `4c 44 49 52 00 00 00 00`          | `LDIR`  |

## Where L-SB records live

`[CONFIRMED]` Each LSM superblock is the **inline payload** of a TLV
slot inside the archive header (page-type 0x01 = ARCH/QARCH). It is not
a (file_offset, length) handle — the L-SB body lives in the header
buffer and points outward at root pages elsewhere in the file.

The TLV directory parser
(`archive_parse_header_tlv_directory @ 0x180015a30`) writes 19 slots
of `{void* payload, uint32_t length}`. The archive opener
`FUN_1800155d0` then calls `lsm_sb_read` once per slot 0..7 (and once
on slot 8 if header version ≥ 7), passing the inline TLV payload
pointer. Mapping (`[CONFIRMED]` from the opener):

| TLV slot | Tree              | Stored at archive struct offset      | Key size | Value size |
|---------:|-------------------|---------------------------------------|----------|------------|
| 0        | `lsm` (meta)      | `arch+0x1078`                         | 0        | 0 (recursive) |
| 1        | `data_map` (dmap) | `arch+0x1088` (`archive_get_data_map`)| **31**   | **10**     |
| 2        | `segment_map`     | `arch+0x1090`                         | **8**    | **32**     |
| 3        | (unidentified, `key=9`, `val=0`) | `arch+0x10e8`              | 9        | 0          |
| 4        | `dedup_map`       | `arch+0x10a8`                         | (empty)  | (empty)    |
| 5        | `nlink_map`       | `arch+0x10b8`                         | **4**    | **132**    |
| 6        | `slices`          | `arch+0x10f8`                         | **20**   | 0          |
| 7        | `umap`            | `arch+0x12a8`                         | (empty)  | (empty)    |
| 8        | `notary` (v7+)    | `arch+0x12b0`                         | (special)| (special)  |

Note: the previous `ARCHIVE3_TLV_DIRECTORY.md` labelled TLV[1] as
`items` and TLV[2] as `dmap`. The empirical schema bytes (key=31, val=10
on TLV[1]) plus the runtime call `archive_get_data_map → arch+0x1088
← TLV[1]` clearly identify TLV[1] as `data_map` and TLV[2] as
`segment_map`. The header-dumper at `FUN_180013730` uses inverted
labels — likely a historical mislabelling in the dumper that the
loader does not propagate. The archive opener (loader) is authoritative
here.

## L-SB byte layout

`[CONFIRMED]` from `lsm_sb_read` and `lsm_sb_create`. Total record size
is `0x178 + extra_payload_len` bytes; minimum is `0x178` (376) when no
in-memory residual tree is serialised.

```
+0x000  4   magic                  = 'L-SB'           (literal ASCII; not byte-swapped)
+0x004  1   format_version         = 2                (must be ≤ 2; checked)
+0x005  1   ctree_count_minus_2    = nr_ctree - 2     (loaded as nr_ctree+2; ≤ 10)
+0x006  1   ctree_max_minus_2      = ctree_max - 2    (≥ ctree_count_minus_2)
+0x007  1   reserved/flags         = 0                (zero on disk; not validated)
+0x008  4   seq_or_id              BE u32             (commit seq # — printed by dumper)
+0x00c  4   ctree_size_hint        BE u32             (LSM compaction "ctree_sz" target)
+0x010  4   key_length             BE u32             (per-record key bytes)
+0x014  4   value_length           BE u32             (per-record value bytes)
+0x018  per-ctree records          (ctree_count entries, each 32 bytes; see below)
   ...     last entry at offset 0x018 + (ctree_count-1)*32
+0x158  1   memtree_encoding       = 0=raw, 1=LZ4, 0x80-bit set = encrypted
+0x159  1   reserved               = 0
+0x15a  2   memtree_node_count     BE u16             (# entries in residual mem-tree)
+0x15c  4   memtree_extra_len      BE u32             (must equal sb_size - 0x178)
+0x160  4   memtree_pages_total    BE u32             (cumulative pages contributing)
+0x164  0x14 reserved/padding      (20 bytes; zero in v2)
+0x178  ... memtree_extra_payload  (memtree_extra_len bytes; LZ4 frame if encoding=1)
```

### Per-ctree slot (32 bytes)

Stored densely from `+0x018` onwards. Slot index `i` (0 ≤ i < ctree_count)
corresponds to ctree level `i+2` (level 0 is the in-mem mem-tree,
level 1 is the residual `memtree_extra_payload`). Layout per slot:

```
+0x00  8   root_page_offset       BE u64  (file offset of root page; 0xff..ff = empty)
+0x08  8   num_pages_total        BE u64  (total pages occupied by this ctree)
+0x10  4   item_count             BE u32  (# leaf entries)
+0x14  4   reserved/zero          BE u32
+0x18  8   max_key_or_size        BE u64  (printed as "max" by dumper; varies)
```

## Empirical L-SB dump (example.tibx, latest ARCH page = 13347627)

```
TLV[0]=lsm           ver=2 ctree_count=3 max=12 seq=0   key/val=0/0
                      mem-tree: 7 nodes, extra_len=314, pages_total=559
TLV[1]=data_map      ver=2 ctree_count=5 max=12 seq=0x1b key=31 val=10
   ctree[2] root_page=0xcba92b000 (page 13347115) num=0x1a2000 cnt=27   max=0x19eb5
   ctree[3] EMPTY
   ctree[4] root_page=0x92026a000 (page 9568874)  num=0x421000 cnt=18   max=0x3f025
TLV[2]=segment_map   ver=2 ctree_count=5 seq=0x1a       key=8  val=32
   ctree[2] root_page=0xcbaacc000 (page 13347532) cnt=26
   ctree[4] root_page=0xb24991000 (page 11684241) cnt=23
TLV[3]=??? key=9     ver=2 ctree_count=4 seq=0xa
   ctree[2] root_page=0xcbab14000 (page 13347604) cnt=10
   ctree[3] root_page=0xb6ea89000 (page 11987593) cnt=8
TLV[5]=nlink_map     ver=2 key=4 val=132   mem-tree only (2 nodes)
TLV[6]=slices        ver=2 key=20 val=0    mem-tree (3 nodes) + ctree[2] root=0xcbab27000
TLV[4]=dedup_map, TLV[7]=umap, TLV[8]=notary: all empty in this archive
```

## LSM page envelope (page-types 0x03 = LEAF, 0x04 = LDIR)

`[CONFIRMED]` from `lsm_page_validate` (FUN_180045510),
`lsm_page_check` (FUN_180046530), `lsm_page_decode` (FUN_1800452f0)
and validated against the file.

```
.tibx file page (4096 bytes total):
+0x00  1   page magic byte            = 0x41
+0x01  1   page type                  = 0x03 (LEAF) | 0x04 (LDIR) | 0x01 (ARCH) | 0xff (DATA)
+0x02  2   reserved                   = 00 00
+0x04  4   page CRC32                 BE u32 (covers body)

.tibx body (4088 bytes; offsets below relative to body start):
+0x00  4   inner magic                = 'LEAF' | 'LDIR'
+0x04  1   format version             = 1            (must be < 2)
+0x05  1   encoding                   = 0(raw) | 1(LZ4) | 0x80-bit (encrypted; same low3 alg)
+0x06  2   reserved/level             BE u16         (low byte often page-tree depth)
+0x08  4   uncompressed_payload_len   BE u32         (matches LZ4 stream-header u_len)
+0x0c  4   total_record_area_len      BE u32         (= inner_LZ4_clen + 8 if LZ4)
+0x10  4   page_id                    BE u32         (cross-checked against caller's ID)
+0x14  4   sequence/format_id         BE u32         (== arch->seq or 0)
+0x18  0x1c reserved/padding (28 bytes; zero in v1)
+0x34  4   inner LZ4 stream-header: compressed_len    BE u32  (only if encoding=1)
+0x38  4   inner LZ4 stream-header: uncompressed_len  BE u32  (only if encoding=1)
+0x3c  ... LZ4 frame (or raw records if encoding=0)
+0x34+total_record_area_len  ...padding...           (zeros to body end)
```

The 8-byte preamble at `body+0x34` (when encoding=1) is the Acronis LZ4
stream wrapper produced by `lsm_lz4_decompress` (FUN_180046790). The
outer `total_record_area_len` field (body+0x0c) equals `inner_LZ4_clen
+ 8`; the validator at FUN_1800452f0 enforces it via `bswap(*(u32*)(buf+0x14)) + 0x34 < 0xff9`.

### LDIR record format (B-tree internal node)

Every internal-page record is `[key (key_length bytes)] [child_page_offset (BE u64)]`.

`[CONFIRMED]` empirically: the data_map root LDIR (page 9568874) decompressed
to exactly 234 bytes = 6 × 39 = 6 × (31 + 8). Each child offset is a
**file byte offset** (not a page index) — divide by 4096 to get page index.

### LEAF record format

Records are concatenated `[key (key_length B)] [value (value_length B)]`,
optionally with a 4-byte BE "presence bitmap" at the start of every
group of 32 records (`[INFERRED]` from FUN_180043d10's
`*(char *)((longlong)param_1 + 0x19)` flag — set on some trees, off on
others). For trees where the bitmap flag is unset (encoding=raw),
LEAF page records pack contiguously.

`[INFERRED]` In the data_map LEAF at depth 2 (page 9565839) we
decompressed 9371 bytes into ~97 records with rec_size=41 — but not
exactly divisible, suggesting either the bitmap-prefix is in use (every
32 records adds 4 bytes overhead → 97 records = 12 bitmap bytes →
`97*41 + 12 = 3989`, or `9371` bytes → ~228 records of 41B = 9348 + 23
trailing bytes; actual encoding may include a per-record "present"
bit-vector). The exact LEAF body byte format is the focus of the
companion *LSM LEAF / page 0x03/0x04 decoder* agent's work.

## LSM-tree walk algorithm

`[CONFIRMED]` from `lsm_lookup_core` (FUN_18004b760), `lsm_iter_init`,
and `FUN_180049fa0` (per-ctree page-walk). Pseudocode:

```c
int lsm_lookup(LsmTree *t, const Key *k, /* out */ Value *v) {
    // 1. Search the in-memory mem-tree (level 0/1) first.
    if (lsm_mem_tree_lookup(t->mem_tree, k, v) == FOUND) return 0;

    // 2. For each ctree level i in [2 .. t->ctree_max], in order:
    for (int i = 2; i <= t->ctree_count; i++) {
        Slot *s = &t->ctrees[i - 2];                  // L-SB per-ctree slot
        if (s->root_page_offset == 0xff..ff) continue; // empty ctree

        u64 cur_offset = s->root_page_offset;
        for (;;) {
            Page *p = lsm_page_read(t, cur_offset);    // decompresses if needed
            int n = page_record_count(p);              // (records/(key_len+ptr_or_val))

            // Binary-search records[] for the largest key <= k.
            int idx = bsearch_le(p->records, k);
            if (idx < 0) break;                        // not in this subtree

            if (p->magic == 'LDIR') {
                cur_offset = read_be_u64(record_value_field(p, idx));
                continue;                              // descend
            } else {                                   // LEAF
                if (key_eq(record_key(p, idx), k)) {
                    *v = record_value(p, idx);
                    return 0;                          // found
                }
                break;
            }
        }
    }
    return NOT_FOUND;
}
```

Notes:
* Levels 2..N are persistent **B-tree-shaped LSM components**, not a
  single B-tree. A miss at level `i` falls through to `i+1`. Compaction
  merges higher levels into lower (older = higher-numbered slots in the
  per-ctree array, per `lsm_init` which sets `ctree_size[i]` =
  `0x100000 << (i - 2)`).
* `lsm_page_read` honours the page's `encoding` byte: encoding=0 means
  records are raw; encoding=1 invokes the Acronis LZ4 stream wrapper;
  encoding=0x80|alg means encrypted (then decrypted to raw or LZ4).
* The validator enforces `page->page_id == expected_id` and
  `page->sequence in {0, arch->seq}`. A mismatch returns error
  `0xffffec75` ("page header is corrupted").

## Per-tree key/value formats

`[CONFIRMED]` from individual `lsm_keyN_*`/`lsm_valN_*` decoders:

### data_map (TLV[1]; arch+0x1088): key=31, value=10

`lsm_key2dmap_ext` (asserts key length = 0x1f):
```
+0x00  8   field_a              BE u64     (high-entropy; likely chunking-key)
+0x08  8   field_b              BE u64
+0x10  1   byte_c                          (param_2 +2 high byte)
+0x11  1   byte_d
+0x12  1   byte_e
+0x13  4   field_f              BE u32
+0x17  8   field_g              BE u64
                                            (total = 31 bytes)
```

`lsm_val2dmap_ext_info` (asserts value length = 0x0a):
```
+0x00  8   ext_offset           BE u64   (top 7 bytes; bottom byte goes to flags?)
+0x08  2   ext_size_or_flags    BE u16
                                            (total = 10 bytes)
```

### segment_map (TLV[2]; arch+0x10e8): key=8, value=32

`lsm_key2segment_id` (asserts key=8): plain `BE u64 segment_id`.

`lsm_val2segment_info` (asserts value=0x20 = 32):
```
+0x00  1   flags_low           (raw byte)
+0x01  7   field_b              BE u56     (top byte of u64 minus +0)
+0x08  4   pack_low26 + flags2  BE u32     (low 6 bits in top, etc.)
+0x0c  8   field_c              packed
+0x14  8   field_d              packed (offset within page)
+0x1c  4   field_e              raw u32
                                            (total = 32 bytes)
```
The `lsm_val2segment_info` decompilation accesses bit-packed fields;
exact semantics are deferred — but the on-disk record size is **32 B**.

### TLV[3] (key=9, value=0)

Identity not yet decoder-confirmed. Empirical observations from
`example.tibx`:

* Root LDIR at byte offset `0xcbab14000` decompresses to 1190 bytes
  (= 70 records of 9 + 8 = 17 bytes each).
* The 70 keys are sorted lexicographically and span the full byte
  range (first bytes 0x03..0xff, evenly distributed). This is
  consistent with a hashed-name index, not a structured ID space.
* No `lsm_key*` decoder in `archive3.dll` asserts `key_len == 9`.

The strings-agent inferred a `name_map` tree from string-table
ordering (`data_map, name_map, segment_map, unused_map, nlink_map,
notary_map`). Mapping that list onto the L-SB schema bytes:

| Strings agent name | Our TLV slot | Schema (k/v) |
|--------------------|--------------|--------------|
| `data_map`         | TLV[1]       | 31 / 10 ✓    |
| `name_map`         | TLV[3]       | 9 / 0 — likely |
| `segment_map`      | TLV[2]       | 8 / 32 ✓     |
| `unused_map`       | TLV[7]       | (= umap; empty) |
| `nlink_map`        | TLV[5]       | 4 / 132 ✓    |
| `notary_map`       | TLV[8]       | (notary, v7+) |

So **TLV[3] is most plausibly `name_map`** — a filename-hash → ID
inverted index. This is an inference, not a decoder confirmation.

A `lsm_alloc_umap_key` symbol exists at 0x180053860 but its key length
is 20 (matching TLV[6]/TLV[7], not TLV[3]).

### nlink_map (TLV[5]; arch+0x10b8): key≥12, value=132

`lsm_key2link_key` (asserts key length ≥ 12):
```
+0x00  8   parent_or_link_id   BE u64
+0x08  4   field_b             BE u32
+0x0c  ... variable suffix     (raw bytes; length = key_len - 12)
```

Value (132 bytes) layout not yet decoded — likely a fixed-size inode/
link record with name + attributes.

### slices (TLV[6]; arch+0x10f8): key=20, value=0

Key allocator `lsm_alloc_umap_key` (sic — labelled umap but used for
slices? Actually it allocates a **20-byte umap key**, not slices).
Slices' key=20 layout is similar but stored as record (no value):
```
+0x00  8   slice_id            BE u64
+0x08  4   sub_id              BE u32 (top bit possibly used as flag)
+0x0c  8   offset              BE u64
+0x14  -   (key end)
```

### umap (TLV[7]; arch+0x12a8): key=20, value=0 (used-extent map)

`lsm_key2umap_ext` (asserts key=0x14):
```
+0x00  8   extent_id_or_off    BE u64
+0x08  4   ext_len_low + flag1 BE u32     (top bit of low byte = flag)
+0x0c  8   ext_offset          BE u64
+0x14  -   (key end)
```

Empty in the sample archive.

### items (no fixed-size lsm_item_init found)

The "items" tree (originally TLV[1] per the dumper) probably collapses
into a different physical slot. The dumper labels TLV[1]="items" but
the **schema there is the data_map schema** (key=31, val=10) per
`lsm_dmap_init` and the loader's wiring. Treat the dumper labels as
historical / partly inverted; trust the loader and the empirical L-SB
schema bytes.

## Empirical validation

`[CONFIRMED]` Walked data_map ctree[4] (root = page 9568874) using the
above formats:

```
depth 0: page 9568874  type=0x04 LDIR   ver=1 enc=0x1  u_len=234  c_len=181
  -> 6 entries of 39 bytes each (key=31 + child=8); first child @ 0x920264000

depth 1: page 9568868  type=0x04 LDIR   ver=1 enc=0x1  u_len=7956 c_len=3976
  -> 102 entries; first child @ 0x91f68f000

depth 2: page 9565839  type=0x03 LEAF   ver=1 enc=0x1  u_len=9371 c_len=4000
  -> ~97 entries (record packing not exactly 41-byte stride; presence-bitmap?)
     [0] key=18ffffff0000000000000002000000000000000000054a0000000200000000  val=00000001000000000000
     [1] key=00010000000000000000000300000000000000000400000000000200000000  val=00000004000000000000
     [2] key=0004ffff000000000000000400000000000000000000100000000200000000  val=00000002000000000000
     [3] key=00020000000000000000000500000000000000000000540000000200000000  val=00000003000000000000
     [4] key=00030000000000000000000600000000000000000010000000000200000000  val=00000009000000000000
```

The keys are 31-byte binary blobs; the "high"-bit `0x18` and `0x00..0x04`
prefixes look like they encode a small enum (file extent class?) plus
a SHA-like inner identifier. The 10-byte values look like
`{8-byte big-endian counter, 2-byte trailer}`.

## Key takeaways for downstream consumers

1. **L-SB is not a separate page** — it is an inline TLV payload in the
   archive header (page-type 0x01). 9 LSM trees in v8 (8 regular + notary).
2. The L-SB carries per-tree metadata: `key_length`, `value_length`,
   `seq`, an **array of per-ctree records** (32 B each) giving
   `{root_page_byte_offset, num_pages, item_count, max_key_offset}`,
   and (optionally) an **LZ4-compressed residual mem-tree** appended
   after the fixed 0x178-byte header.
3. Tree pages (LEAF=0x03, LDIR=0x04) have a **52-byte (`0x34`) inner
   header** followed by an Acronis-LZ4-wrapped record area. The wrapper
   prepends `[BE u32 inner_clen][BE u32 inner_ulen]` (8 bytes) before
   the LZ4 block.
4. **Lookup is multi-layer**: (a) mem-tree, (b) compressed mem-tree from
   L-SB extra payload, (c) ctrees in increasing level order, each one
   a B-tree of LDIR pages above LEAF pages.
5. Each child pointer in an LDIR record is an absolute **file byte
   offset**, not a page index — divide by 4096 (page size) to read.
6. Encoding-byte high bit (`0x80`) indicates encryption. None of the
   trees in the sample archive use encryption.

## Open work

* Exact per-record packing inside LEAF body (variable stride / presence
  bitmap) — companion agent's focus.
* Identity of TLV[3] (key=9, val=0). Per the loader it lives at
  `arch+0x10e8`, the same address used by the existing TLV doc for
  `segment_map`. Resolve cross-doc inconsistency.
* Dumper-vs-loader name inversion (TLV[1]/TLV[2]). Authoritative ID is
  by L-SB schema bytes + loader struct offset, not dumper string.
* Per-tree value layouts beyond field offsets (e.g., nlink_map's 132 B
  value, segment_map's 32 B record).
