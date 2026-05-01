# Archive3 Header TLV Directory

This document describes the 19-entry TLV directory that follows the
1024-byte fixed header record at offset `0x400` of the archive header
(page magic `'ARCH'`).

Source: decompilation of `archive3.dll`, function
`archive_parse_header_tlv_directory` at `0x180015a30` plus its three
callers (`FUN_180013730` header dumper, `FUN_1800155d0` archive opener,
`FUN_1800136a0` minimal stub).

## Directory placement and bounds

The fixed header record begins at body offset `+0x08` of the first page
(after the 4-byte page magic and 4-byte CRC32). The first 0x400 bytes
are a fixed-layout struct (`archive_header`). Starting at body offset
`+0x408` (= `0x400` past the start of the fixed header record) is the
TLV directory, which extends through the end of the header record. The
total fixed-header-record size is announced inline at offset +0x04 of
the fixed-header record (BE u32). The TLV area is
`hdr_size - 0x400` bytes long.

```
[ +0x000  0x400 fixed archive_header struct ]
[ +0x400  TLV directory (variable, hdr_size-0x400 bytes) ]
```

If `hdr_size < 0x400` the parser logs:
`ar#%u: invalid hdr size %u: must be at least %u` and returns `0xffffec75`.

## TLV entry format

Each TLV entry is:

```
+0x00  uint32  length      (big-endian)  ; size of payload in bytes
+0x04  uint8[length]       payload
+0x04+length pad bytes      ; pad up to a 4-byte alignment boundary
```

Stride from one entry's start to the next is computed as:

```
stride = (length + 7) & ~3   ;  i.e., round_up(length + 4, 4)
       = 4-byte length field  +  round_up(length, 4)
```

If the remaining TLV area is smaller than a 4-byte length field, the
parser logs `ar#%u: invalid hdr item %u: 4 bytes expected but %u is left`.
If the announced payload length plus padding exceeds the remaining TLV
area, the parser stores the truncated remainder length in the output
slot's length field and logs
`ar#%u: hdr item %u truncated: %u bytes expected but %u is left`,
returning `0xffffec75`.

The parser writes its results into a 19-slot output array `param_2`,
where each slot is `{void* payload_ptr, uint32_t length}` (16 bytes).
**The payload pointer is to data that lives inline in the header
buffer** (a pointer into the page body). It is not a (file_offset,
size) handle; the section payloads are inline TLV values. However,
many of those inline payloads are themselves **LSM superblocks** that
contain file offsets pointing at LSM tree roots in the rest of the
archive — see "Section semantics" below.

## Version-conditional skip rules

Header version is a BE u16 at fixed-record offset +0x08. Conditional
zero-fills (entry slot left zero, no bytes consumed from TLV stream):

| Version | Indices zero-filled (skipped) |
|---------|-------------------------------|
| `< 7`   | 8, 12, 13, 14, 15, 16         |
| `= 7`   | 12, 13, 14, 15, 16            |
| `>= 8`  | (none — all 19 parsed)        |

So:
- Indices 0..7 and 9..11, 17..18 are present in every version.
- Index 8 (notary tree config) is v7+ only.
- Indices 12..16 are v8+ only.

## Section semantics (19 indices)

Indices 0-9 are confirmed by both the header dumper (`FUN_180013730`) and
the loader (`FUN_1800155d0`). Indices 10-18 are mostly identified via
the loader's consumers; some remain unidentified.

| Idx | Name (canonical)        | Min ver | Payload kind                                                     | Stored at archive struct offset |
|-----|-------------------------|---------|------------------------------------------------------------------|---------------------------------|
| 0   | `lsm` (meta)            | all     | LSM superblock (>=0x178 bytes; tree count + per-tree records); recursive index of the other LSMs in v8+ | `arch+0x1078`     |
| 1   | `data_map` (dmap)       | all     | LSM superblock; **key=31, value=10** (`lsm_dmap_init`)           | `arch+0x1088`                   |
| 2   | `segment_map`           | all     | LSM superblock; **key=8, value=32** (`lsm_key2segment_id`)       | `arch+0x1090`                   |
| 3   | (unidentified; key=9, val=0) | all | LSM superblock; possibly inverted name/segment index         | `arch+0x10e8`                   |
| 4   | `dedup_map`             | all     | LSM superblock (empty in tested archives)                        | `arch+0x10a8`                   |
| 5   | `nlink_map`             | all     | LSM superblock; **key=4 (or ≥12), value=132**                    | `arch+0x10b8`                   |
| 6   | `slices`                | all     | LSM superblock; **key=20, value=0**                              | `arch+0x10f8`                   |
| 7   | `umap` (used map)       | all     | LSM superblock; **key=20, value=0** (empty in tested archives)   | `arch+0x12a8`                   |
| 8   | `notary` (Merkle tree)  | v7+     | Notary tree-config record + tree-root chain                      | `arch+0x12b0`, `+0x550`..`+0x578` |
| 9   | `meta_keys`             | all     | NUL-separated list of UTF-8 key names (max 20)                   | `arch+0x1da8` array             |
| 10  | (unidentified)          | v8+     | unused by openers seen so far                                    | —                               |
| 11  | `dedup_config`          | v8+     | 0 or 12 bytes: three BE u32s (chunking algorithm parameters)     | `arch+0x1ef0..+0x1ef8`         |
| 12  | `golomb_subtable`       | v8+     | Per-level Golomb-coded segment-id index (0x1e+12*N bytes/level)  | `arch+0x10e8` aux at `+0x520` |
| 13  | `ostor_history`         | v8+     | 0 or `0xb70` (=2928) bytes: 1 anchor u64 + 73 records of 5 u64s | `arch+0x658` -> linked entries |
| 14  | (unidentified)          | v8+     | unused by openers seen so far                                    | —                               |
| 15  | (unidentified)          | v8+     | unused by openers seen so far                                    | —                               |
| 16  | (unidentified)          | v8+     | unused by openers seen so far                                    | —                               |
| 17  | extent_table?           | all     | array of 21-byte records `{u64 offset, u32 length, 9 bytes}`     | (printed by FUN_180053e80)      |
| 18  | `volume_table`          | all     | array of 12-byte records `{u32 vol_index, u64 start_offset}`     | rb-tree at `arch+0x3f8`         |

### Verified vs. dump-string label

The header dumper (`FUN_180013730` in `archive3.dll`) uses partly stale
strings: it labels TLV[1] as `"items"` and TLV[2] as `"dmap"`. The
**loader** (`FUN_1800155d0`) is authoritative — it calls
`archive_get_data_map` with the `arch+0x1088` slot (= TLV[1]) and the
per-tree decoder `lsm_dmap_init` asserts `key_length == 31` and
`value_length == 10` against TLV[1]'s on-disk schema bytes. We
empirically verified on `Jmicron 0102.tibx` (header v8) that:

| Slot   | On-disk `key_length` / `value_length` | Decoder asserted        |
|--------|---------------------------------------|-------------------------|
| TLV[1] | 31 / 10                               | `lsm_dmap_init`         |
| TLV[2] | 8 / 32                                | `lsm_key2segment_id`    |
| TLV[3] | 9 / 0                                 | (no decoder asserts 9)  |
| TLV[5] | 4 / 132                               | `lsm_key2link_key`      |
| TLV[6] | 20 / 0                                | `lsm_alloc_umap_key`    |

The dumper-string `"items"` does not match a decoder anywhere — there
is no `lsm_items_init`. It is most likely a historical name that was
dropped from the format but kept as a debug label. **Trust the loader
+ schema bytes, not the dumper strings.**

See `ARCHIVE3_LSM_SUPERBLOCK.md` for the full L-SB layout and the
empirical schema bytes from `Jmicron 0102.tibx` (`hdr_size=0x1540`,
header_version=8).

### Confidence

- **Confirmed via decompilation**: 0..2, 5..9, 11, 12, 13, 18.
- **Confirmed via empirical schema bytes** (`Jmicron 0102.tibx`):
  TLV[1]=data_map (31/10), TLV[2]=segment_map (8/32), TLV[5]=nlink_map
  (4/132), TLV[6]=slices (20/0), TLV[7]=umap (20/0).
- **Inferred / partial**: 17 (record stride from FUN_180053e80 is
  exactly 0x15 bytes; semantic name unconfirmed).
- **Unidentified**: 3 (key=9, val=0 — possibly inverted name/segment
  index — reconcile with strings-agent's `name_map` hypothesis), 4
  (`dedup_map` per loader name, but empty in test archive), 10, 14,
  15, 16. These slots are touched by the TLV parser but no consumer
  references them in the three callers examined.

### Notes on indices 8 and 9

There is an apparent label inversion in the header dumper
`FUN_180013730`: it labels TLV index 8 as `"keys"` and index 9 as
`"notary"`. However the loader `FUN_1800155d0` clearly:

1. Calls `lsm_sb_read(arch[0x12b0], slot8.ptr, slot8.len)` to validate
   slot 8 as an LSM superblock and then passes slot 8's pointer to
   `FUN_180051dd0` which writes
   `notary_tree_degree` at `arch+0x550`,
   `notary_hash_alg`   at `arch+0x553`,
   `notary_hash_size`  at `arch+0x554` and emits log strings
   `lsm#%u: %s unsupported notary tree degree: %u` /
   `lsm#%u: %s unsupported notary hash algorithm: %u` on bad values.
2. Iterates slot 9 with `memchr(.., 0, ..)` to extract NUL-separated
   meta-key strings into `arch+0x1da8` (max 20 entries) — this matches
   the `ar_meta_keys` global table containing `"type"`, `"display_name"`.

The semantic identities are therefore:
- Index 8 = **notary** (tree degree + hash algorithm + tree-root chain).
- Index 9 = **meta_keys** (the NUL-separated key-name list).

The `"keys"`/`"notary"` strings in the dumper are most likely a
historical mis-labelling that was not propagated when the format was
revised.

## TLV parser pseudocode (truncated)

```c
// 0x180015a30  archive_parse_header_tlv_directory
// param_1 = archive id (for logging)
// param_2 = output array (19 x {void*, uint32})
// param_3 = pointer to fixed header record (1024 bytes followed by TLV area)

uint32_t hdr_size = bswap32(*(uint32_t*)(hdr+4));
if (hdr_size < 0x400) return -ec75;       // invalid
uint16_t ver = bswap16(*(uint16_t*)(hdr+8));
uint32_t left = hdr_size - 0x400;
uint32_t* p = (uint32_t*)(hdr + 0x400);
for (int i = 0; i <= 18; i++) {
    bool skip = false;
    if (ver < 7) {
        if (i == 8)              skip = true;             // notary
        else if (i - 12u <= 4u)  skip = true;             // 12..16
    } else if (ver < 8) {
        if (i - 12u <= 4u)       skip = true;             // 12..16
    }
    if (skip) {
        out[i] = (slot){.ptr=NULL, .len=0};
        continue;
    }
    if (left < 4) return -ec75;          // invalid hdr item
    uint32_t len = bswap32(*p);
    out[i].ptr = p + 1;                  // payload pointer (inline)
    uint32_t stride = (len + 7) & ~3u;   // length field + len rounded up to 4
    if (left < stride) {                 // truncated
        out[i].len = left - 4;
        return -ec75;
    }
    out[i].len = len;
    p     = (uint32_t*)((uint8_t*)p + stride);
    left -= stride;
}
return 0;
```

## Suggested follow-up targets

For agents continuing the empirical mapping:

1. **`lsm_sb_read`** — parse and document the LSM-superblock structure
   shared by indices 0..7 (and conditionally 8). It enumerates per-tree
   `{offset, tree_nr, ...}` records that resolve to LSM tree roots
   elsewhere in the file. Resolves `?lsm tree-root format`.
2. **Indices 14, 15, 16** — find callers that consume these slots
   (search xrefs that take the TLV output array and read offsets
   beyond +0xc8 / equivalent). Likely additional v8+ feature payloads.
3. **`FUN_180053e80`** (= prints idx 17 records of size 0x15) and the
   data structure it populates — to confirm "extent_table" hypothesis.
4. **`FUN_180052f50`** (notary subtree-chain walker, called from
   FUN_180051dd0) — documents the on-disk notary-tree-root list and
   per-level fanout/hash sizes. Resolves `?notary tree format`.
5. **`FUN_180054130`** (caller1 line 182, slices automerge data, called
   on slot 17 in caller1) — may reclassify idx 17 as slices-related
   rather than a generic extent table.
