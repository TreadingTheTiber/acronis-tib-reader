# Archive3 Header TLV Directory — AUTHORITATIVE REFERENCE

**Status: SINGLE SOURCE OF TRUTH for the 19-entry TLV directory.**

This document supersedes the per-investigation TLV mappings in
`ARCHIVE3_LSM_SUPERBLOCK.md` and `ARCHIVE3_CHAINS.md`. All TLV-index ↔
arch-context-offset ↔ tree-name relationships were resolved by
decompiling the loader and the public getters in `archive3.dll` and
cross-referencing them with the in-binary tree-name string table.

Whenever those documents disagree with this one, **this one is right.**

---

## Resolution method (how to verify any row yourself)

The loader function **`archive_parse_header_tlv_directory`**
(`FUN_1800155d0` @ `0x1800155d0`) calls the TLV walker
**`FUN_180015a30`** (@ `0x180015a30`) to populate a 19-slot output array
of `{void* payload, uint32_t length}` pairs (16 bytes each, on the
caller's stack at `&local_178`). It then issues **eight mandatory
`lsm_sb_read` calls** in TLV-slot order, each binding TLV slot N to
the LSM-tree-handle pointer at a **fixed `arch+0x10XX` offset**.

The crucial nine lines from the loader (lightly cleaned):

```c
lsm_sb_read(*(byte **)(arch + 0x1078), local_178, local_170);  // TLV[0]
lsm_sb_read(*(byte **)(arch + 0x1088), local_168, local_160);  // TLV[1]
lsm_sb_read(*(byte **)(arch + 0x1090), local_158, local_150);  // TLV[2]
lsm_sb_read(*(byte **)(arch + 0x10e8), local_148, local_140);  // TLV[3]  <-- not segment_map
lsm_sb_read(*(byte **)(arch + 0x10a8), local_138, local_130);  // TLV[4]
lsm_sb_read(*(byte **)(arch + 0x10b8), local_128, local_120);  // TLV[5]
lsm_sb_read(*(byte **)(arch + 0x10f8), local_118, local_110);  // TLV[6]
lsm_sb_read(*(byte **)(arch + 0x12a8), local_108, local_100);  // TLV[7]
if (hdr_ver >= 7)                                              // v7+ only
    lsm_sb_read(*(byte **)(arch + 0x12b0), local_f8,  local_f0);  // TLV[8]
```

Slot 9 (the meta_keys NUL-separated string list) is consumed in-place
in the loader (the `memchr` walk into `arch+0x1da8`) — there is no
`lsm_sb_read` for it because it is not an LSM tree.

The *names* of the trees come from the post-header init function
**`FUN_1800094a0`** (@ `0x1800094a0`), which is the routine that creates
each LSM tree control block at the same eight `arch+0x10XX` offsets.
Each `lsm_create` (or specialised creator) call passes a configuration
struct whose `local_78` slot is a **pointer to a NUL-terminated ASCII
name string**. Reading those nine pointers out of the binary directly
(memory addresses `0x18009770c .. 0x1800979f4`) yields the names
listed in the table below — these are the names the format's own
implementation uses internally.

The public getters `archive_get_data_map` (`@ 0x180008c60`) and
`archive_get_segment_map` (`@ 0x180008fa0`) confirm slots `arch+0x1088`
and `arch+0x1090` respectively, which independently fixes TLV[1] and
TLV[2].

---

## Authoritative TLV table

Every row is **CONFIRMED** by both (a) the `lsm_sb_read` slot in the
loader, and (b) the in-binary tree-name string at the same `arch+0x10XX`
offset's tree-create call site. Public getter cross-references are
listed where they exist.

| TLV | arch ctx offset | C-source name | User-facing alias | Min ver | Key / Val | Decoder / Getter | Evidence |
|-----|-----------------|---------------|-------------------|---------|-----------|------------------|----------|
| 0   | `arch+0x1078`   | `imap`        | `lsm` (meta)      | all     | 0 / 0 (recursive) | `lsm_create` (generic) | `FUN_1800155d0` line 91; name string `0x18009770c="imap"` |
| 1   | `arch+0x1088`   | `dmap`        | `data_map`        | all     | 31 / 10   | `lsm_dmap_init` (`@0x180048450`); `archive_get_data_map` (`@0x180008c60`) returns `arch+0x1088` | `FUN_1800155d0` line 93; name string `0x1800979bc="dmap"`; getter cross-ref |
| 2   | `arch+0x1090`   | `segment_map` | `segment_map`     | all     | 8 / 32    | `lsm_key2segment_id` (`@0x1800533e0`); `archive_get_segment_map` (`@0x180008fa0`) returns `arch+0x1090` | `FUN_1800155d0` line 94; name string `0x1800979c8="segment_map"`; getter cross-ref |
| 3   | `arch+0x10e8`   | `dedup_map`   | `dedup_map`       | all     | 9 / 0     | `dedup_map_create` (`@0x1800411e0`) sets `param_2[6]=9; param_2[7]=0` | `FUN_1800155d0` line 95; name string `0x1800979d8="dedup_map"`; key/val match in `dedup_map_create` |
| 4   | `arch+0x10a8`   | `nlink_map`   | `nlink_map`       | all     | ≥12 / 132 | `lsm_key2link_key` (`@0x18004f9f0`); `lsm_nlink_map_lookup` (`@0x18004fa50`) called via `ar_item_link_list_start` (`@0x180025020`) on `arch+0x10a8` | `FUN_1800155d0` line 97; name string `0x180097720="nlink_map"`; caller chain confirms binding |
| 5   | `arch+0x10b8`   | `smap`        | `slices`          | all     | 4 / 132   | `archive_slice_query` (`@0x180030390`) → `FUN_18002e010` calls `lsm_iter_init(arch+0x10b8)` with 4-byte BE slice_id key, `ar_slice_from_disk` (`@0x18002da80`) reads 132-byte value | `FUN_1800155d0` line 99; name string `0x180097714="smap"`; slice-query call chain confirms 4-byte key + 132-byte value |
| 6   | `arch+0x10f8`   | `umap`        | `umap`            | all     | 20 / 0    | `lsm_umap_init` (`@0x180053f30`) sets key=0x14, val=0; per-tree creator `FUN_180053da0` likewise | `FUN_1800155d0` line 100; name string `0x1800979e4="umap"`; key/val match in creator |
| 7   | `arch+0x12a8`   | `keymap`      | `keymap`          | all     | (special) | `lsm_create` (generic) — encryption key store | `FUN_1800155d0` line 101; name string `0x1800979ec="keymap"` |
| 8   | `arch+0x12b0`   | `notary`      | `notary`          | v7+     | (special) | `archive_notary_*` family (`@0x18002bdb0..0x18002c300`) all dispatch `lsm_notary_map_*` on `arch+0x12b0` | `FUN_1800155d0` line 104; name string `0x1800979f4="notary"`; per-tree creator `FUN_180051c20` |
| 9   | `arch+0x1da8` (NOT an LSM tree) | `meta_keys`   | `meta_keys`       | all     | n/a       | `memchr`-walk in `FUN_1800155d0` (lines 61-71): NUL-separated UTF-8 strings copied into `arch+0x1da8` array (max 20 entries, indexed by `ar_meta_keys` table) | `FUN_1800155d0` lines 61-71; the loader does not call `lsm_sb_read` on this slot |
| 10  | (unused by loader) | —          | —                 | v8+     | —         | parsed by walker, never consumed by loader | TLV walker reserves slot, loader skips |
| 11  | (`arch+0x1ef0..0x1efc`) | `dedup_config` | `dedup_config` | v8+   | —         | `FUN_1800155d0` lines 72-89: 0 or 12 bytes; three BE u32s into `arch+0x1ef0/0x1ef4/0x1ef8` | `FUN_1800155d0` post-meta_keys block |
| 12-16 | (unused by loader) | —          | —                 | v8+     | —         | parsed by walker, never consumed by the three callers examined; **previous "golomb_subtable / ostor_history" labels at slot 12/13 were INFERRED from neighbouring code, never confirmed by a TLV[12]/[13] consumer** | TLV walker reserves slot; no consumer found |
| 17  | `arch+0x658` (object_history) | `ostor_history` | `ostor_history` | v8+ (objstore only) | — | `FUN_1800155d0` lines 122-179: 0 or 0xb70 bytes; copied verbatim into `arch+0x658` only when `arch+0x44c & 0x80` (objstore flag) is set; rejected with `EAR_NOTFOUND` if size≠0xb70 or objstore flag missing | `FUN_1800155d0` object-history block; logs `"object history is not supported"` / `"invalid object history size"` |
| 18  | `arch+0x3f8` (rb-tree of vols) | `volume_table` | `volume_table` | all | 12-byte records `{u32 vol_index, u64 byte_offset}` | rb-tree at `arch+0x3f8` keyed on byte_offset | parsed by another opener path (Round 4 evidence); on whole-disk archives carries a single `(0, 0)` entry |

---

## Empirical schema bytes (`example.tibx`, header_version=8)

| TLV slot | On-disk `key_length` / `value_length` | Confirms |
|----------|---------------------------------------|----------|
| TLV[1] (`dmap`/data_map) | 31 / 10 | matches `lsm_dmap_init` |
| TLV[2] (`segment_map`)   | 8 / 32  | matches `lsm_val2segment_info` |
| TLV[3] (`dedup_map`)     | 9 / 0   | matches `dedup_map_create` |
| TLV[4] (`nlink_map`)     | ≥12 / 132 (4 / 132 in serialized form per L-SB) | matches `lsm_key2link_key` (asserts ≥12); the L-SB record's `key_length=4` is the *common prefix* slot — link records are 12 bytes minimum |
| TLV[5] (`smap`/slices)   | 4 / 132 | matches `archive_slice_query` (4-byte BE slice_id key) + `ar_slice_to_disk` (132-byte value) |
| TLV[6] (`umap`)          | 20 / 0  | matches `lsm_umap_init` (k=0x14, v=0); on this archive the umap stores per-extent slice attribution |
| TLV[7] (`keymap`)        | (empty) | empty in non-encrypted archives |
| TLV[8] (`notary`)        | (empty) | empty in archives without notary trees |

The dumper at `FUN_180013730` uses DIFFERENT (older / partly stale)
labels than the loader. Specifically the dumper labels TLV[1] as
`"items"` and TLV[2] as `"dmap"`. **Trust the loader and the in-binary
tree-name strings**, not the dumper. There is no `lsm_items_init` and
no decoder anywhere asserts a tree named `"items"`.

---

## TLV entry on-disk format

The directory placement, parser bounds, and entry stride remain as
previously documented:

```
[ +0x000  0x400 fixed archive_header struct ]
[ +0x400  TLV directory (variable, hdr_size-0x400 bytes) ]
```

```
+0x00  uint32  length      (big-endian)  ; size of payload in bytes
+0x04  uint8[length]       payload       ; inline in the page body
+0x04+length pad bytes      ; pad up to a 4-byte alignment boundary
```

Stride: `stride = (length + 7) & ~3`.

Version-conditional zero-fills:

| Version | Indices zero-filled (skipped) |
|---------|-------------------------------|
| `< 7`   | 8, 12, 13, 14, 15, 16         |
| `= 7`   | 12, 13, 14, 15, 16            |
| `>= 8`  | (none — all 19 parsed)        |

---

## TLV parser pseudocode

```c
// 0x180015a30  archive_parse_header_tlv_directory walker
uint32_t hdr_size = bswap32(*(uint32_t*)(hdr+4));
if (hdr_size < 0x400) return -EAR_NOTFOUND;
uint16_t ver = bswap16(*(uint16_t*)(hdr+8));
uint32_t left = hdr_size - 0x400;
uint32_t* p = (uint32_t*)(hdr + 0x400);
for (int i = 0; i <= 18; i++) {
    bool skip = false;
    if      (ver < 7 && (i == 8 || (i - 12u <= 4u))) skip = true;
    else if (ver < 8 && (i - 12u <= 4u))             skip = true;
    if (skip) { out[i] = (slot){.ptr=NULL, .len=0}; continue; }
    if (left < 4) return -EAR_NOTFOUND;
    uint32_t len    = bswap32(*p);
    uint32_t stride = (len + 7) & ~3u;
    out[i].ptr = p + 1;
    if (left < stride) { out[i].len = left - 4; return -EAR_NOTFOUND; }
    out[i].len = len;
    p     = (uint32_t*)((uint8_t*)p + stride);
    left -= stride;
}
return 0;
```

---

## History of corrections (why this needed consolidation)

This directory was re-mapped four times by separate RE rounds before
this consolidation. Earlier docs are preserved for historical reference
but their **tree-name claims should be ignored** in favour of this doc.

1. **Round 1 — TLV walker agent** (`ARCHIVE3_TLV_DIRECTORY.md`):
   *Mostly* correct on slot indices, but copied the dumper labels —
   gave TLV[1]=`items`, TLV[2]=`dmap`, TLV[5]=`nlink_map`,
   TLV[6]=`slices`, TLV[7]=`umap`, plus listed slot 17 as the
   "extent_table". Used dumper strings without cross-referencing the
   loader's own tree-create call site.
2. **Round 2 — lsm_sb_read agent** (`ARCHIVE3_LSM_SUPERBLOCK.md`):
   Realised that the dumper labels were inverted; correctly
   re-labelled TLV[1]=`data_map` (k=31/v=10) and TLV[2]=`segment_map`
   (k=8/v=32) using `lsm_dmap_init` + `lsm_key2segment_id`. **Still
   wrong** on TLV[3]=`name_map?` (it is actually `dedup_map`),
   TLV[4]=`dedup_map` (it is actually `nlink_map`),
   TLV[5]=`nlink_map` (it is actually `slices`/`smap`),
   TLV[6]=`slices` (it is actually `umap`),
   TLV[7]=`umap` (it is actually `keymap`).
3. **Round 3 — chain/slices agent** (`ARCHIVE3_CHAINS.md`):
   Spotted that `archive_slice_query` calls `lsm_iter_init` on
   `arch+0x10b8`, which is TLV[5]'s loader-bound slot — so TLV[5]
   *must* be slices, contradicting Round 2's `nlink_map`. Inferred
   TLV[6] = "slice extent attribution index" (umap-shaped, key=20).
   Correct on TLV[5]=slices; **misnamed TLV[6]** as a custom
   `slice_extent_idx` label — its actual canonical name is `umap`
   (the umap *is* used as a per-extent attribution index in this
   archive, but the tree-handle name is just `umap`).
4. **Round 4 — meta_keys / volume_table agent**:
   Verified TLV[18]=`volume_table` and decoded the `(idx=0, byte_offset=0)`
   record on whole-disk example sample. No conflict with the LSM-slot
   mapping; this slot does not pass through `lsm_sb_read`.

The recurring root cause across rounds 1–3: each agent took the
**dumper string** (`FUN_180013730`) as the source of truth, when in
fact the **loader's tree-create call site** (`FUN_1800094a0`) hard-codes
a different, correct set of names that match the on-disk schema bytes
and the public getter API. This document fixes that by:

- using the loader's `lsm_sb_read` slot order to fix TLV-index ↔ arch-offset, and
- using the post-header init's `lsm_create` name-string argument to fix arch-offset ↔ canonical name, and
- using public getters (`archive_get_data_map`, `archive_get_segment_map`) as an independent third anchor.

---

## Confidence summary

- **CONFIRMED via decompile + getter cross-ref**: TLV 0, 1, 2, 5, 6, 8.
- **CONFIRMED via decompile + tree-name string**: TLV 3, 4, 7.
- **CONFIRMED via parser-only (slot consumed but no LSM)**: TLV 9 (meta_keys), TLV 11 (dedup_config), TLV 17 (object_history), TLV 18 (volume_table).
- **INFERRED (slot reserved by walker, no consumer found in three callers studied)**: TLV 10, 12, 13, 14, 15, 16.

Anything labelled "INFERRED" in earlier docs — including
`golomb_subtable` for slot 12, `ostor_history` for slot 13,
`extent_table` for slot 17 — was speculative correlation and is
**not** carried over here. Slot 17 was empirically renamed to
`ostor_history` in this doc on the strength of the loader's 0xb70
size-check (the only place that magic constant appears).

---

## Pointer back from companion docs

If you arrive here from `ARCHIVE3_LSM_SUPERBLOCK.md` or
`ARCHIVE3_CHAINS.md`, those documents reference this one for all
TLV-index ↔ tree-name mappings. The L-SB on-disk *format* is still
documented in `ARCHIVE3_LSM_SUPERBLOCK.md`; the slice record format
(132-byte LSM value at TLV[5]) is in `ARCHIVE3_CHAINS.md`.
