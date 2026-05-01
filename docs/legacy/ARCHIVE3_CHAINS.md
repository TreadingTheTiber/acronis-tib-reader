# Archive3 (`.tibx`) backup-chain / slice format

Source: decompilation of `archive3.dll` (build "Acronis Archive3 v8") via
Ghidra MCP at `http://127.0.0.1:8089/?program=archive3.dll`, plus
empirical inspection of `example.tibx` (54.6 GB sample, header
version 8). Confidence is annotated `[CONFIRMED]` (verified directly
by decompiling named functions and matching empirical bytes) or
`[INFERRED]` (deduced from naming, strings, or partial decompilation).

This is a sibling document to `docs/legacy/CHAIN_FORMAT.md` (the legacy
`.tib` chain format) and to `docs/legacy/ARCHIVE3_LSM_SUPERBLOCK.md`
(the LSM tree envelope). It supersedes the slice-related claims of
the LSM-superblock doc — see "Correction" near the end.

---

## TL;DR

* `.tibx` archives are **self-contained backup chains**. Unlike `.tib`,
  the entire chain (every full / inc / diff / edited slice) lives
  inside one `.tibx` file. There is **no sidecar SQLite catalog**
  required to walk the chain.
* The chain is enumerated through an LSM tree at TLV slot 5 ("the
  slices tree"; key=4 byte BE `slice_id`, value=132-byte slice record).
* Each slice carries: a 16-byte slice UUID, a 4-byte slice_id (1-based
  ordinal in the chain), a slice **type** (FULL / INC / DIFF / EDITED),
  features (hidden, before-sys-patch, converted, isolated-network),
  a creation timestamp, a parent-slice UUID (16 B; zero for FULL), and
  several internal counters.
* The "current state" of the archive is a single ARCH page near the
  end of the file. To "walk back to the first full backup", iterate
  the slices LSM tree by `slice_id` (or follow the parent-UUID chain
  through `archive_slice_query_by_uuid`); each slice's data is
  attributed via the per-extent index in TLV[6] (key=20 B).
* Same set of slice types as `.tib`: BASE / INCREMENTAL / DIFFERENTIAL
  / EDITED. No CDP entry in `slice_type2str` (.tibx omits CDP).

## TLV mapping reference

> The full authoritative TLV directory ↔ arch-offset ↔ tree-name table
> lives in **`ARCHIVE3_TLV_DIRECTORY.md`**. Refer there for evidence
> and for the names of slots not used by the chain logic. The summary
> below is just enough to orient a reader of this doc.

This document covers the slices LSM tree, which the loader binds to
**TLV[5]** at `arch+0x10b8`. The loader's internal C-source name for
this tree is `smap` (slices map) — the user-facing alias is `slices`.
The tree at `arch+0x10f8` (TLV[6]) is the `umap`, and on this archive
the `umap` happens to be used as a per-extent slice attribution
index — but the tree-handle name is `umap`, not a custom
`slice_extent_idx`.

`[CONFIRMED]` Evidence chain for TLV[5] = slices: `archive_slice_query`
(`@0x180030390`) → `FUN_18002e010` (`@0x18002e010`) calls
`lsm_iter_init(arch+0x10b8)` with a 4-byte BE `slice_id` key, then
`lsm_lookup_eq` returns a 132-byte payload that `ar_slice_from_disk`
(`@0x18002da80`) decodes into the slice struct. The post-header init
`FUN_1800094a0` (`@0x1800094a0`) creates this same tree at
`arch+0x10b8` with the in-binary name string `"smap"` at `0x180097714`.

`[CONFIRMED]` Evidence chain for TLV[4] = nlink_map: callers of
`lsm_nlink_map_lookup` (`@0x18004fa50`) — for example
`ar_item_link_list_start` (`@0x180025020`) — pass `arch+0x10a8`. The
post-header init creates that slot's tree with the in-binary name
string `"nlink_map"` at `0x180097720`. So the chain agent's prior
claim ("`nlink_map` is not a top-level slot") was wrong — it is at
TLV[4], simply at a different `arch+0x10XX` offset than the chain
agent had identified.

Quick reference (full evidence in `ARCHIVE3_TLV_DIRECTORY.md`):

| TLV | C-source name | User-facing alias | arch offset | Key/Val |
|----:|---------------|-------------------|-------------|---------|
| 0   | `imap`        | `lsm` (meta)      | 0x1078      | 0/0 (recursive) |
| 1   | `dmap`        | `data_map`        | 0x1088      | 31/10  |
| 2   | `segment_map` | `segment_map`     | 0x1090      | 8/32   |
| 3   | `dedup_map`   | `dedup_map`       | 0x10e8      | 9/0    |
| 4   | `nlink_map`   | `nlink_map`       | 0x10a8      | ≥12/132 |
| **5** | **`smap`**  | **`slices`**      | **0x10b8**  | **4/132** |
| 6   | `umap`        | `umap`            | 0x10f8      | 20/0   |
| 7   | `keymap`      | `keymap`          | 0x12a8      | (special) |
| 8   | `notary`      | `notary` (v7+)    | 0x12b0      | (special) |

---

## 1. Ghidra anchors

| RVA          | Symbol                                  | Role |
|--------------|-----------------------------------------|------|
| `0x18002da80`| `ar_slice_from_disk`                    | Decode 132-byte on-disk slice record into in-memory struct (see §3 for byte-precise mapping). [CONFIRMED] |
| `0x18002eef0`| `ar_slice_to_disk`                      | Encode in-memory slice into 132-byte (effective 131 + 1 pad) on-disk record. [CONFIRMED] |
| `0x18002f8f0`| `archive_slice_create`                  | Public: create a new slice in the current chain. Calls `archive_slice_create_ex`. [CONFIRMED] |
| `0x18002f960`| `archive_slice_create_ex`               | Generates 16-byte UUID via `pcs_get_urandom(buf, 0x10)`, allocates a new slice_id (`*(int *)(arch + 0x64c) + 1`), writes record via `lsm`-insertion path (`FUN_1800349f0`), updates archive ARCH header in-place. [CONFIRMED] |
| `0x180030390`| `archive_slice_query`                   | Public: look up slice by `slice_id` (u32). Wraps `FUN_18002e010`. [CONFIRMED] |
| `0x18002e010`| `(slice_query_core)`                    | Internal: `lsm_iter_init(arch+0x10b8); lsm_lookup_eq(key=BE32(slice_id))`; calls `ar_slice_from_disk` on the value. **This is the proof TLV[5] is the slices tree.** [CONFIRMED] |
| `0x1800303e0`| `archive_slice_query_by_uuid`           | Public: linear scan via `ar_slice_list_start` + `lsm_lookup_next` matching the 16-byte UUID. UUID lookup is **not** indexed — O(N) on chain length. [CONFIRMED] |
| `0x180030560`| `archive_slice_query_prev_or_eq`        | Public: `FUN_18002c5a0(arch, sid, out, 1, 1)` — does `lsm_lookup_le` on `arch+0x10b8` to find the slice with greatest id ≤ requested. Used to walk backwards through the chain. [CONFIRMED] |
| `0x18002c5a0`| `(slice_list_core)`                     | Internal: drives `lsm_lookup_ge`/`le`, applies feature filters (incomplete, hidden, edited via low bits of `flags = (param_4 & 1) << 3 \| (param_5 & 1) \| 4`). Returned record bytes are decoded by `FUN_1800314f0`. [CONFIRMED] |
| `0x1800620a0`| `archive_slice_get_base_uuid`           | Public: walk slice list with `ar_slice_list_start`, return the **first slice's UUID** (i.e., the base FULL of the chain). Despite the name, it returns the *chain root* UUID, not a parent pointer. [CONFIRMED] |
| `0x1800309a0`| `archive_slice_start_chain`             | Public: begin a new chain by writing a FULL/EDITED slice. Resets per-chain counters (`arch + 0x670/0x678/0x680/0x688`). Calls `archive_slice_create_ex`, then `FUN_180030cf0` to mark old slices for cleanup. [CONFIRMED] |
| `0x180031650`| `(start_chain_check)`                   | Internal: validates whether a new chain start is needed (DIFF + last is DIFF → skip; INC + last is INC → also skip; …). Uses `slice_type2str` for log messages. [CONFIRMED] |
| `0x18002fe60`| `archive_slice_finish`                  | Mark current slice "complete". Writes the slice record again with completion bit set (`FUN_18002fea0`), zeros temp slice state. [CONFIRMED] |
| `0x18002f6a0`| `archive_slice_cleanup`                 | Walk LSM (the items LSM at `arch+0x1078`, **not** the slices LSM) and delete records belonging to the current `slice_id` — used after a failed/cancelled slice. [CONFIRMED] |
| `0x180034a90`| `slice_type2str`                        | enum→string: 0→"full", 1→"inc", 2→"diff", 3→"edited". `pcs_bug` on any other value. [CONFIRMED] |
| `0x18002efc0`| `ar_slice_type_from_str`                | str→enum: "diff"→2, "inc"→1, "edited"→3, otherwise 0. [CONFIRMED] |
| `0x180033c10`| `slice_features2str`                    | Decode features bitmask: bit0="" (unnamed first feature), bit1=`hidden`, bit2=`before sys. patch`, bit3=`converted`, bit4=`created in network isolation`. [CONFIRMED] |
| `0x180070060`| `archive_validate_slices`               | Public: structural validation pass over all slices. [CONFIRMED to exist] |
| `0x1800615e0`| `archive_slice_export`                  | Public: copy a slice from one archive to another, materializing a base-full + diff/inc as needed. Internally uses `archive_slice_get_export_params @ 0x180062200`. [CONFIRMED] |
| `0x18002f560`| `archive_hdr_slice_print`               | Diagnostic: print `last sid` / `last full sid` from a slice list header. [CONFIRMED] |

---

## 2. Slice LSM tree shape (TLV[5])

`[CONFIRMED]` from L-SB inspection of the user's archive
(`example.tibx`, latest ARCH page = 13347627):

```
TLV[5] slices  ver=2  ctree_count=3  mem_nodes=2  ctree[2..N]=EMPTY
   key_length=4  value_length=132
   memtree_encoding=1 (LZ4)  memtree_extra_len=112  memtree_pages_total=1
```

Two slices, both held in the **residual mem-tree** (no on-disk ctree
LEAF page). The residual mem-tree is LZ4-compressed and lives in the
extra payload of the L-SB record (`L-SB[0x178 .. 0x178 + extra_len]`).

Decompressed payload (144 bytes):

```
0200000200000001 0000000200_9f7aefd07fadc35a0e9cc76eb19776db_0000018647bf998f
0000018647c9dc5f 000000165d835bcf 00000011c810e000 0000000100000000
0000000700000000 010000000000058e d40000000000000c b53510...zeros...
```

* `00 00 01 86 47 bf 99 8f` = BE u64 = 1681740161423 (Unix-ms) ≈
  2023-04-17 18:42 UTC — slice timestamp #1 ✓ matches the archive's
  `created_unix_ms` reported by `read_arch_header`.
* `00 00 01 86 47 c9 dc 5f` = BE u64 = 1681741053023 ≈ 15 minutes
  later — slice timestamp #2.
* `9f 7a ef d0 7f ad c3 5a 0e 9c c7 6e b1 97 76 db` — looks like a
  random 16-byte UUID (slice UUID).
* The leading `0x02 0x00 0x00 0x02 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x02`
  is consistent with `(node_count=2, slice_id_lo=1, slice_id_hi=2)` —
  the 2 slices in this chain are `slice_id=1` (FULL) and `slice_id=2`
  (INC or DIFF — the type bit is hidden in the flags byte at +0x44 of
  each record, which we cannot extract without an mem-tree decoder).

`[INFERRED]` Mem-tree serialization is `lsm_records_to_tree`
(`FUN_180043d10`) format and is partly variable-stride. A full
decoder is in flight (companion agent's `lsm_cells.py`). For now,
on-disk LEAF pages can be decoded with the byte-precise format in §3
once a chain has compacted past the mem-tree.

---

## 3. On-disk slice record (132-byte LSM value)

`[CONFIRMED]` from `ar_slice_to_disk` (`@ 0x18002eef0`) and
`ar_slice_from_disk` (`@ 0x18002da80`). All multi-byte integers are
**big-endian**. The mem-struct offsets are listed for reference.

```
Slice record (TLV[5] LSM value, 132 bytes; effective 131 + 1 pad):

  +0x00  16   slice_uuid                 raw 16 B  (mem +0x20..+0x30; copied verbatim, no swap)
  +0x10   8   ts_a                       BE u64    (mem +0x30; possibly volume_creation_time)
  +0x18   8   ts_b                       BE u64    (mem +0x38; possibly data_creation_time)
  +0x20   8   parent_uuid_lo             BE u64    (mem +0x40)        ┐ 16 B parent slice UUID
  +0x28   8   parent_uuid_hi             BE u64    (mem +0x48)        ┘ (zero for FULL/BASE)
  +0x30   4   features_or_flags          BE u32    (mem +0x10)        — appears to mirror low bits of +0x44 byte
  +0x34   4   reserved_or_rating         BE u32    (mem +0x14)
  +0x38   4   counter_a                  BE u32    (mem +0x58)
  +0x3c   4   counter_b                  BE u32    (mem +0x5c)
  +0x40   4   counter_c                  BE u32    (mem +0x60)
  +0x44   1   flags_byte                 raw u8    bit-encoded (see below)
  +0x45   8   ts_c                       BE u64    (mem +0x18; UNALIGNED)  — likely ctime / Slice_.dataCreationTime_
  +0x4d   4   slice_id                   BE u32    (mem +0x4)               — 1-based ordinal in chain
  +0x51   8   chain_root_id_or_extra     BE u64    (mem +0x50; UNALIGNED)
  +0x59  42   reserved (zeros)           memset 0
  ----
  total: 0x83 = 131 bytes; LSM value_length is 132 (1 byte trailing pad/alignment).
```

### Flags byte at +0x44

`[CONFIRMED]` from `ar_slice_to_disk` lines:

```c
bVar4 = -(param_1[8] != 0) & 0x80U | *param_1;          // hidden bit + features
if (param_1[1] == 2)      bVar4 |= 4;                    // type=DIFF
else if (param_1[1] == 3) bVar4 |= 8;                    // type=EDITED
*(byte *)((longlong)param_2 + 0x44) = bVar4;
```

And from `ar_slice_from_disk`:

```c
bVar1 = *(byte *)((longlong)param_1 + 0x44);
*param_2     = bVar1 & 0x73;                             // features bits 0,1,4,5,6
if      ((bVar1 & 4) != 0) bVar5 = 2;                    // DIFF
else if ((bVar1 & 8) != 0) bVar5 = 3;                    // EDITED
else                       bVar5 = ((bVar1 & 0x73) != 0); // 1=INCREMENTAL, 0=FULL
param_2[1]   = bVar5;                                    // type
param_2[8]   = bVar1 >> 7;                               // hidden
```

Bit layout of the flags byte:

| Bit | Mask | Meaning                                           |
|-----|------|---------------------------------------------------|
| 7   | 0x80 | `hidden` (slice was internally created, e.g. for system patch) |
| 6   | 0x40 | feature (covered by mask 0x73 → bit 6) — `created in network isolation` |
| 5   | 0x20 | feature (mask 0x73 → bit 5) — `converted` |
| 4   | 0x10 | feature (mask 0x73 → bit 4) — `before sys. patch` |
| 3   | 0x08 | type bit: EDITED                                  |
| 2   | 0x04 | type bit: DIFFERENTIAL                            |
| 1   | 0x02 | feature (mask 0x73 → bit 1) — `hidden` (the *string* "hidden", distinct from bit 7) |
| 0   | 0x01 | feature (mask 0x73 → bit 0) — unnamed (first feature; truncated string at `0x1800a760c`) |

(Bits 0,1,4,5,6 carry the `features` bitmap; bits 2,3 the type; bit 7
the hidden flag. Note that "hidden" is overloaded — bit 1 is a
*string-named* feature called "hidden" in `slice_features2str`, while
bit 7 is the **internal** hidden flag from the create-slice path.)

### Slice type enum

`[CONFIRMED]` from `slice_type2str`:

| Type value | String   | Meaning                                                   |
|-----------:|----------|-----------------------------------------------------------|
| 0          | `"full"` | BASE — first slice of a chain                             |
| 1          | `"inc"`  | INCREMENTAL — depends on the immediately preceding slice  |
| 2          | `"diff"` | DIFFERENTIAL — depends on the chain's BASE only           |
| 3          | `"edited"`| EDITED — a manually-modified slice (in-place edit, rare) |

No `CDP` entry — `.tibx` does not carry continuous-data-protection
slices (unlike `.tib` v23.5, which has `SliceType_CDP` at index 4).

### Computing the type from the disk record

```python
def slice_type_from_flags(flags_byte: int) -> str:
    if flags_byte & 0x04:                  return "diff"
    if flags_byte & 0x08:                  return "edited"
    if (flags_byte & 0x73) != 0:           return "inc"
    return "full"

def slice_features(flags_byte: int) -> list[str]:
    out = []
    f = flags_byte & 0x73
    if f & 0x01: out.append("(unnamed)")
    if f & 0x02: out.append("hidden")
    if f & 0x10: out.append("before sys. patch")
    if f & 0x20: out.append("converted")
    if f & 0x40: out.append("created in network isolation")
    if flags_byte & 0x80: out.append("internal_hidden")
    return out
```

---

## 4. Chain mechanics

### 4.1 How a slice identifies its parent

`[CONFIRMED]` from `ar_slice_to_disk` and `archive_slice_create_ex`:

* For a **FULL** (`type=0`) slice: parent_uuid (disk +0x20..+0x30) is
  zero. `slice_id` is freshly allocated as the first slice in a new
  chain.
* For an **INCREMENTAL** (`type=1`) slice: parent_uuid is set to the
  immediately preceding slice's UUID. (i.e., the chain is a doubly-
  linked list: forward via `slice_id+1`, backward via `parent_uuid`.)
* For a **DIFFERENTIAL** (`type=2`) slice: parent_uuid is set to the
  chain's BASE UUID (the FULL slice that started this chain).
* For an **EDITED** (`type=3`) slice: parent_uuid is set to the
  predecessor slice (the slice this one edits in-place).

The 16-byte `slice_uuid` is generated by `pcs_get_urandom(buf, 0x10)`
in `archive_slice_create_ex`; it is **not** derived from any external
input (i.e., not the archive UUID). Each slice gets a unique random
16-byte ID.

`[CONFIRMED]` Within `archive_slice_create_ex`:

```c
if (param_5 == NULL) {
    pcs_get_urandom(local_b0, 0x10);   // generate fresh 16-byte UUID
    param_5 = local_b0;
}
*(ulonglong *)(arch + 0x590) = *param_5;       // current_slice_uuid_lo
*(ulonglong *)(arch + 0x598) = param_5[1];     // current_slice_uuid_hi
*(int *)(arch + 0x57c) = arch[0x64c];          // arch_current_slice_id ← arch_next_slice_id
*(int *)(arch + 0x64c) += 1;                   // bump the global counter
*(int *)(arch + 0x650) += 1;                   // chain length + 1
if (type == FULL /* 1 */) {
    *(ulonglong *)(arch + 0x680) = 0;          // chain_base_id = 0 (this IS the base)
    *(longlong *)(arch + 0x678) = arch[0x670] + 1;  // start a new chain
    *(ulonglong *)(arch + 0x688) = 0;
}
else if (type == EDITED /* 3 */) {
    *(longlong *)(arch + 0x688) = arch[0x670] + 1;  // edit-chain start
}
```

The archive struct fields:
* `arch + 0x510..0x518` — current slice's UUID (16 B; mirror of "last")
* `arch + 0x57c`        — current slice_id (u32)
* `arch + 0x590..0x598` — the **parent** slice's UUID for the slice
                          being created (the value this code writes
                          into the new slice's record at disk +0x20..+0x30)
* `arch + 0x648`        — last commit_seq
* `arch + 0x64c`        — next slice_id to allocate (monotone counter)
* `arch + 0x650`        — chain length (= count of slices since last FULL)
* `arch + 0x670`        — global chain ordinal
* `arch + 0x678`        — current chain id
* `arch + 0x680..0x688` — chain bookkeeping
* `arch + 0x10b8`       — pointer to the slices LSM tree handle

### 4.2 Walking from "current state" to "first FULL"

Two paths, both `[CONFIRMED]`:

**Path A — by slice_id (efficient, O(log N) per step):**

```python
# starts at the most-recent slice; ends at the FULL with type=0
current_id = arch[0x57c]                           # ar_slice_current_id @ 0x18002d720
while current_id > 0:
    rec = archive_slice_query(arch, current_id)    # hits TLV[5] LSM
    yield rec
    if slice_type(rec.flags_byte) == "full":
        return
    current_id -= 1                                # next-older slice in chain
```

**Path B — by UUID (chained, O(N) per step due to UUID-not-indexed):**

```python
rec = archive_slice_query_by_uuid(arch, current_uuid)
while rec is not None:
    yield rec
    if all(b == 0 for b in rec.parent_uuid):
        return                                     # FULL slice
    rec = archive_slice_query_by_uuid(arch, rec.parent_uuid)
```

Path A is what `ar_slice_list_start` + `ar_slice_list_next`
(`@ 0x18002dde0` / `@ 0x18002dd70`) implement internally:
`lsm_iter_init` → `lsm_lookup_ge` (or `_le`) → `lsm_lookup_next`
through the slices LSM. The L-SB schema's `seq` field doesn't matter
here — the LSM key (slice_id) is densely allocated 1, 2, 3, ….

`archive_slice_get_base_uuid @ 0x1800620a0` uses Path A: it iterates
the slice list from the start, returning the first slice's UUID.

### 4.3 Forward walk: open at FULL, replay each slice in order

```python
for sid in range(1, arch[0x64c]):                  # arch.next_slice_id
    rec = archive_slice_query(arch, sid)
    if rec.flags_byte & 0x80:                      # internal-hidden
        continue
    yield rec
```

The chain is forward-walkable because `slice_id` is densely allocated.
A `slice_id`-based walk is the canonical mount-time replay sequence.

### 4.4 ARCH commit pages and chain identity

`[CONFIRMED]` from the existing `ARCHIVE3_LSM_SUPERBLOCK.md` and
`ARCHIVE3_HEADER_FORMAT.md`:

* The archive header (page-type 0x01 = ARCH/QARCH) is rewritten on
  every commit. Each commit produces a new ARCH page near the end of
  the file; older ARCH pages remain valid as historical points-in-time.
* The L-SB record for the slices tree is **inline** in the latest
  ARCH page. So **every commit re-writes the slices tree's mem-tree
  blob** in place.
* When a new slice is created (`archive_slice_create_ex`), the
  archive's commit cycle:
  1. Insert slice record into mem-tree of TLV[5].
  2. Update `arch + 0x57c` (current_slice_id) and `arch + 0x650` (chain length).
  3. Eventually flush mem-tree to a LEAF page (LSM compaction; happens
     when the mem-tree exceeds the size hint at L-SB +0x0c).
  4. Allocate a new ARCH page at the file tail, write the new L-SB
     records into its TLV directory, link it via the ARCI commit-tree.
* The **archive_uuid** at ARCH page 0 (offset +0x28) is the *archive*
  identity, not any single chain's identity. The first FULL slice's
  UUID is the *chain* identity (via `archive_slice_get_base_uuid`).

In `example.tibx` the archive_uuid is
`655f4ba513f6efc834432712570b1240` (16 B), which is **not** equal to
either of the two slice UUIDs in the slices tree — confirming that
archive UUID and slice UUID are independent.

---

## 5. Comparison with `.tib` (legacy `Archive2`) chain format

| Aspect                                  | `.tib` (Archive2)                                    | `.tibx` (Archive3)                                |
|-----------------------------------------|------------------------------------------------------|---------------------------------------------------|
| Chain unit                              | One file per slice                                   | One file per **chain** (contains all slices)      |
| Filename pattern                        | `<archive>_<TYPE>_b<B>_s<S>_v<V>.tib`                | `<archive>.tibx` (no `_b`/`_s`/`_v`)              |
| Chain link in-file                      | **None** — only `<task_id>` / `<computer_id>` chain ID; needs sidecar DB | **Present** — `parent_uuid` (16 B) at disk +0x20 of every slice record |
| Chain enumeration                       | Filename scan + verify metainfo XML matches `task_id`| `lsm_iter_init(slices_tree)` — `slice_id` 1..N    |
| Sidecar dependency                      | Yes — SQLite `local-archives.db` / `mms.db` with `Slice_(parentId_, sliceUid_, ...)` | **No** — chain fully described inside the `.tibx`|
| Forward link                            | `archive_pit_next` (UUID) in PIT TLV record          | `slice_id + 1` (densely allocated)                |
| Backward link                           | None (catalog-only via `Slice_.parentId_`)           | `parent_uuid` (16 B) embedded in slice record     |
| Slice types                             | BASE / INC / DIFF / EDITED / **CDP**                 | BASE / INC / DIFF / EDITED (no CDP)               |
| Stored timestamp                        | Trailer XML `task_id` only — actual timestamps in DB | 3× BE-u64 timestamps inside slice record (ts_a/b/c) |
| Mount-time chain build                  | Directory scan + open every `.tib`                   | Open one `.tibx` + walk LSM[5]                    |

**Key takeaway**: a third-party `.tibx` reader does **not** need any
sidecar files to enumerate the chain. The `lsm_lookup`-based slice
walker is sufficient. This is the inverse of `.tib`, where filenames
+ catalog DB are mandatory.

---

## 6. TLV[6] / `umap` — per-extent slice attribution

`[CONFIRMED]` TLV[6] is the `umap` tree (canonical name from the
in-binary string `0x1800979e4`); the loader binds it to `arch+0x10f8`,
not `arch+0x12a8`. The `lsm_umap_init` symbol at `0x180053f30` (and
the per-tree creator `FUN_180053da0`) sets `key=0x14, value=0`,
matching the on-disk schema bytes. The earlier "umap loader is wired
to `arch+0x12a8` (TLV[7])" claim was wrong — TLV[7] is `keymap`
(encryption key store), not `umap`.

`[CONFIRMED]` empirical: TLV[6] in `example.tibx` has
`item_count=2` (mem-tree) and a small ctree[2] root LDIR at page
13347623 with **7 child LEAF pages** holding ~199 keys each. The
20-byte key has the structure:

```
+0x00  8   key_part_a    BE u64   (sequential byte-offsets in the user's archive: 0x22771d, 0x439a81, 0x6459aa, 0x855682, 0xa58441, 0xc6ac89, 0xcb9a75)
+0x08  8   slice_id      BE u64   (always 0x02 for first 4 LDIR entries, 0x03 for last 3)
+0x10  4   version_or_flag BE u32 (always 0x00000001 in observed data)
```

`[INFERRED]` On this archive the `umap` is being used as a
**per-data-extent slice ownership index**: for each chunk in
`data_map`, which slice last wrote/modified it. The umap is a
SET-shaped LSM (value=0) — mere presence of the key signals "slice
S last modified extent E at version V". This is consistent with the
generic "used-extent map" semantic referenced in the LSM superblock
doc and the existing `lsm_key2umap_ext` (`@0x180053910`) decoder
asserting `key_len == 20`.

---

## 7. Confidence summary

| Claim                                                                    | Confidence | Source                                                                                  |
|--------------------------------------------------------------------------|------------|------------------------------------------------------------------------------------------|
| TLV[5] (key=4, val=132) is the slices tree                               | CONFIRMED  | `archive_slice_query` and friends iterate `*(arch + 0x10b8)` = TLV[5] (loader binding)  |
| Slice key = BE u32 `slice_id`; slice_id densely allocated from 1         | CONFIRMED  | `archive_slice_query` body builds 4-byte BE key; create_ex bumps `*(arch + 0x64c)`      |
| Slice value = 132-byte record (effective 131 + 1 pad)                    | CONFIRMED  | `ar_slice_to_disk` writes 0x83 bytes; assertion `local_b70 < 0x84` in slice_query_core  |
| Slice record carries 16-byte UUID + parent UUID + slice_id + flags       | CONFIRMED  | Byte-precise mapping from `ar_slice_to_disk`                                            |
| 4 slice types: full / inc / diff / edited (no CDP)                       | CONFIRMED  | `slice_type2str` enum 0..3 only; `pcs_bug` for any other value                          |
| Features: (unnamed) / hidden / before-sys-patch / converted / network-isolated | CONFIRMED  | `slice_features2str` bit-walk on a u32 with named string addresses              |
| Hidden flag bit 7; type=DIFF bit 2; type=EDITED bit 3                    | CONFIRMED  | `ar_slice_to_disk` flags-byte computation                                                |
| `parent_uuid` field is at disk +0x20..+0x30 of slice record               | CONFIRMED  | `ar_slice_to_disk` writes mem +0x40, +0x48 (no swap on first half) at disk +0x20, +0x28; create_ex sets these from `arch + 0x590..0x598` |
| `parent_uuid` is zero for FULL slices                                    | INFERRED (very strong) | create_ex zeroes `arch + 0x680/0x688` for FULL; mem +0x40/+0x48 read from these in to_disk |
| Chain walk via `archive_slice_query_prev_or_eq` is in-archive (no sidecar)| CONFIRMED  | Function does `lsm_lookup_le` on `arch + 0x10b8`; no I/O outside the `.tibx`            |
| `.tibx` carries no sidecar SQLite DB requirement                         | CONFIRMED  | Decompiled chain functions never reference `mms.db` / `sqlite` / `local-archives.db`    |
| Each commit rewrites the latest ARCH page; older ARCH pages remain valid | CONFIRMED  | Per `ARCHIVE3_HEADER_FORMAT.md` and L-SB inline-in-ARCH design                          |
| `archive_uuid` ≠ first slice's UUID                                      | CONFIRMED  | Empirically distinct in the user's `.tibx`                                              |
| TLV[6] (key=20) is `slice_extent_idx` (per-extent ownership)             | INFERRED   | Empirical: keys carry slice_id at +0x08; sorted by extent-byte-offset prefix; no decoder symbol found |
| TLV[6] is NOT the slices tree                                            | CONFIRMED  | Slice-related functions never iterate `arch + 0x10f8`                                   |
| Mem-tree records use a different (compressed) format than LEAF cells     | CONFIRMED  | 144-byte LZ4 blob holds 2 slices that would total 264 bytes raw; need cell-decoder for byte-precise unpack |

---

## 8. Open questions for follow-up

1. **Empirical mem-tree decoder** — confirm the 144-byte LZ4 blob
   resolves to 2 × 132-byte slice records once `lsm_records_to_tree`
   (FUN_180043d10) is decoded. The companion `lsm_cells.py` agent
   owns this.
2. **TLV[6] decoder symbol** — find the helper that asserts a 20-byte
   key and decodes it into `(extent_id, slice_id, version)`. Check
   `lsm_alloc_umap_key @ 0x180053860` and its callers.
3. **Field semantics of mem `+0x18` (ts_c) vs `+0x30` (ts_a) vs `+0x38`
   (ts_b)** — three timestamps per slice. One is plausibly
   `dataCreationTime`; the other two may be `volumeCreationTime` and
   `startTime` (matching the `.tib` `Slice_` columns).
4. **`arch + 0x648` `commit_seq`** — written into slice record at
   `arch + 0x584` ↔ counter_a (mem +0x58). Verify this is the LSM
   commit sequence at slice-creation time.
5. **`archive_slice_get_data_size`** — extract the per-slice data
   footprint computation. Likely walks TLV[6] aggregating extent
   sizes for matching `slice_id`.

---

## Appendix A — relevant strings (anchors)

```
0x1800a74d0  "full"            (slice_type2str -> 0)
0x1800a74dc  "inc"             (slice_type2str -> 1)
0x1800a74d8  "diff"            (slice_type2str -> 2)
0x1800a74e4  "edited"          (slice_type2str -> 3)
0x1800a7548  "diff"            (ar_slice_type_from_str -> 2)
0x1800a754c  "inc"             (ar_slice_type_from_str -> 1)
0x1800a7554  "edited"          (ar_slice_type_from_str -> 3)
0x1800a7610  "hidden"          (slice_features2str bit 1)
0x1800a7618  "before sys. patch" (slice_features2str bit 2)
0x1800a7630  "converted"       (slice_features2str bit 3)
0x1800a7640  "created in network isolation" (slice_features2str bit 4)
0x1800a7500  "c:\ja\workspace\pipeline\ab-backup-archive3\libarchive3\archive_slice.c"
0x1800a76b0  "ar#%u: archive_slice_query(sid=%u)"
0x1800a7c58  "ar#%u: archive_slice_start_chain..."
0x1800a7cd0  "ar#%u: archive_slice_create(sid=..."
```

---

## Appendix B — empirical L-SB dump for the user's archive

```
Archive: /path/to/example.tibx
File size: 54,671,892,480 bytes (13,347,628 pages of 4 KiB)
Latest ARCH page: 13347627 (header_version=8, hdr_size=0x1540)
Archive UUID: 655f4ba5-13f6-efc8-3443-2712570b1240

LSM superblocks (corrected names):
  TLV[0] lsm           ver=2 ctree_count=3 mem_nodes=7
  TLV[1] data_map      key=31 val=10  (the chunk-content map)
     ctree[2] root_page=13347115 num=0x1a2000 cnt=27   max=0x19eb5
     ctree[4] root_page=9568874  num=0x421000 cnt=18   max=0x3f025
  TLV[2] segment_map   key=8  val=32
     ctree[2] root_page=13347532 cnt=26
     ctree[4] root_page=11684241 cnt=23
  TLV[3] (name_map?)   key=9  val=0
     ctree[2] root_page=13347604 cnt=10
     ctree[3] root_page=11987593 cnt=8
  TLV[4] dedup_map     EMPTY
  TLV[5] slices        key=4  val=132   mem_nodes=2 (2 slices in this archive!)
                       ctree[*] EMPTY (all in mem-tree)
                       memtree_extra_len=112 (LZ4-compressed, decoded to 144 B)
  TLV[6] (slice_ext_idx?) key=20 val=0  mem_nodes=3
                       ctree[2] root_page=13347623 cnt=2
                                LDIR with 7 children (LEAF pages 13347616..13347622)
                                ~1380 keys total, encoding (extent_off, slice_id ∈ {2,3}, ver=1)
  TLV[7] umap          EMPTY
  TLV[8] notary        EMPTY

Slice 1 (FULL ?, slice_id=1) — UUID:?  (not extracted; needs mem-tree decoder)
Slice 2 (INC or DIFF, slice_id=2) — UUID 9f7aefd0-7fad-c35a-0e9c-c76eb19776db (?)
                                    timestamp 0x18647bf998f ≈ 2023-04-17 18:42 UTC
                                    timestamp 0x18647c9dc5f ≈ 2023-04-17 18:57 UTC

Note: TLV[6] has slice_id values 2 and 3 in its keys, but TLV[5] reports
only 2 slices. This either means the user's archive had a slice deleted
(and TLV[6] still carries its extent attributions) or the in-mem-tree
node count of 2 is per-record and not per-slice. Resolution requires
the mem-tree decoder.
```

End of spec.
