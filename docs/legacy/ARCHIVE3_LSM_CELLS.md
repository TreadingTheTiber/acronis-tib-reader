# Archive3 LSM cell-stream encoding

This note documents the per-page cell-stream encoding used inside
LEAF (page-type 0x03) and LDIR (page-type 0x04) pages of an
Acronis archive3 (`.tibx`) file.  It is the missing piece between
"I have an L-SB superblock and a tree of LDIR/LEAF pages" and "I
can list the (key, value) entries in that tree".

The encoding was recovered by reverse-engineering `archive3.dll`
on a Windows installation; the relevant Ghidra functions are
listed at the end of this document.

## On-disk layout, top to bottom

A single 4096-byte LEAF or LDIR page is laid out as:

```
+0x000 .. +0x008  outer page envelope ('A' 0x03/0x04 ... CRC32C)
+0x008 .. +0x040  inner LSM page header (see below)
+0x040 .. +0x040+on_disk_size  cell stream (compressed bytes)
+0x040+on_disk_size .. +0x1000  zero pad / unused tail
```

After the outer envelope is stripped (this is what
`TibxReader.read_page()` returns as `body`), the page body is:

| Offset | Size | Field              | Notes                                   |
|--------|------|--------------------|-----------------------------------------|
| 0x00   | 4    | `magic`            | `"LEAF"` or `"LDIR"`                    |
| 0x04   | 1    | `version`          | Must be `< 2`                           |
| 0x05   | 1    | `encoding`         | low 7 bits = codec (0 raw, 1 LZ4); bit 7 = encrypted |
| 0x06   | 2    | `cell_count`       | BE u16 -- number of cells on the page   |
| 0x08   | 4    | `uncompressed_size`| BE u32 -- length of decoded cell buffer |
| 0x0C   | 4    | `on_disk_size`     | BE u32 -- compressed length on disk     |
| 0x10   | 4    | `key_size_param`   | BE u32 -- per-tree validator (e.g. 27)  |
| 0x14   | 4    | `sequence_id`      | LE u32                                  |
| 0x18   | 0x1C | (zero pad)         |                                         |
| 0x34   | ...  | cell stream        | length = `on_disk_size`                 |

Note that **`encoding` is at byte offset +0x05, not +0x06**.  Earlier
notes pointed at +0x06 because the BE u16 at +0x06 (cell count) is
usually `0x00xx` for pages with fewer than 256 cells, which made +0x06
look like a "0x00 dominant" encoding byte.  In every LEAF/LDIR page in
the test archive the actual encoding byte at +0x05 is `0x01`.

## Codec dispatch (`encoding & 0x7F`)

| Codec | Bytes seen | Description |
|-------|------------|-------------|
| 0     | 0          | Raw -- the cell stream is the on-disk bytes verbatim, and `on_disk_size == uncompressed_size`.  Used for very small pages and during memtable construction. |
| 1     | 18 919 / 18 919 | Multi-block LZ4.  See below.  This is the only codec observed in real archives. |
| ...   | 0          | Reserved.  The DLL `pcs_bug`s on any other value. |

### `encoding & 0x80` -- encrypted

When the high bit is set, the cell stream is first decrypted with the
archive's per-volume key (`lsm->decrypt_cb` in the source) before being
fed to the codec.  The decrypt callback is registered via
`archive_set_compatibility(... encryption ...)` and is not currently
implemented in `tibread`; encrypted pages raise `NotImplementedError`.

### Codec 1: multi-block LZ4

The stream is a concatenation of blocks; each block has the layout:

```
+0  4   compressed_size    BE u32
+4  4   uncompressed_size  BE u32
+8  N   LZ4 block payload  (N = compressed_size)
```

Successive blocks are decompressed via `LZ4_decompress_safe_continue`,
i.e. each block is decompressed against the **previously emitted**
output as its history dictionary (so history references can cross
block boundaries).  In our Python implementation we pass the last 64
KiB of accumulated output as `dict=` to `lz4.block.decompress`.

Real-world frames have several blocks; for `data_map` LEAF pages we
have observed frames like:

```
block 0: c=1523  u=3997
block 1: c= 855  u=2472
block 2: c= 539  u=1607
block 3: c= 355  u=1033
block 4: c= 259  u= 701
block 5: c= 141  u= 414
block 6: c= 122  u= 291
block 7: c=  55  u= 127
block 8: c=  48  u=  86
total c=3897 (+8*9 hdrs = 3969 = on_disk_size)
total u=10728 = uncompressed_size
```

A common bug is to assume a single LZ4 frame and decode only the first
block; that returns roughly the first quarter of the cells and then
truncates.

## Cell-record layout (after decompression)

Within the `uncompressed_size`-byte decoded buffer the cells are laid
out in one of two ways depending on the owning tree's L-SB
configuration (`fixed_key_size` and `fixed_val_size` at L-SB +0x10 /
+0x14) and on whether the page is LEAF or LDIR.

### Compact mode (LEAF only, `fixed_key_size != 0`)

Cells are partitioned into **groups** of up to 24 cells.  Each group
is preceded by a 4-byte LE u32 header:

```
u32 LE = group_count  | (alive_b1 << 8) | (alive_b2 << 16) | (alive_b3 << 24)
```

Decoded as:
* `group_count = u32 & 0xFF`  (1..24, number of cells in this group)
* `bitmap = b3 | (b2 << 8) | (b1 << 16)` -- a 24-bit alive-bitmap

Bit `i` of `bitmap` corresponds to cell `i` of the group:
* `bit == 1`  alive cell -- contains key followed by value.
* `bit == 0`  tombstone -- key only, no value bytes.

Cell layout within a group:
```
alive cell:    key (fixed_key_size bytes) | val (fixed_val_size bytes)
tombstone:     key (fixed_key_size bytes)
```

### Variable mode (LDIR always, LEAF if `fixed_key_size == 0`)

LDIR pages always use the variable layout regardless of the tree's
fixed sizes -- their values are pre-defined to be 8-byte child page
offsets.  LEAF pages of a tree configured with `fixed_key_size == 0`
also use this layout.

There is no group bitmap.  Each cell is laid out as:

If `fixed_key_size == 0`:
```
leb128 key_len | leb128 val_len | key (key_len) | val (val_len)
```

If `fixed_key_size != 0` (LDIR of a fixed-key tree):
```
key (fixed_key_size) | val (fixed_val_size)
```
where `fixed_val_size` is **forced to 8** for LDIR (a child-page byte
offset, BE u64).

The leb128 encoding is the standard 7-bit-per-byte little-endian
variant: `value |= (byte & 0x7F) << shift; shift += 7; continue while
byte >= 0x80`.

## Per-tree configuration in the test archive

These were extracted from the seven L-SB records in
`example.tibx`:

| TLV slot | Name          | `fixed_key` | `fixed_val` | Has on-disk runs |
|----------|---------------|-------------|-------------|------------------|
| 0        | `lsm`         | 0           | 0           | no               |
| 1        | `data_map`    | 31          | 10          | yes (3 ctrees)   |
| 2        | `segment_map` | 8           | 32          | yes              |
| 3        | `tlv3` (name?)| 9           | 0           | yes              |
| 4        | `dedup_map`   | 0           | 0           | no               |
| 5        | `nlink_map`   | 4           | 132         | no               |
| 6        | `slices`      | 20          | 0           | yes              |
| 7        | `umap`        | 0           | 0           | no               |
| 8        | `notary`      | 0           | 0           | no               |

`data_map` is the only tree in the archive that uses **compact mode**
(LEAF pages with `fixed_key_size != 0`).  The other three trees with
on-disk runs (`segment_map`, `tlv3`, `slices`) all happen to have LDIR
roots that point at flat fixed-stride leaves.

## Worked example: smallest tree (slices)

```
TLV[6] 'slices'  fk=20 fv=0  root=13347623

Page 13347623 is an LDIR with 7 cells (8 children).  Each LDIR record
is `key (20) | child_offset (BE u64)`:
    key=000000000022771d000000000000000200000001  child=0xcbab20000
    key=0000000000439a81000000000000000200000001  child=0xcbab21000
    ...

The leaves (LEAF, encoding=1) decode via codec 1 LZ4 multi-block to
3326 (key, empty-value) entries total.  Sample first 5 entries:

    [0] key=0000000000000003000000000000000200000003  val=
    [1] key=0000000000001014000000000000000200000001  val=
    [2] key=000000000000203d000000000000000200000001  val=
    [3] key=0000000000003045000000000000000200000001  val=
    [4] key=000000000000404d000000000000000200000001  val=
```

The 20-byte key looks like `(slice_id BE u64, 0..0, role BE u32)`;
the empty value indicates this tree is used purely as a sorted key
set (a slice list / index, hence the `slices` tree name).

## Worked example: segment_map decode

```
TLV[2] 'segment_map'  fk=8 fv=32  root=13347532

LEAF entries decode as:
    seg_id=26  v_part1=0x2e000000  offset=0x25c8aa455  hash=035a1afd442f...
    seg_id=27  v_part1=0x53000000  offset=0x3ae409d38  hash=d57261c7f0e7...
    ...
```

The 32-byte value matches the `lsm_val2segment_info` layout in the
DLL (segment offset, length, hash, flags), although the exact field
order is documented separately in `RESEARCH_TIBX_LSM.md`.

## Reverse-engineering trace (Ghidra)

The decoder is reachable from `lsm_lookup_*` / `lsm_iter_*` via the
page-cache path:

* `lsm_page_read` (180045700)
* `FUN_180045510`  - validates header, allocates mem-tree, calls FUN_1800452f0
* `FUN_1800452f0`  - reads `on_disk_size = u32_BE(body+0x14) + 0x34`,
                     calls FUN_1800462f0 with `body+8`
* `FUN_1800462f0`  - dispatches on encoding byte (`body[0x0d]` from its
                     local frame, same as `body[5]` from the magic);
                     calls FUN_180046790 for codec 1
* `FUN_180046790`  - the multi-block LZ4 decoder
                     (uses `LZ4_decompress_safe_continue`)
* `FUN_180043d10`  - the post-decompress cell loop;
                     reads compact-mode group header from `*(uint*)param_2`,
                     dispatches to FUN_180046d00 for variable records,
                     calls `lsm_mem_tree_add` for each cell
* `FUN_180046d00`  - leb128 key_len + val_len for variable cells
* `FUN_180046530`  - header validate (matches against
                     `lsm_t[0x158 + 0x48*level]` for the per-layer
                     `key_size_param` check)

The encoding-byte legality check (`bVar4 < 2` after stripping the
encrypt high bit) is what limits codec values to 0 or 1; codec 2 is
not implemented in the DLL.

## Implementation

The Python implementation lives in
[`tibread/tibx/lsm_cells.py`](../../tibread/tibx/lsm_cells.py).  The
public entry point is `decode_page_cells(body, fixed_key_size,
fixed_val_size)` which returns `(LsmInnerHeader, [LsmCell])` where
each `LsmCell` carries `(key, value, alive)`.

`tibread/tibx/lsm.py` exposes higher-level walkers:
* `iter_tree_entries(reader, sb)` -- iterate every cell in the
  primary ctree of an `LsmSuperblock`.
* `walk_lsm_tree(reader, root, key_length, value_length)` -- iterate
  every LEAF cell reachable from a given root page.
