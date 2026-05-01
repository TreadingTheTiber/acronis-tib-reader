# Archive3 `data_map` extent index (TLV[1])

This note documents the on-disk format of the **data_map** LSM tree of
an Acronis archive3 (`.tibx`) file.  The data_map is the index that
maps every **(volume_id, source_byte_offset)** tuple to the
**(segment_id, extent_index)** in which the corresponding bytes are
stored.  Together with the segment_map (TLV[2]) it is the bridge
between "logical disk byte X of volume V" and the compressed/encrypted
SG segment that actually holds those bytes.

The format was recovered by decompiling `archive3.dll` and observing
the four small functions that move ext records between their on-disk
form and the in-memory `dmap_ext` / `dmap_ext_info` structs:

* `lsm_key2dmap_ext`     — `0x1800485d0`  (decode 31-byte key)
* `dmap_ext2ondisk`      — `0x180048240`  (encode 31-byte key)
* `lsm_val2dmap_ext_info`— `0x180048640`  (decode 10-byte value)
* `dmap_ext_info2ondisk` — `0x180048280`  (encode 10-byte value)

The Python implementation lives in `tibread/tibx/data_map.py` and is
covered by `tools/tests/test_tibx_data_map.py`.

## Where it lives

The data_map is the LSM tree at **TLV slot index 1** in the archive
header's TLV directory.  Like the other LSM trees (slice_map at TLV[5],
segment_map at TLV[2]), it consists of an L-SB superblock plus a
ctree of LDIR/LEAF pages.  Walking is identical to the rest of the
LSM machinery — see `ARCHIVE3_LSM_SUPERBLOCK.md` and
`ARCHIVE3_LSM_CELLS.md` — so the only thing this document covers is
the **(key, value) cell payload format**.

## Key — 31 bytes, big-endian

```
+0x00 .. +0x08    u64  volume_id          # 10 = main partition stream;
                                          #   2..12 are small metadata streams
+0x08 .. +0x10    u64  source_byte_off    # source-disk byte offset within volume
+0x10 .. +0x13    u24  extent_length      # length of this extent in bytes
+0x13 .. +0x17    u32  field3             # always 0x00000002 in observed
                                          #   archives (record kind / version)
+0x17 .. +0x1F    u64  extent_id          # global monotonically-increasing
                                          #   extent id (debug/back-pointer use)
```

Total = 31 bytes.  Note the **u24** (3-byte) length field — this
matches the on-disk layout produced by `dmap_ext2ondisk`, even though
the in-memory struct widens it to a 32-bit int.  An extent is
therefore at most 16 MiB long.

### Why the lex-sort property matters

Because the key starts with `volume_id` (BE u64) followed by
`source_byte_off` (BE u64), the lexicographic byte-order on raw key
bytes is identical to ordinal order on `(volume_id, source_byte_off,
...)`.  This is what makes a binary-search "lookup less-or-equal"
correct: the extent that **covers** byte `X` of volume `V`, if any, is
the largest entry whose `(volume_id, source_offset) <= (V, X)`, and
its `[source_offset, source_offset + extent_length)` range is then
checked for containment.

This is exactly what `data_map.lookup_le` does.

## Value — 10 bytes, big-endian

```
+0x00 .. +0x08    u64  segment_id     # key into segment_map (TLV[2])
+0x08 .. +0x0A    u16  extent_index   # 0,1,2,... for multi-extent segments;
                                      #   0xFFFF when the extent fills the
                                      #   entire segment (typical for big
                                      #   stream-10 extents)
```

Total = 10 bytes.  `extent_index = 0xFFFF` is a sentinel meaning "this
extent fills its entire segment" — no per-segment indexing required.
Smaller / packed segments use `extent_index = 0, 1, 2, ...` to
disambiguate which extent in the segment is being referred to.

## Sample lookups against `Jmicron 0102.tibx`

These are the empirically-verified ground-truth lookups pinned by
`tools/tests/test_tibx_data_map.py`:

| Volume | Source byte | Result                    |
|--------|-------------|---------------------------|
| 10     | 0x00000000  | seg_id `0x58` (MBR extent)|
| 10     | 0x00100000  | seg_id `0x5d`             |
| 99     | 0x00000000  | None (volume not present) |

Volume 10 is the main partition stream of the archived disk; bytes
`[0, ~1 MiB)` are the legacy MBR + 1 MiB Windows alignment slop, which
is why the very first extent points at a small dedicated segment
(0x58) rather than the larger ones used for the rest of the volume.

## Public Python surface

```python
from tibread.tibx import (
    DataMapKey,        # decoded 31-byte key
    DataMapValue,      # decoded 10-byte value
    DataMapEntry,      # (key, value) pair, with .covers(volume_id, byte)
    decode_key,        # bytes(31) -> DataMapKey
    decode_value,      # bytes(10) -> DataMapValue
    load_extents,      # TibxReader -> sorted List[DataMapEntry]
    lookup_le,         # (entries, volume_id, byte_offset) -> Optional[DataMapEntry]
)
```

`encode_key` is also exposed at `tibread.tibx.data_map.encode_key`
(matching `dmap_ext2ondisk`); it is used in tests to assert
encode/decode symmetry but is **not** required for read-only archive
access.

## Cross-references

* `ARCHIVE3_LSM_SUPERBLOCK.md` — L-SB header layout, ctree pointer
  semantics; data_map is reached via TLV[1].
* `ARCHIVE3_LSM_CELLS.md` — per-page cell-stream encoding that wraps
  every (key, value) pair in a LEAF page.
* `ARCHIVE3_TLV_DIRECTORY.md` — definitive list of TLV slots; data_map
  is slot 1, segment_map is slot 2, slice_map is slot 5.
* `RESEARCH_TIBX_LSM.md` — narrative recovery notes for the broader
  LSM walker.

## Ghidra anchors (archive3.dll)

| Symbol                   | RVA          | Role                       |
|--------------------------|--------------|----------------------------|
| `lsm_key2dmap_ext`       | `0x1800485d0`| decode 31-byte key         |
| `dmap_ext2ondisk`        | `0x180048240`| encode 31-byte key         |
| `lsm_val2dmap_ext_info`  | `0x180048640`| decode 10-byte value       |
| `dmap_ext_info2ondisk`   | `0x180048280`| encode 10-byte value       |
