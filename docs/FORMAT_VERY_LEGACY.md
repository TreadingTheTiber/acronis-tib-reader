# FORMAT_VERY_LEGACY.md — the third (oldest) `.tib` generation

Companion to `FORMAT.md` (TI 2018+ "modern") and `FORMAT_LEGACY.md` (TI
2014–2017 "legacy"). This document covers the **even-older** `.tib`
generation — files that the TI 2018+ binary does NOT read directly via
SequentialImageStream, but instead routes through a **container migration**
function that rewrites the file's container envelope into the modern shape
before the rest of the engine sees it.

Source unit: `k:/8029/backup/container_convert.cpp`. Function:
`ConvertFromLegacyFormat` (mangled symbol string at
`product.bin:0x095bdee8`). Entry point at line 0x65 of that source.

> **Confidence note** — every concrete byte/field below is "confirmed via
> decompilation" of `FUN_091f6780`. The era attribution and the precise
> meanings of the secondary fields (slice descriptor, 0x548-byte block) are
> "inferred from naming and structural context"; absent a sample very-legacy
> `.tib` to test against, none of this has been validated against bytes on
> disk. Treat the byte layouts as "Acronis's runtime expectation", not as
> "verified empirical .tib spec".

---

## TL;DR

- `ConvertFromLegacyFormat` is a **fallback** path. The two callers
  (`FUN_0918c850` and `FUN_0918cff0` in the unnamed `container_open*` family)
  first try the **modern** container opener; if it throws an exception with
  `error_info[1] == 0x40011` (caller 1) or `== 0x2870001` (caller 2), they
  re-attempt by calling `ConvertFromLegacyFormat`.
- The conversion is **structural, not data-rewriting**: it reads the
  very-legacy 32-byte volume header + a slice-descriptor table, validates
  Adler32 over each, and then constructs a fresh **modern container** via
  `AppendContainerArchive` (`FUN_091ed500`, source `container_api.cpp`).
  The new modern container REFERENCES the original file's payload
  in-place and exposes it through the modern container API.
  The original file is opened read/write but only the **container
  envelope** (header + slice table) is rewritten in modern form.
- The exact gate at line 0x7f of `container_convert.cpp`:

  ```c
  if (header.magic       != 0xA2B924CE) throw;   // shared volume-header magic
  if (header.hdr_len     != 0x20)       throw;
  if (header.version     != 0x0001)     throw;   // <<<<<< the discriminator
  if (header.flags_at_14 != 0x00000001) throw;
  if (header.sector_size != 0x00001000) throw;   // 4 KiB sector
  ```

- Adler32 (Acronis's `FUN_08b6f260`, modulus 0xfff1) is then validated over
  the 32-byte header with `header[0x18..0x1c]` (the stored Adler32 slot)
  zeroed during compute. This is the **same Adler32 layout** the modern
  and TI 2014 legacy formats use, just at a different `version` value.
- The very-legacy file then carries a **slice descriptor table** at the
  modern-style "metadata" position. Each slice descriptor is **0x548 bytes
  (1352)** with a **0x28-byte (40) preamble that starts with `[size==0x28,
  Adler32, ...]`** (validated by `FUN_091f5b50` line 6 — `if (param_1[2] ==
  0x28 && param_1[3] == 0x548)`). The Adler32 covers `param_1[1..0x3FF]`,
  i.e. the 4 KiB minus the leading u32 size and u32 Adler32.
- The slice loop steps in **0x40000-byte (256 KiB) increments** — that is
  the very-legacy block stride. Each iteration: read 4 KiB at
  `slice_offset`, validate Adler32 over those 4 KiB, advance to the next
  slice. The final slice descriptor encodes the partition / image total
  size in 64-bit form (`uVar9 = (slice_count - 1) * 0x40000 + ...`).
- After the slice table is parsed, a **new modern container archive** is
  constructed in-place via `AppendContainerArchive` and finalised via
  `FUN_091f1bd0` (likely the modern container "close+commit"). The
  ConvertFromLegacy-call returns the freshly-minted modern container
  pointer to the caller, which then proceeds as if the file had been
  modern from the start.

---

## Format-era taxonomy (all three .tib generations TI 2018+ supports)

| Era | Marker | Hdr `version` | Hdr `+0x1c` | Block stride | Trailer family | Reader path |
|---|---|---|---|---|---|---|
| **Modern** (TI 2018+, builds 17000+) | TLV tag `0x9b` present in metadata blob | 0 | 0x20 (block_align=32) | 512 KiB (128 clusters × 4 KiB) | 41-byte trailer body + 0x94E18A2B magic + 48-byte footer | `HybridImageStream::ctor` (FUN_0898bbd0) → `HybridChunkMap`/`ExtraFileChunkMap`/`DiskChunkMap` |
| **Legacy** (TI 2014–2017, builds 16000–16xxx) | TLV tag `0x9b` ABSENT in metadata blob | 0 | 0x20 (block_align=32) | 256 KiB (64 clusters × 4 KiB) | 16-byte mini-trailer + 32-byte mirrored header (no magic) | `SequentialImageStream::ctor` (FUN_08977a70) → `SequentialChunkMap` |
| **Very-legacy** (this doc; TI 2013 and earlier — see era discussion below) | header `version == 1`, `+0x1c == 0x1000` | 1 | 0x1000 (sector_size=4096) | 256 KiB (slice descriptor stride 0x40000) | 0x548-byte slice descriptor table (1352 B per slice) | **`ConvertFromLegacyFormat`** (FUN_091f6780) wraps the file as a modern container; afterwards the modern reader takes over |

### Detection algorithm (recommended)

```
read header[0..32]
if header.magic != 0xA2B924CE: not a .tib
if header.hdr_len != 0x20:     unsupported (TI Mac variants, possibly)
adler32 = adler32_acronis(header[0..32] with [0x18..0x1c] zeroed)
if adler32 != header[0x18..0x1c]: corrupt or unsupported
case header.version:
  0:  → check `tag 0x9b` in metadata blob
        present → MODERN
        absent  → LEGACY (sequential)
  1:  → if header.flags_at_14 == 1 and header.sector_size == 0x1000
          → VERY-LEGACY  (needs ConvertFromLegacyFormat to convert envelope)
        else: unsupported
  other: unsupported (Mac? unknown future variant?)
```

Note that `version == 1` was claimed in the older agent's
`FORMAT_LEGACY.md` to be the "Mac variant" marker. That note was based on
hearsay; the Ghidra evidence here shows `version == 1` is unambiguously the
**very-legacy Windows** format gate, because `+0x1c == 0x1000` (the page
size) is checked alongside it and there is no Mac-platform branch in the
function. The Mac variant (if it exists) presumably uses different magic,
not different `version`.

---

## Detailed structural walk of the very-legacy header

```
offset  size    field          value(s) checked by ConvertFromLegacyFormat
0x00    4       magic          0xA2B924CE
0x04    2       hdr_len        0x0020
0x06    2       version        0x0001                ← the gate
0x08    8       (read; unused) (preserved across the convert)
0x10    4       (read; unused)
0x14    4       flags          0x00000001            ← the gate
0x18    4       adler32        Adler32(header,zeroed[0x18..0x1c])
0x1C    4       sector_size    0x00001000            ← the gate
```

Total = 32 bytes, identical OUTER size to modern/legacy headers.

After the header, the file body contains a sequence of **slice descriptors**
(at 4 KiB-aligned positions; the loop seeks each in turn and reads 0x1000
bytes per descriptor). Each descriptor:

```
offset  size    field
0x000   4       size_of_descriptor   = 0x28 (40)         ← FUN_091f5b50 line 6
0x004   4       adler32              over [0x008..0x1000]
0x008   4       size_of_payload      = 0x548 (1352)      ← FUN_091f5b50 line 6
0x00C   4       (unknown)
0x010 .. 0x1000 payload                                   (4080 bytes incl. headers)
```

Validation: `FUN_091f5b50` zero-extends the 40-byte preamble, computes
Adler32 over `[0x4..0x1000]` (the 4 KiB minus the leading 4-byte size and
4-byte Adler32 fields), and compares against `[0x4..0x8]`. If equal it
returns `[0x4..0x8]` (the stored Adler32) as a "this slice is valid" flag;
zero otherwise.

The 1352-byte (`0x548`) payload is most likely a **slice/chunk descriptor**
for one fixed-size block of the on-disk image. Acronis emits such
descriptors at file offsets corresponding to multiples of `0x40000` (256
KiB), strongly suggesting a fixed 256 KiB image-block layout. (This is
characteristic of TI True Image 11 / 2009 / 2010-era backup files, which
used 256 KiB compressed blocks with a per-block descriptor for restart on
crash.)

---

## How the conversion proceeds

Sketch of `FUN_091f6780` after gate validation:

```c
// 1. Slurp the slice list by walking the file forwards.
slices = vector<SliceDesc>;
local_30dc = open_file_handle(input_file);
local_201c = read_one_4kb_slice_at(0);             // first slice header
slices.push(local_201c);
while (true) {
    next_offset = read_next_slice_offset(slices.last());
    if (next_offset == 0x40000000) {               // slice-table sentinel
        // append modern-archive entry, then break
        new_slice_via_modern_writer(...);
        break;
    }
    if (next_offset >= 0x1000 && next_offset != 0x40000000) {
        if (next_offset > 0x40000000) error;
        slices.push(read_one_4kb_slice_at(next_offset));
    } else {
        // slice-table is consumed; fall through to converter body
    }
}

// 2. Build a NEW MODERN container header in place (rewrite header bytes 0..32).
local_3060 = adler32(header, zeroed[0x18..0x1c]);
write_header_at_offset_0(new_modern_header_struct);

// 3. For each surviving (uVar6 - 1) slice, write a modern slice trailer
//    sized exactly 0x40000 bytes downstream.
for slice in slices[..n-1]:
    write_modern_slice_trailer_at(slice.modern_offset);

// 4. Final 0x38-byte modern descriptor block:
//    {1, 0x38, 0x548, 3, 0, ..., (uVar9 + uVar15 = 64-bit total size in 4 KiB pages)}
local_3048 = 1; local_3044 = 0x38;
local_3040 = 0x548; local_303c = 3; local_3038 = 0;
local_3030 = total_pages_lo;  local_302c = total_pages_hi;
adler32(local_3054[0]) = adler32_acronis(local_2018, 0xffc);
write_descriptor_at(eof_aligned);

// 5. Construct a modern container ARCHIVE (FUN_091edd50 ctor wrapped by AppendContainerArchive).
modern_archive = operator_new(0xfc);
FUN_091edd50(modern_archive, file_handle, ?, &input_archive_holder, /*append=*/1);
FUN_091f1bd0(modern_archive);                      // commit/finalize
modern_archive.vtable[0x28]();                     // close
return modern_archive;                             // caller receives a modern handle
```

**Net effect**: the input `.tib` is opened, its 32-byte header and
slice-table are rewritten in modern form (preserving the 64-bit total-size
field), and the resulting file is then handed to the modern reader. After
conversion, the file is no longer "very-legacy" on disk — it is now a
modern container. **This is a one-way, in-place migration.**

This means TI 2018+ MUTATES very-legacy `.tib` files when it opens them.
A reader that wants to support read-only restoration of very-legacy files
without mutation must either:

- Implement the converter logic in memory (read the legacy slice table,
  synthesize a modern container view), OR
- Refuse to open such files, requiring the user to first open them once
  in a writable copy with TI 2018+ to migrate them.

---

## Era identification

The modern format = TI 2018 (build 17750+ ≈ v23.5).
The legacy format = TI 2014 (build ~16500), confirmed via miner1's
embedded XML metainfo `<productinfo name="True Image"><version major="16"
minor="0"/><build number="6514"/></productinfo>`.

Working backwards: TI 2013 = build 15xxx, TI 2012 = build 14xxx, TI 2011 =
build 13xxx, TI 2010 = build 12xxx, TI 2009 = build 11xxx, TI 11 (Home) =
build 8xxx (released 2007). The "256 KiB compressed block + per-slice
descriptor" pattern with `version=1, sector_size=4096` is consistent with
**TI 2010 / TI 2011 / TI 2012 / TI 2013** — i.e. Acronis True Image Home
2010-2013, build numbers 12xxx-15xxx.

The presence of `flags_at_14 == 1` as a fixed gate suggests this format had
exactly one flag value Acronis ever shipped — consistent with a single
mainline product variant of that era. Earlier formats (TI 8/9/10, builds
4xxx-7xxx, ca. 2003-2006) likely have a different magic word entirely
(those predate the `0xA2B924CE` magic, which appears to date from TI 2010
based on the absence of older format markers in the `CheckVolumeHeader`
binary). TI 2018+ does NOT support those even-older formats; it would fail
at the magic check.

**Best estimate**: the very-legacy format covers `.tib` files from
**Acronis True Image Home 2010 through 2013**, builds 12000–15999.

---

## Worth implementing for the GitHub project?

**Recommendation: no, unless a sample file appears.**

Reasons:

1. **No sample available.** Without a real very-legacy `.tib`, none of the
   slice-descriptor field semantics can be validated. The Ghidra-derived
   structure layout above is enough to detect such a file, but parsing the
   1352-byte descriptors requires either bytes to test against, or
   considerably more reverse-engineering effort to map field meanings.
2. **Population is tiny.** TI 2010–2013 era backups are 13–16 years old
   and almost universally either restored (and discarded), upgraded
   through TI's own migration path (in which case they are now modern or
   legacy on disk), or lost. The user population needing read-only
   recovery from this era's `.tib` files is essentially zero.
3. **Acronis's own approach is "migrate, then open."** TI 2018+ does not
   actually READ very-legacy files; it converts them. A clone of that
   strategy in the GitHub project would mean implementing the writer side
   too, which is far more work than the reader side.
4. **The supported-era taxonomy is the deliverable.** Documenting that
   "the GitHub project supports modern + legacy" while explicitly listing
   "very-legacy is detected but not parsed; please use Acronis True Image
   2018+ to migrate first" is a complete, defensible position for a
   third-party reader.

If a sample file does appear, the code path is well-isolated: detect via
the gate above, then dispatch to a `convert_in_memory()` routine that
constructs a synthetic modern container view in RAM. The Ghidra anchors
listed below should make incremental field-discovery tractable in 1–2
days of focused work.

---

## product.bin Ghidra anchors (very-legacy)

| Address | Symbol | Source / Role |
|---|---|---|
| `0x091f6780` | `ConvertFromLegacyFormat` | `container_convert.cpp` line 0x65; the entry point. Gate, header validation, slice walk, modern-container construction. |
| `0x091f5b50` | (anonymous) | `container_convert.cpp`; validates a 4 KiB slice descriptor: `[size==0x28][adler32][size==0x548][...]` then Adler32 over `[0x4..0x1000]`. |
| `0x091f5be0` | `EnsureFileIsMissing` | `container_convert.cpp` line 0x37; precondition helper used during conversion (verifies output slot is unused). |
| `0x091f5f00` | (anonymous) | `container_convert.cpp`; thin wrapper around the `Write` virtual at `+0x29` of `../include/file/file.h`. Used by the conversion to write the new modern header bytes. |
| `0x091f6740` | (anonymous) | `container_convert.cpp`; vector push-back helper for the slice list. |
| `0x091f6250` | (anonymous) | `container_convert.cpp` ~line 0x4a; pre-conversion validator (reads file size, virtual-method dispatch). |
| `0x091ed500` | `AppendContainerArchive` | `container_api.cpp` line 0x32; constructs the new modern container that wraps the converted file. |
| `0x091edd50` | (modern container ctor) | `container_api.cpp`; allocator+initializer for the 0xfc-byte modern container struct. |
| `0x091f1bd0` | (modern container finalize) | sets `+0x26 = 1`, calls modern-archive setup at `+0x9c` and `+0xa0`. |
| `0x08b6f260` | `Adler32` | Acronis's standard Adler32 (modulus 0xfff1). Same routine the modern + legacy formats use. |
| `0x0918c850` | (anonymous) | First caller. Tries modern open; on exception with `error_info[1] == 0x40011`, falls back to ConvertFromLegacyFormat. |
| `0x0918cff0` | (anonymous) | Second caller. Tries modern open; on exception with `local_28[1] == 0x2870001`, falls back to ConvertFromLegacyFormat. |
| `0x094de154` | string | `"k:/8029/backup/container_convert.cpp"` — the source-file string baked into all exception throws. |
| `0x095bdee8` | string | `"ConvertFromLegacyFormat"` — the function-name string baked into exception throws. |
| `0x094f0a0f` | string | `"legacy_file_format"` — orphan tag string with no direct xref; possibly used as a category label by the error-info system but not directly in this function. |

---

## Confidence summary

| Finding | Source |
|---|---|
| Gate is `magic + hdr_len + version==1 + flags==1 + sector_size==0x1000` | **Decompiled** (FUN_091f6780 line ~120 of decompiled output, matching source line 0x7f) |
| Adler32 over header with stored slot zeroed | **Decompiled** (FUN_08b6f260 calls in FUN_091f6780) |
| Slice descriptor is `[u32 size=0x28][u32 adler32][u32 size=0x548][u32 ?][1352 bytes payload + 0x4-padding]` | **Decompiled** (FUN_091f5b50 lines 6, 14) |
| 256 KiB block stride | **Inferred** (the 0x40000 multiplier on slice index in the final size computation; not yet verified against bytes) |
| Modern-container construction via AppendContainerArchive | **Decompiled** (FUN_091ed500/FUN_091edd50 pair, source line 0x32 of container_api.cpp) |
| One-way mutation (file is rewritten on read) | **Inferred** from the absence of any "discard new container, return slices directly" branch in FUN_091f6780 — every branch terminates by either throwing or constructing a new container. Additionally, `Write` (FUN_091f5f00 → file.h `Write` at line 0x29) is called multiple times during the conversion. |
| Triggers via exception 0x40011 / 0x2870001 from modern opener | **Decompiled** (FUN_0918c850, FUN_0918cff0 dispatchers) |
| Era = TI 2010–2013 | **Inferred** from build-number arithmetic relative to known modern (17000+, TI 2018+) and legacy (16500, TI 2014) eras; no decoded version string in this binary unambiguously names the very-legacy era. |
| Slice-payload field semantics within the 0x548 bytes | **Unknown** — would require sample bytes to decode. |
