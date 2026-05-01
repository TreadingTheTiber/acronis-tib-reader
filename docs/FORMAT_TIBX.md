# `.tibx` (QARCH archive3) — RE notes index

This is the master table of contents for everything `tibread` has
reverse-engineered about Acronis True Image's `.tibx` format (TI 2020+).

The reader lives at `tibread/tibx/` and is exposed via the
`tib tibx-info` / `tib tibx-stat` / `tib tibx-verify` / `tib tibx-volumes`
CLI commands. See `README.md` for the supported-feature matrix and
`CHANGELOG.md` for per-release scope.

## High-level structure

A `.tibx` is a fixed-size 4 KiB-page store with:
- A `QARCH` ARCH header carrying a 19-entry TLV directory.
- Nine named LSM trees (`data_map`, `segment_map`, `dedup_map`,
  `nlink_map`, `slices`, `umap`, `keymap`, `notary`, plus the root
  `lsm`) walked via interior LDIR and leaf LEAF pages with a
  cell-encoded layout.
- Zstd-compressed segments addressed by `segment_map` lookups.
- Per-page CRC-32C with single-bit FEC on the page body.

It is **not** a SQLite database, despite earlier folklore.

## Canonical specs (consolidated, current)

| Doc | Topic |
|---|---|
| [`legacy/ARCHIVE3_HEADER_FORMAT.md`](legacy/ARCHIVE3_HEADER_FORMAT.md) | ARCH header layout (`QARCH` magic, version, hdr_size, hdr_version) |
| [`legacy/ARCHIVE3_TLV_DIRECTORY.md`](legacy/ARCHIVE3_TLV_DIRECTORY.md) | **Canonical** 19-entry TLV directory mapping (supersedes older per-tag notes) |
| [`legacy/ARCHIVE3_PAGE_VERIFY.md`](legacy/ARCHIVE3_PAGE_VERIFY.md) | Page CRC-32C + single-bit FEC scheme |
| [`legacy/ARCHIVE3_LSM_SUPERBLOCK.md`](legacy/ARCHIVE3_LSM_SUPERBLOCK.md) | L-SB superblock layout (per-tree ctree roots, sequence numbers) |
| [`legacy/ARCHIVE3_LSM_CELLS.md`](legacy/ARCHIVE3_LSM_CELLS.md) | Cell decoder for LDIR (interior) and LEAF pages |
| [`legacy/ARCHIVE3_PAGE_05.md`](legacy/ARCHIVE3_PAGE_05.md) | Page type `0x05` = Golomb-Rice dedup filter |
| [`legacy/ARCHIVE3_OPEN_FLOW.md`](legacy/ARCHIVE3_OPEN_FLOW.md) | Acronis's `.tibx` open / mount flow (from `product.bin`) |
| [`legacy/ARCHIVE3_CHAINS.md`](legacy/ARCHIVE3_CHAINS.md) | Backup chain mechanics (full + increments) |
| [`legacy/ARCHIVE3_ENCRYPTION.md`](legacy/ARCHIVE3_ENCRYPTION.md) | Encryption / `key != 0` segment wrapping (skeleton) |
| [`legacy/ARCHIVE3_CHUNK_INDEX.md`](legacy/ARCHIVE3_CHUNK_INDEX.md) | Chunk-index lookups via `data_map` / `segment_map` |
| [`legacy/ARCHIVE3_GHIDRA_SETUP.md`](legacy/ARCHIVE3_GHIDRA_SETUP.md) | Ghidra setup notes for analysing `product.bin` |

## Early recon (historical, kept for archaeology)

These predate the consolidation pass. They contain raw observations,
some hypotheses that turned out wrong, and the byte-level evidence that
fed the canonical specs above. Read these only if you're tracing the
RE history, not implementing against the format.

| Doc | Original scope |
|---|---|
| [`RESEARCH_TIBX.md`](RESEARCH_TIBX.md) | Top-level recon entry point |
| [`legacy/RESEARCH_TIBX_STRUCTURE.md`](legacy/RESEARCH_TIBX_STRUCTURE.md) | First pass at file structure |
| [`legacy/RESEARCH_TIBX_FILE_MAP.md`](legacy/RESEARCH_TIBX_FILE_MAP.md) | Page-type histogram + offsets |
| [`legacy/RESEARCH_TIBX_LSM.md`](legacy/RESEARCH_TIBX_LSM.md) | Early LSM-tree hypothesis |
| [`legacy/RESEARCH_TIBX_STRINGS.md`](legacy/RESEARCH_TIBX_STRINGS.md) | Strings extracted from sample files |
| [`legacy/RESEARCH_TIBX_EXPORTS.md`](legacy/RESEARCH_TIBX_EXPORTS.md) | Acronis SDK export-table walk |

## Implementation map

| Code | Doc(s) it implements |
|---|---|
| `tibread/tibx/format.py` | `ARCHIVE3_HEADER_FORMAT`, `ARCHIVE3_TLV_DIRECTORY`, `ARCHIVE3_PAGE_VERIFY` |
| `tibread/tibx/lsm.py` | `ARCHIVE3_LSM_SUPERBLOCK`, `ARCHIVE3_OPEN_FLOW` |
| `tibread/tibx/lsm_cells.py` | `ARCHIVE3_LSM_CELLS` |
| `tibread/tibx/segment.py` | `ARCHIVE3_CHUNK_INDEX` (segment side) |
| `tibread/tibx/disk_image.py`, `disk_adapter.py` | `ARCHIVE3_CHUNK_INDEX` (LBA-range bootstrap), `ARCHIVE3_OPEN_FLOW` |
| `tibread/tibx/encryption.py` | `ARCHIVE3_ENCRYPTION` (skeleton) |
| `tibread/tibx/reader.py` | top-level glue + CLI integration |

## Known unknowns

- Encrypted (`key != 0`) archives — spec'd as a skeleton, no sample.
- Chain walker — in flight in a separate agent (see `ARCHIVE3_CHAINS.md`).
- FUSE mount via the `NtfsVolume` shim — in flight in the disk-adapter
  integration agent.
- Write paths — out of scope; `tibread` is read-only.
