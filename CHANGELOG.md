# Changelog

All notable changes to `tibread` will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-30

First public release. Reverse-engineered end-to-end from `product.bin` (Acronis
True Image v23.5 build 17750) plus a representative sample of real-world `.tib`
files spanning TI 2013 through TI 2018+.

### Added

- **Sector-mode `.tib` reader (modern era, TI 2018+)**
  - 16-byte block preamble, 128 clusters per block.
  - Self-describing chunk-map discovery: 13-byte locator at TLV tag `0x9b`
    inside the metadata blob points to a single zlib-compressed chunk-map
    region in the post-data trailer.
  - Chunk-map decoder: zlib + column-major byte transpose + zigzag-delta
    decoding of 12-byte `{u64 offset, u32 length}` records, matching the
    layout of Acronis's `ExtraFileChunkMap` (`FUN_089839b0` in `openimg.cpp`).
- **Sector-mode `.tib` reader (legacy era, TI 2014/2015/2016)**
  - 8-byte block preamble, 64 clusters per block.
  - Format-era detected from the metadata blob (absence of TLV tag `0x9b`).
  - Chunk map is split across inline `SequentialChunkMap` records interleaved
    with the block stream; first open does a sequential scan to assemble it
    (~4 minutes for an 8 GB file), then caches the result in a `.idx` sidecar.
- **Very-legacy `.tib` detection (TI 2010–2013)**: `version=1`,
  `sector_size=0x1000`. Rejected with a clean error pointing the user at the
  TI 2018+ in-place migration path.
- **`.tibx` detection (TI 2020+)**: emits a clean error explaining that the
  QARCH archive container is a different format.
- **Pure-Python NTFS reader** (`tibread.ntfs.NtfsVolume`): MFT walking,
  directory listing, file reading, resident + non-resident attribute support.
- **Transparent NTFS-level decompression**:
  - **LZNT1** (NTFS attribute compression) — `tibread.lznt1`, decompressed
    on read; 64 KB compression units with an LRU cache.
  - **WOF / Compact OS Xpress** (4K / 8K / 16K chunks) — `tibread.xpress`,
    auto-detected via `IO_REPARSE_TAG_WOF` (`0x80000017`); reads of the
    (sparse) unnamed `$DATA` are rerouted to the `:WofCompressedData`
    alternate stream and decompressed transparently.
- **CLI**: `tib info`, `tib index`, `tib verify`, `tib ls`, `tib extract`,
  `tib mount`.
- **Mount integrations**: FUSE (Linux, `fusepy`) and WinFsp (Windows,
  `winfspy`, experimental).
- **Cached partition-direct index** (`.tib.idx` sidecar): O(1) random-access
  lookups on re-open.
- **Volume-header Adler32 verifier** (`tib verify`).

### Verified working

- **`example_full_b1_s1_v1.tib`** — 1.04 TiB, TI v23.5 build 17750
  (modern era). End-to-end recovery confirmed at ~99% file-count parity vs.
  the source `.xml` metainfo (200,000+ files extracted; remaining failures
  are Recycle-Bin entries with deallocated source clusters and old QuickTime
  `.mov` files with non-`ftyp` headers — genuine source-data issues, not
  reader bugs).
- **`legacy_example.tib`** — 8.18 GiB, TI 2013 era (legacy era,
  8-byte preamble, 64-cluster blocks). End-to-end recovery confirmed at 100%
  file-count parity. Inline chunk-map scan completes in ~4 minutes; cached
  re-opens are instant.

### Known limitations

- **`.tibx` (TI 2020+)** — not supported. Different container format
  (SQLite-backed QARCH archive); use a different tool.
- **Very-legacy `.tib` (TI 2010–2013, `version=1`)** — rejected with a
  clean error. Workaround: open once in TI 2018+ to migrate in place,
  then re-run `tibread`.
- **Encrypted `.tib`** — spec written (AES-CBC + PBKDF2 / SHA-stretch /
  scrypt), decoder skeleton only. Needs a sample to finish.
- **Multi-volume splits** (`_v1.tib`, `_v2.tib`, …) — detection only;
  open the *last* volume to read metadata. Span-spanning reads not yet
  implemented.
- **Incremental / differential chains** — spec written, not implemented.
  Needs sidecar `mms.db` (catalog) for chain reconstruction.
- **WOF / LZX-compressed files** (algorithm 1) — not implemented; rare
  in practice. WOF / Xpress (algorithms 0/2/3) is supported.
- **Filesystem-mode `.tib`** (magic `0x8F5C36C6` v1, `0x44686EB4` v2) —
  format spec'd in `docs/FORMAT.md`, not yet implemented.
- **Tape-archive `.tib`** (footer magic `0x179631B4`) — out of scope.

[0.1.0]: https://github.com/yourname/tibread/releases/tag/v0.1.0
