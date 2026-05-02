# Contributing to tibread

Thanks for your interest in extending `tibread`. The project's reverse-
engineered surface is small enough to keep in your head, and most useful
extensions cluster around the same handful of files.

## Project layout

```
tibread/
├── reader.py              Low-level block reader (TibReader); reads TIBIDX02/03 indices
├── chunkmap_locator.py    Format-era detection + modern chunk-map locator
├── chunkmap.py            Modern chunk-map decoder
├── chunkmap_legacy.py     Legacy inline-SequentialChunkMap discovery + decoder
├── indexer.py             build_index(): top-level entry point; dispatches modern/legacy
├── verify.py              Volume-header Adler32 + magic-word validator
├── ntfs.py                Pure-Python NTFS reader (NtfsVolume)
├── lznt1.py               LZNT1 decompressor (NTFS attribute compression)
├── xpress.py              Xpress LZ77+Huffman decompressor (WOF / Compact OS)
├── metadata.py            TLV parser for the trailing metadata blob
├── mount/fuse.py          FUSE mount (Linux)
└── cli.py                 `tib` command-line entry point

docs/
├── FORMAT.md              Modern (TI 2018+) sector-mode spec — user-facing
├── FORMAT_LEGACY.md       Legacy (TI 2014/2015/2016) sector-mode spec — user-facing
├── FORMAT_VERY_LEGACY.md  TI 2010-2013 (rejected; documented for completeness)
├── RE_HISTORY.md          Reverse-engineering play-by-play
├── CONTRIBUTING.md        (this file)
└── legacy/                Per-investigation RE notes (historical; not the spec)
```

## Adding support for a new format era

The TI 2014 legacy support added in commit `2e2eeb7` is the canonical example
of how to extend `tibread` to a new sector-mode era. The pattern:

1. **Detect the era.** Add detection logic in
   `chunkmap_locator.detect_format_era` (and, if a fail-fast magic check is
   useful, in `verify._read_volume_header`). Return a string label
   (`"modern"`, `"legacy"`, etc.). For TI 2014 the discriminator is the
   absence of TLV tag `0x9b` in the metadata blob; for very-legacy it's
   `version == 1 + sector_size == 0x1000`.

2. **Write a chunk-map decoder.** Most variants share the matrix-transpose
   + zigzag-delta + zlib record encoding (see `chunkmap.py`); copy and
   adjust for the new variant's record size, TLV tags, and on-disk
   placement. For TI 2014 this is `chunkmap_legacy.py`, which had to
   discover inline records embedded in the block stream.

3. **Update `indexer.py`'s dispatch.** `build_index()` already branches on
   `detect_format_era()`; add a new branch and a `_build_index_<era>()`
   helper that emits records compatible with `TibReader`.

4. **Bump the index format if geometry changes.** TIBIDX03 adds
   `clusters_per_block` and `preamble_len` u32 fields after the standard
   header, so the same on-disk index layout works for both modern (16-byte
   preamble + 128 cpb) and TI 2014 legacy (8-byte + 64 cpb). If you need
   to record additional per-file geometry, either reuse the
   `reserved_flags` u64 in TIBIDX03 or bump to TIBIDX04.

5. **Wire geometry into `reader.py`.** `TibReader.__init__` reads
   `clusters_per_block` and `preamble_len` from the TIBIDX03 header (or
   defaults from constants for TIBIDX02). Make sure any new geometry is
   propagated correctly.

6. **Add a clean error path for variants you can't read.** Raise
   `chunkmap_locator.UnsupportedTibFormat` with a human-readable
   explanation; the CLI catches it and exits with code 2.

7. **Document it.** Write a user-facing spec in `docs/`. Move investigation
   notes to `docs/legacy/` (or a parallel subdir) once the spec is stable.

8. **Test end-to-end.** At minimum: `tib info`, `tib verify`, `tib ls`, and
   the programmatic `from tibread import open_tib; open_tib(...).list_dir("")`
   path. Confirm the cached `.idx` round-trips (delete it, re-run, check it
   regenerates identically).

## Open RE work

The following are reasonably well-scoped and still-useful next steps:

### Filesystem-mode `.tib` (v1 + v2)

Magics `0x8F5C36C6` (v1) and `0x44686EB4` (v2) — see `verify.py` for the
detection. These are an entirely different layout from sector-mode
(per-file rather than per-block backups). The format isn't documented
here yet; would need a fresh RE pass against a sample.

### Encrypted `.tib`

Spec is in `docs/FORMAT.md` (Encryption section). AES-CBC + one of three
KDFs (SHA256-stretch, PBKDF2-HMAC-SHA256, scrypt). A skeleton decoder
exists historically in `decrypt_tib.py`; needs a sample encrypted `.tib`
to nail down the last 2-3 envelope bytes and validate end-to-end.

### `.tibx` (TI 2020+)

Different container entirely (SQLite-backed). Currently rejected with a
clean error in `chunkmap_locator._read_volume_header`. Adding read support
is a non-trivial new project rather than an incremental extension.

### NTFS LZNT1 / Xpress wire-up

`tibread.lznt1` and `tibread.xpress` both have working pure-Python
decompressors. Neither is currently invoked from `NtfsVolume.read_file`
when an attribute is compressed (LZNT1) or WOF-stored (Xpress). The
integration plan: in `ntfs.py`, when reading a non-resident attribute,
check the attribute's compression flag / WOF reparse point and route
through the appropriate decompressor before returning the data.

### TI 2014 residual region

The ~1.9 MB region after the MD5 dedup manifest in legacy `.tib` files
is a multi-stream container that hasn't been fully decoded; see
`FORMAT_LEGACY_RESIDUAL.md`. Not load-bearing for reading.

### Multi-volume splits

`_v1.tib`, `_v2.tib`, ... — currently detected only. To support reading,
the indexer needs to (a) enumerate sibling files, (b) open the LAST
volume to get the chunk map, (c) translate file-offsets in the chunk map
back to `(volume_index, offset_within_volume)` pairs.

## Running the QC battery

The end-to-end QC commands are documented at the top of the README. For
internal tests during development:

```bash
# Modern format
python -m tibread.cli info  /path/to/storage_full_b1_s1_v1.tib
python -m tibread.cli verify /path/to/storage_full_b1_s1_v1.tib
python -m tibread.cli ls    /path/to/storage_full_b1_s1_v1.tib | head

# Legacy format (slow first open)
python -m tibread.cli info  /path/to/legacy_example.tib

# Programmatic
python -c "from tibread import open_tib; v=open_tib('...'); print(v.list_dir(''))"
```

The cached `.idx` sidecar is a deterministic function of the `.tib`'s
content; if you change `chunkmap_legacy` or `indexer`, delete the `.idx`
to force a rebuild.

## Ghidra / binary RE setup

Most of the on-disk format was derived by decompiling Acronis True Image's
`product.bin` in Ghidra. The function anchors are listed in each
`FORMAT*.md` doc.

If you're picking up where a previous agent left off, the relevant
project file is the one shared across the swarm; ask the maintainer.
The "re-host" workflow notes (which Ghidra MCP setup, how to spawn a
fresh agent against a function address, etc.) live in `CLAUDE.md` at the
repo root.

For one-off lookups: the binary is a stripped Linux ELF; symbols are
re-derived from RTTI + string xrefs. Useful starting points:

- `0x08973290` — `ImageStream` constructor / format dispatcher
- `0x089839b0` — `ExtraFileChunkMap::ctor` (modern chunk map)
- `0x08982090` — `SequentialChunkMap::ctor` (legacy chunk map)
- `0x08983090` — `DiskChunkMap::ctor` (whole-disk-image variant)
- `0x091f6780` — `ConvertFromLegacyFormat` (TI 2010-2013 migration)
- `0x082160c0` — `CheckVolumeHeader` (magic + Adler32)
- `0x08b6f260` — Acronis's Adler32 (bog-standard zlib)

## Code style

- Pure stdlib by default. Optional `numpy` for hot loops only (the chunk-map
  decoder accepts a pure-Python fallback). Optional `fusepy` / `winfspy`
  for mounting.
- Type hints on public APIs. `from __future__ import annotations` everywhere
  so we work on Python 3.9+.
- Errors that the user can act on go through `UnsupportedTibFormat` (caught
  by the CLI). Internal bugs should raise `ValueError` / `RuntimeError`.
- Keep the on-disk format docs in sync with the code. If you change a
  parser, update the spec.
