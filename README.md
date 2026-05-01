# tibread

[![CI](https://github.com/USER/tibread/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/tibread/actions/workflows/ci.yml)
[![Lint](https://github.com/USER/tibread/actions/workflows/lint.yml/badge.svg)](https://github.com/USER/tibread/actions/workflows/lint.yml)

**Status:** `tibread 0.1.0` — works end-to-end on Acronis True Image
2013–2018+ sector-mode `.tib` files. See [CHANGELOG.md](CHANGELOG.md) for
the full feature matrix.

**Pure-Python read-only access to Acronis True Image `.tib` backups.**
Mount, list, and extract files from `.tib` files without Acronis software.

This was originally built to recover a 1 TB backup from a long-discontinued
Acronis True Image installation. It now supports any sector-mode `.tib`
self-describingly — no per-file constants, no manual offset hunting.

### Benchmarks

| File | Size | Era | First-open (cold, builds index) | Re-open (cached) | Recovery rate |
|---|---|---|---|---|---|
| `STORAGE_full_b1_s1_v1.tib` | 1.04 TiB | TI v23.5 (modern) | ~3 min (chunk-map decode + NTFS index) | <10 s incl. NTFS load | ~99% (200,000+ files vs. source XML metainfo) |
| `miner1_default_full_b1_s1_v1.tib` | 8.18 GiB | TI 2013 (legacy) | ~4 min (sequential inline-chunk-map scan) | <1 s | 100% (NTFS file-count parity) |

The "remaining 1%" on `STORAGE` is genuine source-data damage (Recycle-Bin
entries with deallocated source clusters, old QuickTime `.mov` files with
non-`ftyp` headers), not reader bugs. See `docs/RE_HISTORY.md` for the
full validation account.

## Features

- **Read sector-mode `.tib` backups** — the common full-disk image format,
  both the modern variant (TI 2018+, 16-byte preamble + 128-cluster blocks)
  and the legacy variant (TI 2014/2015/2016, 8-byte preamble + 64-cluster
  blocks).
- **Self-describing** — no hardcoded offsets or sizes. The format era is
  detected from the backup's own metadata blob (TLV tag `0x9b` presence
  test), and the chunk map is decoded from there.
- **Pure Python** — no Acronis libraries, no compiled extensions, no dependencies
  on `ntfs-3g`. Optional `numpy` makes index-building faster.
- **NTFS filesystem reader built in** — list, stat, and read files directly
  from the backed-up volume's NTFS metadata (no need to mount the partition
  image with a separate tool).
- **FUSE mount on Linux** — expose the `.tib`'s files as a read-only filesystem.
- **WinFsp mount on Windows** — same, on Windows (experimental, see `tools/`).
- **Caches an index** next to the `.tib` so re-opens are instant.

## Installation

```bash
git clone https://github.com/yourname/tibread.git
cd tibread
python3 -m venv .venv
source .venv/bin/activate
pip install -e .                  # core, exposes the `tib` command
pip install -e '.[fuse]'          # + Linux FUSE mount support
pip install -e '.[winfsp]'        # + Windows WinFsp mount support
pip install -e '.[fast]'          # + numpy for ~5× faster index builds
```

Verify the install:

```bash
tib --version          # -> tibread 0.1.0
tib info /path/to/backup_full_b1_s1_v1.tib
```

System packages required for the FUSE mount on Linux:
- `libfuse2` and the `fusermount` / `fusermount3` binary

`tibread` requires Python 3.9+ and has no mandatory third-party dependencies.

## Quickstart

### Mount a `.tib` and browse files

```bash
tib mount backup_full_b1_s1_v1.tib /mnt/tib
ls /mnt/tib
file "/mnt/tib/Users/alice/Documents/x.docx"
fusermount -u /mnt/tib   # unmount
```

### Extract a single file

```bash
tib extract backup_full_b1_s1_v1.tib "Users/alice/Documents/x.docx" -o ./x.docx
```

### List the contents of a directory inside the backup

```bash
tib ls backup_full_b1_s1_v1.tib "Users/alice"
```

### Inspect the `.tib`'s structure

```bash
tib info --ntfs backup_full_b1_s1_v1.tib
```

### Bulk extract via robocopy (Windows) after FUSE mount

After you've mounted the backup, the standard tools work:

```cmd
robocopy "\\?\X:\path\to\mount" "\\?\D:\restored" /E /R:0 /W:0 /XJ /MT:8 /COPY:DAT /DCOPY:T /UNILOG:C:\rc.log
```

(`/XJ` skips reparse points like `TheVolumeSettingsFolder`. Use `\\?\` for paths >260 chars.)

### Inspect a `.tibx` archive (TI 2020+, experimental)

The `.tibx` reader is read-only and currently exposes six inspection
commands. Full mount lands once the in-flight `disk_adapter` integration
is merged; today `tibx-mount` exercises the bootstrap path only.

For an end-to-end walkthrough (with verified command output and the
programmatic API), see [`docs/TIBX_USER_GUIDE.md`](docs/TIBX_USER_GUIDE.md).

```bash
tib tibx-info    backup.tibx              # ARCH header (hostname, GUID, agent build) + segment scan
tib tibx-stat    backup.tibx              # LSM-tree superblocks + ctree summary
tib tibx-verify  backup.tibx --sample 100 # Sample N pages and validate CRC-32C
tib tibx-volumes backup.tibx              # TLV[18] volume_table cross-referenced against the MBR
tib tibx-chain   backup.tibx              # Enumerate slices (full / inc / diff) from TLV[5]
tib tibx-mount   backup.tibx              # Bootstrap NtfsVolume (currently MBR + first 256 KiB only)
```

Encrypted (`key != 0`, AES-wrapped) archives are decoded in spec only —
the encryption skeleton is at `tibread/tibx/encryption.py`. See
`docs/FORMAT_TIBX.md` for the full RE index.

### Programmatic API

```python
from tibread import open_tib

vol = open_tib("backup_full_b1_s1_v1.tib")

# Iterate the root directory
for entry in vol.list_dir(""):
    print(entry.name, entry.size if not entry.is_dir else "<dir>")

# Read a file by NTFS path (use forward slashes; package converts internally)
data = vol.read_file("Users/alice/Documents/x.docx")
```

## What's supported, what isn't

| Format | Status | Notes |
|---|---|---|
| Sector-mode `.tib`, modern (TI 2018+, 16-byte preamble + 128-cluster blocks) | ✅ Supported | The common full-disk backup format from Acronis True Image 2018-2019. See `docs/FORMAT.md`. |
| Sector-mode `.tib`, legacy (TI 2014/2015/2016, 8-byte preamble + 64-cluster blocks) | ✅ Supported | Recognised by absence of TLV tag `0x9b` in the metadata blob; chunk map is split across inline `SequentialChunkMap` records interleaved with the block stream. **First open is slow** (sequential scan to find the inline chunk maps — ~4 minutes for 8 GB; subsequent opens are instant via the cached `.idx` sidecar). See `docs/FORMAT_LEGACY.md`. |
| Sector-mode `.tib`, very-legacy (TI 2010-2013, `version=1` + `sector_size=0x1000`) | ❌ Rejected with a clean error | Acronis True Image 2018+ reads these only by destructively migrating them in-place to the modern format. To read with `tibread`: open once in TI 2018+ to migrate, then re-run. See `docs/FORMAT_VERY_LEGACY.md`. |
| `.tibx` (TIB eXtended, "QARCH" archive3 page-store) | ⚠️ Experimental — `info` / `stat` / `verify` / `volumes` / `chain` work; `mount` reaches the bootstrap region only (full mount lands with disk_adapter integration) | Acronis True Image 2020+ uses a 4 KiB-page LSM-tree store with Zstd-compressed segments (not SQLite, despite earlier folklore). `tibread.TibxReader` decodes: page header + CRC-32C + single-bit FEC; the 19-entry ARCH-header TLV directory (canonical mapping in `docs/legacy/ARCHIVE3_TLV_DIRECTORY.md`); all 9 LSM superblocks; ctree walks across LDIR / LEAF pages with the cell decoder; segment decompression (Zstd `key=0`); all six page types named (incl. `0x05` Golomb-Rice dedup filter); slice / backup-chain enumeration via `tibread.tibx.chains`. The encryption format (`key!=0` AES-wrapped segments) is spec'd as a skeleton in `tibread/tibx/encryption.py`. Working CLI commands: `tib tibx-info`, `tib tibx-stat`, `tib tibx-verify`, `tib tibx-volumes`, `tib tibx-chain`, `tib tibx-mount` (bootstrap-only). FUSE mount via the disk-adapter shim is in active integration. Tested on one specific file. See `tibread/tibx/` and `docs/FORMAT_TIBX.md`. |
| Filesystem-mode v1 `.tib` (magic `0x8F5C36C6`) | ⚠️ Format spec'd, not yet implemented | See `docs/FORMAT.md` |
| Filesystem-mode v2 `.tib` (magic `0x44686EB4`) | ⚠️ Format spec'd, not yet implemented | See `docs/FORMAT.md` |
| Tape archive `.tib` (footer magic `0x179631B4`) | ❌ Out of scope | Rare in 2026 |
| Encrypted `.tib` | ⚠️ Spec written, decoder skeleton only | AES-CBC + PBKDF2/SHA-stretch/scrypt; needs a sample to finish |
| Multi-volume splits (`_v1.tib`, `_v2.tib`, …) | ⚠️ Detection only | Open the *last* volume to access metadata |
| Incremental / differential chains | ⚠️ Spec written, not implemented | Needs sidecar `mms.db` (catalog) for chain reconstruction |
| NTFS `LZNT1`-compressed files | ✅ Supported | Decompressed transparently on read via `tibread.lznt1`; 64 KB compression units cached LRU. |
| WOF / Compact OS Xpress-compressed files | ✅ Supported (Xpress 4K / 8K / 16K) | Detected via `IO_REPARSE_TAG_WOF` (0x80000017); reads of the (sparse) unnamed `$DATA` are rerouted to `:WofCompressedData` and decompressed via `tibread.xpress`. **WOF / LZX (algorithm 1) is not implemented** (rare; falls back to zeros). |

Pull requests welcome for the remaining ⚠️ items above.

## How it works

A sector-mode `.tib` is a 32-byte volume header, then a long block stream
(each block = cluster-presence bitmap + zlib-compressed cluster data), then
a trailing region containing per-block dedup metadata, a TLV metadata blob,
and a sector trailer with `sliceSize64` + magic `0x94E18A2B`.

The critical reverse-engineered piece is the **on-disk chunk map**: a
zlib-compressed table that maps every partition block of the source volume
to its byte offset in the `.tib`. Acronis encodes it as 12-byte records
{u64 zigzag-delta-offset, u32 length}, with a column-major byte transpose
applied before zlib compression for better ratio.

The modern (TI 2018+) and legacy (TI 2014/2015/2016) variants share this
chunk-map encoding but differ in where it lives: modern stores it in a
single dedicated post-data region pointed to by a 13-byte locator in the
metadata blob (TLV tag `0x9b`); legacy splits it into inline records
interleaved with the block stream.

`tibread` detects the variant via the metadata blob, decodes the chunk map
(`tibread.chunkmap` / `tibread.chunkmap_legacy`), then builds a
"partition-direct" index keyed by partition_block (`tibread.indexer`) that
makes random-access reads O(1). The included NTFS reader (`tibread.ntfs`)
then walks the source volume's MFT exactly as the source OS would.

For full RE history see `docs/RE_HISTORY.md`. For format specs see
`docs/FORMAT.md` (modern), `docs/FORMAT_LEGACY.md` (legacy), and
`docs/FORMAT_VERY_LEGACY.md` (TI 2010-2013, rejected).

`.tibx` (TI 2020+) is a wholly different container: a 4 KiB-page LSM-tree
store with a `QARCH` ARCH header carrying a 19-entry TLV directory, nine
named LSM trees (`data_map`, `segment_map`, `dedup_map`, …) walked via
ctree LDIR/LEAF pages, and Zstd-compressed segments addressed by the
segment_map. Pages carry CRC-32C with single-bit FEC. The full TLV
directory mapping is canonical in `docs/legacy/ARCHIVE3_TLV_DIRECTORY.md`;
see `docs/FORMAT_TIBX.md` for the master index of all `.tibx` RE notes.

## Project layout

```
tibread/                    Python package (importable + CLI)
├── reader.py               Low-level block reader (TibReader, TIBIDX02/03 indices)
├── chunkmap_locator.py     Self-describing chunk-map discovery + format-era detection
├── chunkmap.py             Modern chunk-map decoder (zlib + transpose + zigzag-delta)
├── chunkmap_legacy.py      Legacy inline-SequentialChunkMap discovery + decode
├── indexer.py              build_index(): dispatches modern vs legacy
├── ntfs.py                 Pure-Python NTFS reader (NtfsVolume)
├── lznt1.py                LZNT1 decompressor (NTFS attribute compression)
├── xpress.py               Xpress LZ77+Huffman decompressor (WOF / Compact OS)
├── verify.py               Volume-header Adler32 validator + format-magic dispatch
├── metadata.py             Metadata-blob TLV parser
├── mount/fuse.py           FUSE mount (Linux)
├── tibx/                   Experimental `.tibx` (QARCH archive3) reader
│   ├── reader.py           TibxReader: page reader + ARCH header decode
│   ├── format.py           Page header / CRC-32C / FEC / TLV directory
│   ├── lsm.py              L-SB superblock parser + ctree walker
│   ├── lsm_cells.py        Cell decoder for LDIR / LEAF pages
│   ├── segment.py          Zstd-compressed segment reader
│   ├── disk_image.py       Bootstrap read_lba_range() (early plumbing)
│   ├── disk_adapter.py     Bridge to NtfsVolume (in flight)
│   └── encryption.py       AES-wrapped segment skeleton (in flight)
└── cli.py                  `tib` command entry point

tools/                      Standalone scripts (helper / advanced use)
docs/                       Format specs and RE notes
├── FORMAT.md / FORMAT_LEGACY.md / FORMAT_VERY_LEGACY.md   `.tib` specs
├── FORMAT_TIBX.md          `.tibx` master RE-notes index
└── legacy/                 Per-investigation RE notes (`.tib` + `.tibx`)
```

## Tested on

The following `.tib` files have been confirmed working end-to-end on this
release. If your file matches one of these eras, it should Just Work; if
not, please open an issue with `tib info <file>` output.

| File | Size | Source TI version | Format era | Result |
|---|---|---|---|---|
| `STORAGE (R)_full_b1_s1_v1.tib` | 1.04 TiB | True Image v23.5 build 17750 (2018+) | modern (16-byte preamble, 128-cluster blocks) | Mount + extract OK; ~99% file-count parity vs. source XML metainfo (200,000+ files) |
| `miner1_default_full_b1_s1_v1.tib` | 8.18 GiB | True Image 2013 | legacy (8-byte preamble, 64-cluster blocks, inline chunk-map records) | Mount + extract OK; 100% file-count parity |

## Status

This is a 0.1 release. It works end-to-end for the original 1 TB recovery
that motivated it (~99% file recovery vs. the source XML metainfo's count;
remaining failures are Recycle-Bin entries with deallocated source clusters
and old QuickTime `.mov` files with non-`ftyp` headers — both genuine, not
reader bugs) plus a TI 2013 legacy backup at 100% parity. It almost
certainly contains rough edges on other people's `.tib` files. Bug reports
very welcome — see `CHANGELOG.md` for the precise scope of supported and
unsupported variants.

## Acknowledgments

- Reverse-engineered from `product.bin` (Acronis True Image v23.5 build 17750)
  using Ghidra and a swarm of LLM agents. See `docs/RE_HISTORY.md` for the play-by-play.
- The chunk-map decoder is built on the algorithm in Acronis's `ExtraFileChunkMap`
  function (`k:/8029/resizer/backup/openimg.cpp`, FUN_089839b0).

## License

MIT — see `LICENSE`.
