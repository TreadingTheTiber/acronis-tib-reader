# tibread

**Pure-Python read-only access to Acronis True Image `.tib` backups.**
Mount, list, and extract files from `.tib` files without Acronis software.

This was originally built to recover a 1 TB backup from a long-discontinued
Acronis True Image installation. It now supports any sector-mode `.tib`
self-describingly — no per-file constants, no manual offset hunting.

## Features

- **Read sector-mode `.tib` backups** (the most common kind: full-disk image backups).
- **Self-describing** — works on any sector-mode `.tib` of the v23.x format generation
  with no hardcoded offsets or sizes. The chunk-map locator is parsed from
  the backup's own metadata blob.
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
pip install .                  # core
pip install '.[fuse]'          # + Linux FUSE mount support
pip install '.[winfsp]'        # + Windows WinFsp mount support
pip install '.[fast]'          # + numpy for ~5× faster index builds
```

System packages required for the FUSE mount on Linux:
- `libfuse2` and the `fusermount` / `fusermount3` binary

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
| Sector-mode `.tib`, modern (TI 2018+, 16-byte preamble + 128-cluster blocks) | ✅ Supported | The common full-disk backup format from Acronis True Image 2018-2019 |
| Sector-mode `.tib`, legacy (TI 2014/2015/2016, 8-byte preamble + 64-cluster blocks) | ✅ Supported | Recognised by absence of TLV tag `0x9b` in the metadata blob; chunk map is split across inline `SequentialChunkMap` records interleaved with the block stream. See `docs/FORMAT_LEGACY.md`. |
| `.tibx` (TIB eXtended, "QARCH" archive) | ❌ Different format, not supported | Acronis True Image 2020+ replaced `.tib` with `.tibx`, which uses an SQLite-backed archive container instead of the layout this reader handles. **If your file is `.tibx`, use a different tool.** |
| Filesystem-mode v1 `.tib` (magic `0x8F5C36C6`) | ⚠️ Format spec'd, not yet implemented | See `docs/FORMAT.md` |
| Filesystem-mode v2 `.tib` (magic `0x44686EB4`) | ⚠️ Format spec'd, not yet implemented | See `docs/FORMAT.md` |
| Tape archive `.tib` (footer magic `0x179631B4`) | ❌ Out of scope | Rare in 2026 |
| Encrypted `.tib` | ⚠️ Spec written, decoder skeleton only | AES-CBC + PBKDF2/SHA-stretch/scrypt; needs a sample to finish |
| Multi-volume splits (`_v1.tib`, `_v2.tib`, …) | ⚠️ Detection only | Open the *last* volume to access metadata |
| Incremental / differential chains | ⚠️ Spec written, not implemented | Needs sidecar `mms.db` (catalog) for chain reconstruction |
| NTFS `LZNT1`-compressed files | ⚠️ Decompressor available (`tibread.lznt1`); not yet wired into `NtfsVolume` | |
| WOF / Compact OS Xpress-compressed files | ⚠️ Decompressor available (`tibread.xpress`); not yet wired into `NtfsVolume` | |

The "not yet wired" items each have a working pure-Python decompressor in the
package and a documented integration plan; pull requests welcome.

## How it works

A sector-mode `.tib` is a 32-byte volume header, then a long block stream
(each block = 16-byte cluster-presence bitmap + zlib-compressed cluster
data), then a post-data region containing several zlib-compressed metadata
streams plus an MD5 manifest and a cuckoo dedup filter, then a 780-byte TLV
metadata blob, then a 41-byte sector trailer.

The critical reverse-engineered piece is the **on-disk chunk map**: a
zlib-compressed table that maps every partition block of the source volume
to its byte offset in the `.tib`. Acronis encodes it as 12-byte records
{u64 zigzag-delta-offset, u32 length}, with a column-major byte transpose
applied before zlib compression for better ratio.

`tibread` decodes the chunk map (`tibread.chunkmap`), then builds a
"partition-direct" index keyed by partition_block (`tibread.indexer`) that
makes random-access reads O(1). The included NTFS reader (`tibread.ntfs`)
then walks the source volume's MFT exactly as the source OS would.

For full RE history and the format specification, see `docs/FORMAT.md`.

## Project layout

```
tibread/                    Python package (importable + CLI)
├── reader.py               Low-level block reader (TibReader)
├── chunkmap_locator.py     Self-describing chunk-map offset/size discovery
├── chunkmap.py             Chunk-map zlib + transpose + zigzag-delta decoder
├── indexer.py              build_index(): one call from .tib to ready-to-read
├── ntfs.py                 Pure-Python NTFS reader (NtfsVolume)
├── lznt1.py                LZNT1 decompressor (NTFS attribute compression)
├── xpress.py               Xpress LZ77+Huffman decompressor (WOF / Compact OS)
├── verify.py               Volume-header Adler32 validator
├── metadata.py             780-byte metadata-blob TLV parser
├── mount/fuse.py           FUSE mount (Linux)
└── cli.py                  `tib` command entry point

tools/                      Standalone scripts (helper / advanced use)
docs/                       Format specs and RE notes
```

## Status

This is a 0.1 release. It works end-to-end for the original 1 TB recovery
that motivated it (99.5% file recovery vs. the source XML metainfo's count;
remaining failures are Recycle-Bin entries with deallocated source clusters
and old QuickTime `.mov` files with non-`ftyp` headers — both genuine, not
reader bugs). It almost certainly contains rough edges on other people's
`.tib` files. Bug reports very welcome.

## Acknowledgments

- Reverse-engineered from `product.bin` (Acronis True Image v23.5 build 17750)
  using Ghidra and a swarm of LLM agents. See `docs/RE_HISTORY.md` for the play-by-play.
- The chunk-map decoder is built on the algorithm in Acronis's `ExtraFileChunkMap`
  function (`k:/8029/resizer/backup/openimg.cpp`, FUN_089839b0).

## License

MIT — see `LICENSE`.
