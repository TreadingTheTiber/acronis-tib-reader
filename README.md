# acronis-tib-reader

[![CI](https://github.com/TreadingTheTiber/acronis-tib-reader/actions/workflows/ci.yml/badge.svg)](https://github.com/TreadingTheTiber/acronis-tib-reader/actions/workflows/ci.yml)
[![Lint](https://github.com/TreadingTheTiber/acronis-tib-reader/actions/workflows/lint.yml/badge.svg)](https://github.com/TreadingTheTiber/acronis-tib-reader/actions/workflows/lint.yml)

**Pure-Python read-only access to Acronis True Image `.tib` and `.tibx` backups.**
Mount, browse, list, and extract files without Acronis software.

> **Status:** 0.3.0 — supports sector-mode `.tib` (TI 2013–2018+),
> `.tibx` (TI 2020+, first open-source reader), and the FS-mode hybrid
> `.tib` variant Acronis produces when backing up file shares (NAS /
> SMB). See [CHANGELOG.md](CHANGELOG.md) for the full feature matrix.

The package installs a single `tib` command. Import name remains
`tibread` for code use.

## What it can do

| Format | What you can do | How |
|---|---|---|
| Sector-mode `.tib` (full-disk image, TI 2013–2018+) | Mount as a filesystem; list / extract any file by path | `tib mount`, `tib ls`, `tib extract` |
| `.tibx` (TI 2020+, full-disk image) | Same — full FUSE mount with multi-partition + multi-slice support | `tib mount backup.tibx /mnt/x --partition N` |
| FS-mode hybrid `.tib` (NAS / share backup; sector header + FS-mode trailer) | Browse in a local web browser; download individual files; or bulk-extract with original paths | `tib browse-fs`, `tib extract-fs` |

## Installation

```bash
git clone https://github.com/TreadingTheTiber/acronis-tib-reader.git
cd acronis-tib-reader
python3 -m venv .venv
source .venv/bin/activate
pip install -e .                  # core, exposes the `tib` command
pip install -e '.[fuse]'          # + Linux FUSE mount support
pip install -e '.[winfsp]'        # + Windows WinFsp mount support
pip install -e '.[fast]'          # + numpy for ~5× faster index builds
```

Verify:

```bash
tib --version
tib info /path/to/backup_full_b1_s1_v1.tib
```

System requirements:
- Python 3.9+ (no other mandatory dependencies)
- Linux FUSE mount needs `libfuse2` and `fusermount` / `fusermount3`

## Quickstart

### Browse an FS-mode (NAS / share) backup

The simplest UX for non-technical users — no extraction, no FUSE
driver, just a folder tree in the browser. The first run builds an
index (one full sequential read of the archive). Subsequent runs load
the cached `.fs.idx` sidecar and start instantly.

```bash
tib browse-fs share_backup_example.tib
# [tibread] building index (one-time scan)...
# [tibread] index built: 155,422 files
# [tibread]   URL: http://127.0.0.1:43217/
```

Your default browser opens to a folder listing. Click folders to
navigate, click files to preview (images / video / audio / pdf inline)
or download. `Ctrl-C` stops the server.

### Bulk-extract an FS-mode backup with original paths

For users who want offline copies of every file:

```bash
tib extract-fs share_backup_example.tib /path/to/output --rename-to-original
```

Files come out at their original Windows paths (`Documents/Photos/...`).
Filter to a subset of the archive with `--max-files` or `--max-bytes`.

### Mount a sector-mode `.tib` or `.tibx`

```bash
# Sector-mode .tib (single partition, no flag needed)
tib mount backup_full_b1_s1_v1.tib /mnt/tib
ls /mnt/tib
fusermount -u /mnt/tib

# .tibx (MBR multi-partition: pick one with --partition)
tib mount backup.tibx /mnt/tibx --partition 1   # main C:
fusermount -u /mnt/tibx
```

### Extract a single file (sector-mode / .tibx)

```bash
tib extract backup_full_b1_s1_v1.tib "Users/alice/Documents/x.docx" -o ./x.docx
```

### Inspect a `.tibx` archive

```bash
tib tibx-info    backup.tibx              # ARCH header (hostname, GUID, agent build)
tib tibx-stat    backup.tibx              # LSM-tree superblocks + ctree summary
tib tibx-verify  backup.tibx --sample 100 # Sample-validate page CRC-32C
tib tibx-volumes backup.tibx              # MBR partitions / volume_table
tib tibx-chain   backup.tibx              # Enumerate slices (full / inc / diff)
```

### Programmatic API

```python
from tibread import open_tib

vol = open_tib("backup_full_b1_s1_v1.tib")
for entry in vol.list_dir(""):
    print(entry.name, entry.size if not entry.is_dir else "<dir>")

data = vol.read_file("Users/alice/Documents/x.docx")
```

For FS-mode archives:

```python
from tibread.fs_browse import build_index, iter_file_bytes

idx = build_index("share_backup_example.tib")
target = next(e for e in idx.files if e.path.endswith("photo.jpg"))
content = b"".join(iter_file_bytes("share_backup_example.tib", target))
```

## Format support matrix

| Format | Status | Notes |
|---|---|---|
| Sector-mode `.tib`, modern (TI 2018+, 16-byte preamble + 128-cluster blocks) | ✅ Supported | The common full-disk backup format. See `docs/FORMAT.md`. |
| Sector-mode `.tib`, legacy (TI 2014/2015/2016, 8-byte preamble + 64-cluster blocks) | ✅ Supported | Detected by absence of TLV tag `0x9b`. **First open is slow** (sequential scan to find inline chunk-map records — minutes for a multi-GB archive); subsequent opens are instant via the `.idx` sidecar. See `docs/FORMAT_LEGACY.md`. |
| Sector-mode `.tib`, very-legacy (TI 2010–2013, 4 KiB sector size) | ❌ Rejected with a clean error | Acronis True Image 2018+ migrates these in-place. Open once in TI 2018+ to migrate, then re-run. See `docs/FORMAT_VERY_LEGACY.md`. |
| `.tibx` (TIB eXtended, TI 2020+) | ✅ Supported | Full FUSE mount, `data_map` + `segment_map` LSM walks, multi-partition, multi-slice. See `docs/FORMAT_TIBX.md`. |
| FS-mode hybrid `.tib` (sector header + `0x94E18A2C` trailer; NAS / share backups) | ✅ Browse + extract | `tib browse-fs` and `tib extract-fs`; original filenames + paths recovered from the directory-tree blob. |
| Filesystem-mode v1 / v2 `.tib` (magic `0x8F5C36C6` / `0x44686EB4`) | ⚠️ Format spec'd, not yet implemented | Different layout from the FS-mode hybrid. See `docs/FORMAT.md`. |
| Multi-volume splits (`_v1.tib`, `_v2.tib`, …) | ✅ Detected | Reader auto-redirects you at the LAST volume (which carries the metadata). |
| Encrypted `.tib` | ⚠️ Spec written, decoder skeleton only | AES-CBC + PBKDF2/SHA-stretch/scrypt; needs an encrypted sample to finish |
| Tape archive `.tib` (footer magic `0x179631B4`) | ❌ Out of scope | Rare in 2026 |
| Incremental / differential chains | ⚠️ Detection only | Reconstruction needs the sidecar `.db` catalog |
| NTFS LZNT1-compressed files | ✅ Supported | Decompressed transparently on read |
| WOF / Compact OS Xpress-compressed files | ✅ Supported (Xpress 4K / 8K / 16K) | LZX algorithm not implemented (rare) |

Pull requests welcome for the ⚠️ items above.

## How it works

A sector-mode `.tib` is a 32-byte volume header, then a long block
stream (each block = cluster-presence bitmap + zlib-compressed cluster
data), then a trailing region with per-block dedup metadata, a TLV
metadata blob, and a sector trailer. The critical reverse-engineered
piece is the on-disk **chunk map** — a zlib-compressed table mapping
every partition block to its byte offset in the `.tib`. Modern (TI
2018+) and legacy (TI 2014–2016) variants share the encoding but
differ in *where* it lives (post-data region pointed to by TLV `0x9b`
vs. inline records interleaved with the block stream).

`.tibx` (TI 2020+) is a wholly different container: a 4 KiB-page
LSM-tree page-store with an `ARCH` header carrying a 19-entry TLV
directory, nine named LSM trees (`data_map`, `segment_map`,
`dedup_map`, …) walked via ctree LDIR / LEAF pages, and Zstd-compressed
segments. Pages carry CRC-32C with single-bit FEC.

The FS-mode hybrid `.tib` (NAS / share backups) wraps a
filesystem-mode body inside sector-mode framing: per-file content as
length-prefixed zlib stored blocks, an out-of-band per-file metadata
batch, and a trailing directory-tree blob that maps NTFS file IDs to
original Windows paths. See `docs/legacy/FILESYSTEM_MODE_TIB.md` for
the full decode.

## Project layout

```
tibread/                    Python package (importable + CLI)
├── chunkmap_locator.py     Format-era detection + chunk-map discovery
├── chunkmap.py             Modern chunk-map decoder
├── chunkmap_legacy.py      Legacy inline-SequentialChunkMap walker
├── chunkmap_fs.py          FS-mode hybrid walker + directory-tree decoder
├── fs_browse.py            FS-mode index + on-demand extract + HTTP browser
├── indexer.py              build_index() dispatch
├── ntfs.py                 Pure-Python NTFS reader (NtfsVolume)
├── lznt1.py / xpress.py    NTFS / WOF transparent-compression decoders
├── reader.py               Low-level block reader
├── verify.py               Adler32 validator + format-magic dispatch
├── metadata.py             Metadata-blob TLV parser
├── mount/fuse.py           FUSE mount (Linux)
├── tibx/                   `.tibx` (TI 2020+) reader
│   ├── reader.py / format.py / lsm.py / lsm_cells.py
│   ├── segment.py / segment_map.py / data_map.py
│   ├── disk_adapter.py     NTFS bridge for FUSE mount
│   └── encryption.py       Encrypted-segment skeleton
└── cli.py                  `tib` command entry point

tools/                      Standalone scripts + tests
docs/                       Format specs and RE notes
```

## Acknowledgments

Reverse-engineered from `product.bin` (Acronis True Image v23.5 build
17750) and `archive3.dll` using Ghidra and a multi-agent LLM workflow.
See `docs/RE_HISTORY.md` for the play-by-play.

## License

MIT — see `LICENSE`.
