# `.tibx` reader — how-to guide

A practical guide for reading data out of an Acronis True Image `.tibx`
backup with `tibread`. If you've just `pip install`-ed `tibread` and have
a `.tibx` file in front of you, start here.

> Status: the `.tibx` reader is **experimental**. Inspection commands
> (`tibx-info`/`stat`/`verify`/`volumes`/`chain`) are solid; full file
> extraction via `tibx-mount` is partial — see below.

---

## 1. What's a `.tibx` file?

`.tibx` ("TIB eXtended") is the backup container introduced by **Acronis
True Image 2020** to replace the older `.tib` format. Internally it
identifies itself as `QARCH` archive3: a fixed 4 KiB-page store with
nine LSM-tree indexes (`data_map`, `segment_map`, `dedup_map`, etc.),
Zstd-compressed data segments, and per-page CRC-32C with single-bit FEC.
Despite earlier folklore, it is **not** a SQLite database.

---

## 2. What can `tibread` do with `.tibx` today?

| Capability | Command |
|---|---|
| Detect a `.tibx` file | `tib tibx-info FILE` |
| Inspect format structure | `tib tibx-stat FILE` |
| Validate page integrity (CRC-32C) | `tib tibx-verify FILE` |
| List the volumes/partitions inside | `tib tibx-volumes FILE` |
| List backup-chain slices (full / inc / diff) | `tib tibx-chain FILE` |
| Mount and read individual files (**partial**) | `tib tibx-mount FILE MOUNT` |
| Decompress arbitrary segments | Programmatic API |

### `tibx-mount` caveats

`tibx-mount` bootstraps an `NtfsVolume` and walks `segment_map` to
satisfy reads. It works **for small partitions where the NTFS BPB lives
in the bootstrap region** (first ~256 KiB). Larger volumes need the
in-flight `disk_adapter` integration before mount is end-to-end reliable.

---

## 3. Quickstart

After `pip install tibread`, the `tib` command is on your `PATH`.

### Confirm it really is a `.tibx`

```bash
tib tibx-info backup.tibx
```

Truncated output on a real Acronis backup:

```
tibx file: backup.tibx  (54,671,892,480 bytes)
  pages: 13,347,630 of 4096 bytes
ARCH header:
  header_magic      : QARCH
  archive_uuid      : 655f4ba513f6efc834432712570b1240
  hostname          : STRIDER-WIN63
  agent_build       : ACPHO 27.3.1.40173 Win
```

`header_magic: QARCH` means `tibread` will accept it.

### See the LSM index structure

```bash
tib tibx-stat backup.tibx
```

This prints all nine LSM-tree superblocks with their ctree roots, page
counts, and item counts. Useful for confirming the file isn't truncated
or corrupted.

### Spot-check page integrity

```bash
tib tibx-verify backup.tibx              # random sample of 1,000 pages
tib tibx-verify backup.tibx --sample 50  # quicker spot-check
tib tibx-verify backup.tibx --full       # every page (slow, GB-scale read)
```

Any non-zero "CRC mismatches" count means the file has bit-rot or was
truncated mid-write.

### Discover the backed-up partitions

```bash
tib tibx-volumes backup.tibx
```

Decodes the `volume_table` TLV and the embedded MBR/GPT, and
cross-references the two.

### List the backup chain

```bash
tib tibx-chain backup.tibx
```

Each `.tibx` carries a chain of slices (`type=full`, `inc`, or `diff`),
printed in chronological order so you can tell whether the file is a
chain root or an increment that depends on a parent.

---

## 4. What's NOT supported

- **Encrypted `.tibx`** (`key != 0`, AES-wrapped segments). The decoder
  is sketched in `tibread/tibx/encryption.py` but no test sample exists,
  so it's spec-only.
- **LZX-compressed segments**. Very rare in practice — the common
  variants are `Stored` (raw), `LZ4`, and `Zstd`, all of which work.
- **Writing `.tibx` files**. `tibread` is read-only by design.
- **Acronis Mobile backups**. Those use a different on-disk format
  even though they share the `.tibx` extension.

---

## 5. Programmatic API

For anything beyond the CLI, drive the reader directly:

```python
from itertools import islice
from tibread import TibxReader

with TibxReader("backup.tibx") as r:
    # ARCH header (returns a dict)
    h = r.read_arch_header()
    print("host:", h["hostname"], "uuid:", h["archive_uuid"])
    print("pages:", r.page_count, "size:", r.file_size)

    # Iterate segments and decompress them
    for seg in islice(r.find_segments(), 3):
        plain = r.decompress_segment(seg)
        print(f"  page={seg.page_idx} zlen={seg.zlen} -> {len(plain)} bytes")
```

Verified output on a sample file:

```
host: STRIDER-WIN63 uuid: 655f4ba513f6efc834432712570b1240
pages: 13347630 size: 54671892480
  page=6 zlen=480 -> 262144 bytes
  page=7 zlen=2795 -> 4096 bytes
  page=8 zlen=1042 -> 8192 bytes
```

### Reading raw LBA ranges

`TibxDiskAdapter` is the bridge that lets higher-level code (e.g. the
NTFS reader) treat the `.tibx` as a virtual disk. It exposes a
`read(byte_offset, length)` method that walks `segment_map` to satisfy
reads. Useful when you want to feed a custom filesystem reader:

```python
from tibread import TibxReader, TibxDiskAdapter

with TibxReader("backup.tibx") as r:
    adapter = TibxDiskAdapter(r)
    mbr = adapter.read(0, 512)   # the MBR sector of the backed-up disk
```

(Same caveat as `tibx-mount`: reads outside the bootstrap region depend
on the in-flight chunk-index work.)

### Walking the LSM trees (advanced)

The nine LSM trees are walked via `tibread.tibx.lsm` /
`tibread.tibx.lsm_cells`. Use this to enumerate every chunk reference,
build a custom dedup analyser, etc. See `ARCHIVE3_LSM_CELLS.md`.

---

## 6. Format reference

If you want to know what's actually on disk:

- [`docs/FORMAT_TIBX.md`](FORMAT_TIBX.md) — master index of every
  `.tibx` RE note, mapping each spec doc to the code that implements it.
- `docs/legacy/ARCHIVE3_*.md` — per-subsystem RE notes: header format,
  TLV directory, page CRC/FEC, LSM superblock, LDIR/LEAF cell decoder,
  backup-chain mechanics, chunk-index lookups, encryption skeleton, and
  Acronis's own open/mount flow.

---

## 7. Acknowledgments

The `.tibx` spec was reverse-engineered from `product.bin` (Acronis
True Image v23.5 build 17750) by a multi-agent swarm: header decoder,
page-CRC analyser, LSM superblock walker, cell decoder, segment
decompressor, chain walker, disk-adapter integrator, and stress-test
fuzzer all ran as separate agents and reconciled findings into the
canonical `ARCHIVE3_*.md` specs. See `docs/RE_HISTORY.md`.
