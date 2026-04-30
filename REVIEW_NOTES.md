# tibread 0.1.0 — pre-release review punch list

Generated during a final-polish review pass over the package, focused on
the files touched by the recent legacy + compression-wireup commits:
`ntfs.py`, `chunkmap_legacy.py`, `indexer.py`, `reader.py`,
`chunkmap_locator.py`, `cli.py`, `mount/fuse.py`.

Scope of this review: identify bugs, dead code, robustness gaps, and
test-coverage holes. Easy/safe items were fixed in this pass; risky
items are listed below as deferred.

## Severity legend

- **HIGH**    — incorrect output, data corruption, crash on common inputs.
- **MEDIUM**  — robustness / error-path issue; unlikely on healthy files.
- **LOW**     — cosmetic, dead code, documentation drift.

---

## Fixed in this pass

| # | Sev | File | Item |
|---|-----|------|------|
| 1 | LOW | `chunkmap_legacy.py` | Removed unused imports `struct`, `Iterator`. |
| 2 | LOW | `reader.py` | Removed unused `import os`. |
| 3 | LOW | `chunkmap_locator.py` | Removed unused `from pathlib import Path`. |
| 4 | LOW | `cli.py` | Removed unused import `_default_index_path`. |
| 5 | LOW | `cli.py / cmd_info` | Was calling `compute_header_adler32` twice; now once. |
| 6 | MED | `reader.py / _decompress_block` | If `comp_len < preamble_len` (corrupt index), `f.read(neg)` reads to EOF and `zlib.decompress` would explode opaquely. Now raises a clear `ValueError`. |
| 7 | LOW | `chunkmap_locator.py` | The multi-candidate disambiguation block sorted twice in opposite directions and had a stale comment. Simplified to one sort + a clarified comment. No behavioural change on the common (single-candidate) path. |

---

## Deferred — flagged but not changed (low risk OR risky to touch this late)

### Robustness

| # | Sev | File | Item |
|---|-----|------|------|
| 8 | MED | `reader.py / TibReader.__init__` | The index's stored `tib_size` field is read but never compared against the actual `.tib` file size. Mismatch would silently mis-read. Suggest `if Path(tib_path).stat().st_size != self.tib_size: warn`. |
| 9 | MED | `reader.py / _file()` | Per-thread file handles are opened lazily via `threading.local` but never closed. For a long-running FUSE mount this is at most one fd per worker thread, but there's no `close()` method on `TibReader` either. Consider `__del__` or explicit `.close()` that walks `_tls.__dict__`. |
| 10 | MED | `indexer.py / build_index` | If a stale/corrupt `.idx` exists next to the `.tib` (e.g. partial write from a killed indexer run), we accept it without a magic check. `TibReader.__init__` will reject it loudly, but a `--force` hint in the error would be friendlier. |
| 11 | LOW | `chunkmap_locator.py / _modern_chunkmap_offset` | `f.read(2)` may return 0 or 1 bytes on a truncated `.tib`; the subsequent `zhdr[:1] != b"\x78"` would be `b""[:1] != b"\x78"` (true → ValueError). Error message would say "doesn't start with 0x78" which is misleading on truncation. |
| 12 | LOW | `ntfs.py / _FileDisk.read` | Returns zero-padded bytes when reading past EOF. Caller has no way to distinguish "real zero clusters" from "ran off the end of a truncated `.tib`". Probably fine, but the comment in the code doesn't say it. |
| 13 | LOW | `chunkmap_legacy.py / _consume_zlib_stream` | `max_extra` sanity bail only triggers if `len(decompressed) == 0`. A pathological zlib stream that produces 1 byte and consumes 4 GB would not bail. Edge case. |

### Concurrency (FUSE multi-threaded mode)

| # | Sev | File | Item |
|---|-----|------|------|
| 14 | LOW | `reader.py / LRUCache` | `LRUCache.put` uses a lock, good. `_decompress_block` does `cache.get` then `cache.put` without a lock — two threads can both miss, both decompress the same block, and both `put`. Wasteful but not incorrect (same block contents → same result). |
| 15 | MED | `ntfs.py / _decompressed_cu` cache | `NtfsVolume._cu_cache_get/put` is not thread-safe. The FUSE mount uses `nothreads=False` (multi-threaded). Two threads racing on the same compressed file might both decompress and one's result overwrites the other's. Result is correct but extra work. A real issue would be torn `OrderedDict` mutation — Python's GIL likely saves us, but should be documented. |

### Documentation / API surface

| # | Sev | File | Item |
|---|-----|------|------|
| 16 | LOW | `tibread/__init__.py` | Quick-start docstring shows `tib.list_files()` but the public method is `tib.list_dir(path)`. There is no `list_files()`. Misleading. |
| 17 | LOW | `cli.py` module docstring | Says `tib extract <tib> <path-in-vol> [-o]` but the actual flag is `-o OUTPUT` with a value. Minor. |
| 18 | LOW | `reader.py / TibReader` | No docstring on `read_cluster`, `read`, `_block_preamble`. Public method `read` is documented; the others are internal. OK. |
| 19 | LOW | `indexer.py` | Module docstring describes only `TIBIDX02`; `TIBIDX03` is now also written for legacy. Update to mention both. |
| 20 | LOW | `ntfs.py / NtfsVolume.find_mft_extent2` | Long docstring + slow linear scan path. Currently unreferenced from indexer / open_tib codepaths — used by hand-written tools only. Worth marking as advanced/internal in the docstring or moving to `tools/`. |

### Dead code

| # | Sev | File | Item |
|---|-----|------|------|
| 21 | LOW | `chunkmap.py / build_skipmap_csv` | The `__main__` runner still emits the MFT-extent-anchor validation table with hardcoded block numbers from the original RE work. Harmless (only triggers when run directly), but should probably be moved to `tools/` next release. |
| 22 | LOW | `ntfs.py / find_dense_file0_regions` | Brute-force MFT-region scanner. Slow, only used by hand investigations. Candidate to move to `tools/`. |

### Test coverage gaps

The single integration test (`tools/tests/test_compression.py`) covers
LZNT1 + WOF read paths against synthesised attribute scenarios. The
end-to-end smoke test (`extract_magic_check.py`) requires real `.tib`
files at `/mnt/e/...`.

What's NOT covered by automated tests:

| # | What | Why it matters |
|---|------|---------------|
| T1 | Index format-era dispatch | `build_index` choosing modern vs legacy never exercised in CI; would catch a regression in `detect_format_era` + dispatch. |
| T2 | TIBIDX03 round-trip | Legacy index reader uses parametric geometry — write-then-read with a synthetic blob. |
| T3 | `UnsupportedTibFormat` paths | We have 4 detection paths (.tibx / fs-v1 / fs-v2 / very-legacy). None are covered by tests. A 32-byte synthetic header per case would do it. |
| T4 | CLI subcommands | No tests at all. At minimum a `subprocess.run(["tib", "--help"])` smoke test would catch import-time regressions. |
| T5 | `TibReader.read` corner cases | Reads at exactly `partition_size`, length=0, offset+length > partition_size, sparse cluster reads. None tested. |
| T6 | FUSE mount path | Untested. Hard to test without root. Could mock `FUSE` and just exercise `_NtfsFS.getattr/readdir/read`. |
| T7 | Truncated `.tib` | Open a `.tib` truncated to 1024 bytes — does `discover_chunkmap_offset` raise cleanly? |
| T8 | Corrupt index | Open a `.tib.idx` with bad magic — does `TibReader` raise cleanly? |

### Recommended additions (do not necessarily implement now)

- **`test_unsupported_formats.py`** — synthesise the 4 unsupported-magic
  headers and assert each raises `UnsupportedTibFormat` with the right
  message substring.
- **`test_cli_smoke.py`** — `subprocess` invocation of `tib --version`
  and `tib --help` to catch import regressions.
- **`test_index_roundtrip.py`** — write a fake TIBIDX02 + TIBIDX03 to
  `tmp_path`, read with `TibReader`, assert geometry fields are correct.

---

## Smoke test results (post-fix)

- `python3 tools/tests/test_compression.py` — all 7 sub-tests pass.
- `tib info /mnt/e/miner1_default_full_b1_s1_v1.tib` — see commit log.
- `tib verify` on both test files — see commit log.

If any of the above fails after a fix lands, revert the corresponding row.
