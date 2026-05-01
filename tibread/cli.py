"""
tibread CLI — `tib` command-line entry point.

Subcommands:
  tib info <tib>                       Show .tib structure (header, streams, MFT).
  tib index <tib> [--out IDX]          Build (or rebuild with --force) the partition-direct index.
  tib verify <tib>                     Validate volume header Adler32 + structural checks.
  tib mount <tib> <mountpoint> [opts]  Mount the .tib's NTFS volume read-only via FUSE (Linux).
  tib extract <tib> <path-in-vol> [-o] Extract a single file by NTFS path.
  tib ls <tib> [<path>]                List files in the .tib's filesystem.
  tib tibx-info <tibx>                 Show .tibx structure (experimental; archive3 page-store).
  tib tibx-stat <tibx>                 Show detailed .tibx LSM-tree status (per-tree ctree summary).
  tib tibx-verify <tibx>               Validate every page's CRC-32C; report mismatches.
  tib tibx-mount <tibx>                Probe NTFS via .tibx-backed disk adapter [experimental].

Examples:
  tib info backup_full_b1_s1_v1.tib
  tib mount backup_full_b1_s1_v1.tib /mnt/tib
  tib extract backup_full_b1_s1_v1.tib "Users/alice/Documents/x.docx" -o ./x.docx
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .reader import TibReader
from .indexer import build_index, open_tib


def cmd_info(args):
    from .chunkmap_locator import discover_chunkmap_offset, detect_format_era
    from .verify import compute_header_adler32

    tib = Path(args.tib)
    # Validate format up-front so unsupported variants (.tibx, fs-mode,
    # very-legacy) fail with a clean single-line error instead of partial
    # output. compute_header_adler32 raises UnsupportedTibFormat on .tibx
    # and unknown magics; detect_format_era covers very-legacy.
    ok, stored, computed = compute_header_adler32(str(tib))
    print(f"tib file: {tib}  ({tib.stat().st_size:,} bytes)")
    era = detect_format_era(str(tib))
    print(f"  format era: {era}")
    if era == "modern":
        chunkmap_off, chunkmap_size = discover_chunkmap_offset(str(tib))
        print(f"  chunk-map: offset={chunkmap_off:,}  comp_size={chunkmap_size:,}")
    else:
        print(f"  chunk-map: inline (multiple SequentialChunkMap records "
              f"interleaved with the block stream)")
    print(f"  header Adler32: stored={stored:08X} computed={computed:08X} {'OK' if ok else 'MISMATCH'}")

    # Build (or load) index, then show partition stats
    idx_path = build_index(tib, progress=args.verbose)
    r = TibReader(str(tib), str(idx_path), cache_blocks=4)
    if r.partition_size >= 1024 ** 4:
        size_str = f"{r.partition_size / 1024**4:.2f} TiB"
    else:
        size_str = f"{r.partition_size / 1024**3:.2f} GiB"
    print(f"  partition_size: {r.partition_size:,} bytes ({size_str})")
    print(f"  block_count: {r.block_count:,}")
    print(f"  geometry: clusters_per_block={r.clusters_per_block}, preamble_len={r.preamble_len}")
    print(f"  index file: {idx_path}")

    # Quick NTFS probe
    if args.ntfs:
        from .ntfs import NtfsVolume
        try:
            mft_lcn = NtfsVolume.find_mft_lcn(r)
            vol = NtfsVolume(r, build_index=False, mft_lcn_override=mft_lcn)
            total = vol._mft_real_size // vol.mft_record_size
            print(f"  NTFS MFT: located at LCN {mft_lcn:,}, {total:,} records")
        except Exception as e:
            print(f"  NTFS probe failed: {e}")
    return 0


def cmd_index(args):
    out = build_index(args.tib, args.out, force=args.force, progress=True)
    print(f"index written: {out}")
    return 0


def cmd_verify(args):
    from .verify import compute_header_adler32
    ok, stored, computed = compute_header_adler32(args.tib)
    print(f"header Adler32 stored={stored:08X} computed={computed:08X} -> {'OK' if ok else 'MISMATCH'}")
    return 0 if ok else 1


def cmd_ls(args):
    vol = open_tib(args.tib, progress=args.verbose)
    path = args.path or "/"
    for fe in vol.list_dir(path):
        kind = "d" if fe.is_dir else "-"
        size = "" if fe.is_dir else f"{fe.size:>12,}"
        print(f"{kind} {size}  {fe.name}")
    return 0


def cmd_extract(args):
    vol = open_tib(args.tib, progress=args.verbose)
    out = Path(args.out) if args.out else Path(args.path.replace("\\", "/")).name
    data = vol.read_file(args.path)
    out.write_bytes(data)
    print(f"wrote {len(data):,} bytes to {out}")
    return 0


def cmd_tibx_info(args):
    """Print a structural summary of an Acronis archive3 (.tibx) file."""
    from .tibx import TibxReader

    with TibxReader(args.tibx) as r:
        print(f"tibx file: {args.tibx}  ({r.file_size:,} bytes)")
        print(f"  pages: {r.page_count:,} of 4096 bytes")
        print()
        hdr = r.read_arch_header()
        print("ARCH header:")
        for key in (
            "header_magic",
            "version",
            "archive_uuid",
            "created_unix_ms",
            "modified_unix_ms",
            "hostname",
            "disk_guid",
            "install_guid",
            "agent_build",
        ):
            if key in hdr:
                print(f"  {key:18s}: {hdr[key]}")
        if hdr.get("strings"):
            print(f"  strings (page 1) : {hdr['strings']}")
        print()

        summary = r.file_map_summary()
        print("File map:")
        print(f"  head page types: " + ", ".join(
            f"#{idx}=0x{t:02x}" for idx, t in summary["head_page_types"]
        ))
        print(f"  tail page types: " + ", ".join(
            f"#{idx}=0x{t:02x}" for idx, t in summary["tail_page_types"]
        ))
        if summary["leaf_run_pages"]:
            print(
                f"  LEAF region: pages "
                f"{summary['leaf_run_start']:,}..{summary['leaf_run_end']:,} "
                f"(span {summary['leaf_run_pages']:,} pages, "
                f"{summary.get('leaf_page_count', summary['leaf_run_pages']):,} of them LEAF)"
            )
        else:
            print("  LEAF run: not found in tail sample")
        print()

        # Walk the first N segments to give a flavour without iterating
        # the whole 50 GB file.  --max-segments 0 enumerates every segment.
        max_segments = args.max_segments if args.max_segments and args.max_segments > 0 else None
        n = 0
        comp_hist: dict[int, int] = {}
        total_zlen = 0
        total_len = 0
        first5: list = []
        for seg in r.find_segments():
            comp_hist[seg.comp] = comp_hist.get(seg.comp, 0) + 1
            total_zlen += seg.zlen
            total_len += seg.length
            if n < 5:
                first5.append(seg)
            n += 1
            if max_segments is not None and n >= max_segments:
                break

        scope = (
            f"first {max_segments:,} segments"
            if max_segments is not None
            else f"all {n:,} segments"
        )
        print(f"Segment scan ({scope}):")
        print(f"  segments seen: {n:,}")
        print(f"  total compressed: {total_zlen:,} bytes")
        print(f"  total uncompressed (claimed): {total_len:,} bytes")
        if total_zlen:
            ratio = total_len / total_zlen
            print(f"  ratio: {ratio:.2f}x")
        print(f"  comp variant histogram: " + ", ".join(
            f"0x{c:04x}={n}" for c, n in sorted(comp_hist.items())
        ))
        print()
        print("First 5 segments:")
        for i, seg in enumerate(first5):
            print(
                f"  #{i}: page={seg.page_idx:,}  len={seg.length:,}  "
                f"zlen={seg.zlen:,}  key={seg.key}  "
                f"comp=0x{seg.comp:04x}  span={seg.page_span()} pages"
            )
    return 0


def cmd_tibx_stat(args):
    """Print the per-LSM-tree summary for a ``.tibx`` archive.

    This is the tibx-shaped equivalent of ``tib info --ntfs`` for .tib:
    archive UUID + source disk + hostname + agent build, then a
    summary row per LSM tree (key/value sizes, ctree count, item
    count, root page offsets), then a coarse file-map breakdown.
    """
    from .tibx import TibxReader, read_archive_header, walk_ctree
    from .tibx.format import PAGE_TYPE_NAMES

    with TibxReader(args.tibx) as r:
        info = r.read_arch_header()
        hdr = read_archive_header(r)

        print(f"tibx file: {args.tibx}")
        print(f"  size: {r.file_size:,} bytes  ({r.page_count:,} pages of 4 KiB)")
        print()
        print("ARCH header:")
        for key in (
            "header_magic",
            "version",
            "archive_uuid",
            "created_unix_ms",
            "modified_unix_ms",
            "hostname",
            "disk_guid",
            "install_guid",
            "agent_build",
        ):
            if key in info:
                print(f"  {key:18s}: {info[key]}")
        print(f"  arch_page         : {hdr.arch_page} (latest)")
        print(f"  hdr_size          : 0x{hdr.hdr_size:x}  ({hdr.hdr_size} bytes)")
        print(f"  hdr_version       : {hdr.hdr_version}")
        print()

        print(f"LSM index ({len(hdr.lsm_trees)} L-SB superblocks parsed):")
        # Header row.
        print(f"  {'TLV':>3}  {'name':12s}  {'k/v':7s}  "
              f"{'seq':>5s}  {'ctrees':>6s}  {'items':>6s}  "
              f"{'pages':>7s}  roots")
        for sb in hdr.lsm_trees:
            roots = []
            total_items = 0
            total_num_pages = 0
            active_ctrees = 0
            for ci, ct in enumerate(sb.ctrees):
                if ct.offset is None:
                    continue
                active_ctrees += 1
                total_items += ct.item_count
                total_num_pages += ct.num_pages
                roots.append(f"L{ci+2}={ct.root_page}")
            kv = f"{sb.key_length}/{sb.value_length}"
            roots_str = ",".join(roots) if roots else "(memtree-only)"
            if sb.memtree_node_count and not roots:
                roots_str = f"(memtree {sb.memtree_node_count} nodes)"
            page_count = total_num_pages // 4096
            print(
                f"  [{sb.tlv_index}]  {sb.name or '?':12s}  {kv:7s}  "
                f"0x{sb.seq:>3x}  {active_ctrees:>6d}  {total_items:>6d}  "
                f"{page_count:>7d}  {roots_str}"
            )
        print()

        # Walk one LDIR for the data_map (TLV[1]) for a smoke check.
        for sb in hdr.lsm_trees:
            if sb.tlv_index != 1 or not sb.has_disk_runs:
                continue
            print(f"Top-down walk of data_map (TLV[1]) ctrees:")
            for ci, ct in enumerate(sb.ctrees):
                if ct.offset is None:
                    continue
                stats = walk_ctree(r, ct, sb.key_length)
                err = f" err={stats.error}" if stats.error else ""
                print(
                    f"  ctree[{ci+2}] root_page={stats.root_page}: "
                    f"{stats.levels_visited} levels  "
                    f"({stats.ldir_pages} LDIR + {stats.leaf_pages} LEAF), "
                    f"per-level entries={stats.page_count_per_level}{err}"
                )
            break
        print()

        # File map summary.
        summary = r.file_map_summary()
        print("File map:")
        print(f"  page count       : {summary['page_count']:,}")
        print(f"  head page types  : " + ", ".join(
            f"#{idx}=0x{t:02x}" for idx, t in summary["head_page_types"]
        ))
        print(f"  tail page types  : " + ", ".join(
            f"#{idx}=0x{t:02x}" for idx, t in summary["tail_page_types"]
        ))
        if summary["leaf_run_pages"]:
            print(
                f"  LEAF region      : pages "
                f"{summary['leaf_run_start']:,}..{summary['leaf_run_end']:,} "
                f"(span {summary['leaf_run_pages']:,} pages, "
                f"{summary.get('leaf_page_count', summary['leaf_run_pages']):,} of them LEAF)"
            )
        # Locate ARCH/ARCI distribution at the tail.
        tail_arch = sum(1 for _, t in summary["tail_page_types"] if t == 0x01)
        tail_arci = sum(1 for _, t in summary["tail_page_types"] if t == 0x02)
        print(f"  tail ARCH/ARCI   : {tail_arch} ARCH, {tail_arci} ARCI in tail sample")
    return 0


def cmd_tibx_verify(args):
    """Walk a ``.tibx`` file and validate every page's CRC-32C envelope.

    By default a random sample of pages is verified for fast spot-check
    (``--sample N``).  Pass ``--full`` to walk the entire file (slow on
    multi-GiB archives without the ``crc32c`` C extension installed).
    """
    import random
    import time

    from .tibx import TibxReader
    from .tibx.format import PAGE_TYPE_NAMES

    with TibxReader(args.tibx) as r:
        total_pages = r.page_count
        if args.full:
            indices = range(total_pages)
            scope = f"all {total_pages:,} pages"
        else:
            n = min(args.sample, total_pages)
            rng = random.Random(args.seed)
            indices = sorted(rng.sample(range(total_pages), n))
            scope = f"random sample of {n:,} of {total_pages:,} pages"

        print(f"tibx file: {args.tibx}  ({r.file_size:,} bytes, "
              f"{total_pages:,} pages)")
        print(f"verifying {scope}...")

        ok = 0
        bad = 0
        by_type: dict[int, int] = {}
        bad_pages: list[tuple[int, int, int]] = []
        t0 = time.monotonic()
        report_every = max(1, len(indices) // 20) if hasattr(indices, '__len__') else 100_000

        for i, page_idx in enumerate(indices):
            try:
                page_ok, stored, computed = r.verify_page(page_idx)
            except IOError as e:
                print(f"  page {page_idx}: read error: {e}", file=sys.stderr)
                bad += 1
                continue
            ptype = r.read_raw_page(page_idx)[1]
            by_type[ptype] = by_type.get(ptype, 0) + 1
            if page_ok:
                ok += 1
            else:
                bad += 1
                if len(bad_pages) < 32:
                    bad_pages.append((page_idx, stored, computed))
            if args.verbose and (i + 1) % report_every == 0:
                elapsed = time.monotonic() - t0
                rate = (i + 1) / elapsed if elapsed else 0
                print(f"  {i + 1:,}/{len(indices) if hasattr(indices, '__len__') else '?':,} "
                      f"({rate:,.0f} pages/s)")

        elapsed = time.monotonic() - t0
        total = ok + bad
        rate = total / elapsed if elapsed else 0
        bytes_per_s = rate * 4096

        print()
        print(f"verified {total:,} pages in {elapsed:.2f}s")
        print(f"  rate: {rate:,.0f} pages/s ({bytes_per_s / 1e6:,.1f} MB/s)")
        print(f"  OK: {ok:,}")
        print(f"  CRC mismatches: {bad:,}")
        if by_type:
            print(f"  by page type:")
            for t in sorted(by_type):
                name = PAGE_TYPE_NAMES.get(t, f"0x{t:02x}")
                print(f"    {name} (0x{t:02x}): {by_type[t]:,}")
        if bad_pages:
            print(f"  first {len(bad_pages)} bad pages:")
            for pidx, stored, computed in bad_pages:
                print(f"    page {pidx:,}: stored=0x{stored:08x} "
                      f"computed=0x{computed:08x}")
        return 0 if bad == 0 else 1


def cmd_tibx_mount(args):
    """Bootstrap an :class:`NtfsVolume` against a ``.tibx`` archive.

    Currently only the first 256 KiB of the source disk is reachable
    (the bootstrap segment); reads beyond that fail with
    :class:`ChunkMapNotImplemented` until the segment_map LSM-tree cell
    decoder lands.  This subcommand reports what works (MBR / partition
    table / BPB-if-in-range) and what doesn't, so the plumbing is ready
    to flip on once the LSM walker arrives.
    """
    from .tibx import TibxDiskAdapter
    from .tibx.disk_image import BOOTSTRAP_LEN, ChunkMapNotImplemented
    from .ntfs import NtfsVolume

    print(f"tibx file: {args.tibx}")

    with TibxDiskAdapter(args.tibx) as adapter:
        try:
            mbr = adapter.read(0, 512)
        except Exception as e:
            print(f"  MBR read failed: {type(e).__name__}: {e}")
            return 1
        sig_ok = mbr[510:512] == b"\x55\xaa"
        print(f"  MBR signature  : {'OK (0x55AA)' if sig_ok else 'MISSING'}")
        print(f"  partition_size : {adapter.partition_size:,} bytes")
        print(f"  block_count    : {adapter.block_count:,} (4 KiB blocks)")

        partitions = adapter.list_mbr_partitions()
        if partitions:
            print(f"  MBR partitions ({len(partitions)}):")
            for i, p in enumerate(partitions):
                in_boot = p["byte_offset"] < BOOTSTRAP_LEN
                marker = "  <-- BPB in bootstrap" if in_boot else ""
                print(
                    f"    #{i}: type=0x{p['type']:02x} "
                    f"first_lba={p['first_lba']:,}  "
                    f"size={p['byte_size']:,} bytes "
                    f"({p['byte_size'] / 1024**3:.2f} GiB){marker}"
                )

    print()
    print("Attempting NtfsVolume bootstrap on each MBR partition:")
    if not partitions:
        print("  no MBR partitions found; skipping NTFS probe")
        return 0
    for i, p in enumerate(partitions):
        print(f"  partition #{i} (offset {p['byte_offset']:,}):")
        if p["byte_offset"] >= BOOTSTRAP_LEN:
            print(
                f"    boot sector at byte {p['byte_offset']:,} is past the "
                f"bootstrap region (0..{BOOTSTRAP_LEN}); cannot read BPB "
                f"until the segment_map LSM walker lands."
            )
            continue
        padapter = TibxDiskAdapter(args.tibx, partition_offset=p["byte_offset"])
        try:
            try:
                vol = NtfsVolume(padapter, build_index=False)
            except ChunkMapNotImplemented:
                print(
                    f"    BPB parsed; $MFT read NOT YET POSSIBLE "
                    f"(LSM walker required)"
                )
                tmp = NtfsVolume.__new__(NtfsVolume)
                tmp.disk = padapter
                try:
                    tmp._parse_boot_sector()
                    print(
                        f"    BPB: bytes_per_sector={tmp.bytes_per_sector} "
                        f"sectors_per_cluster={tmp.sectors_per_cluster} "
                        f"cluster_size={tmp.cluster_size}"
                    )
                    print(
                        f"         total_sectors={tmp.total_sectors:,} "
                        f"mft_lcn={tmp.mft_lcn:,} mftmirr_lcn={tmp.mftmirr_lcn:,}"
                    )
                    print(
                        f"         mft_record_size={tmp.mft_record_size} "
                        f"index_record_size={tmp.index_record_size}"
                    )
                    if tmp.oem_warning:
                        print(f"         OEM warning: {tmp.oem_warning}")
                    print(
                        f"    $MFT byte offset = "
                        f"{tmp.mft_lcn * tmp.cluster_size:,} on partition; "
                        f"reading it requires LSM walker."
                    )
                except Exception as e2:
                    print(f"    BPB parse failed: {type(e2).__name__}: {e2}")
            except Exception as e:
                print(f"    BPB parse FAILED: {type(e).__name__}: {e}")
            else:
                total = vol._mft_real_size // vol.mft_record_size
                print(f"    NtfsVolume bootstrap SUCCESS: {total:,} MFT records")
        finally:
            padapter.close()
    return 0


def cmd_mount(args):
    try:
        from .mount.fuse import fuse_mount
    except ImportError as e:
        print(f"FUSE mount unavailable: {e}", file=sys.stderr)
        print("Install with: pip install fusepy", file=sys.stderr)
        return 1
    return fuse_mount(args.tib, args.mountpoint, foreground=args.foreground)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="tib",
        description="Read-only access to Acronis True Image .tib backups.",
    )
    p.add_argument("--version", action="version", version=f"tibread {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ap = sub.add_parser("info", help="Show .tib structure summary.")
    ap.add_argument("tib")
    ap.add_argument("--ntfs", action="store_true", help="Also probe NTFS MFT.")
    ap.set_defaults(func=cmd_info)

    ap = sub.add_parser("index", help="Build the partition-direct index.")
    ap.add_argument("tib")
    ap.add_argument("--out", help="Output path (default: <tib>.idx).")
    ap.add_argument("--force", action="store_true", help="Rebuild even if cached.")
    ap.set_defaults(func=cmd_index)

    ap = sub.add_parser("verify", help="Validate volume-header Adler32.")
    ap.add_argument("tib")
    ap.set_defaults(func=cmd_verify)

    ap = sub.add_parser("ls", help="List files in the .tib's filesystem.")
    ap.add_argument("tib")
    ap.add_argument("path", nargs="?", default="")
    ap.set_defaults(func=cmd_ls)

    ap = sub.add_parser("extract", help="Extract a single file.")
    ap.add_argument("tib")
    ap.add_argument("path", help="Path within the .tib's filesystem.")
    ap.add_argument("-o", "--out", help="Output path (default: basename of source).")
    ap.set_defaults(func=cmd_extract)

    ap = sub.add_parser(
        "tibx-info",
        help="Show .tibx (archive3) structure summary [experimental].",
    )
    ap.add_argument("tibx")
    ap.add_argument(
        "--max-segments",
        type=int,
        default=200,
        help="Cap segment-scan at this many segments (default: 200; "
             "use 0 for full file scan).",
    )
    ap.set_defaults(func=cmd_tibx_info)

    ap = sub.add_parser(
        "tibx-stat",
        help="Show .tibx LSM-tree status (per-tree ctree summary) [experimental].",
    )
    ap.add_argument("tibx")
    ap.set_defaults(func=cmd_tibx_stat)

    ap = sub.add_parser(
        "tibx-verify",
        help="Validate every page's CRC-32C in a .tibx file [experimental].",
    )
    ap.add_argument("tibx")
    ap.add_argument(
        "--sample",
        type=int,
        default=1000,
        help="Verify a random sample of N pages (default: 1000). "
             "Ignored when --full is given.",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Seed for the sampling RNG (default: 0; deterministic).",
    )
    ap.add_argument(
        "--full",
        action="store_true",
        help="Walk every page in the file (slow; ~51 GiB on the test "
             "archive). Without the optional 'crc32c' C extension this "
             "may take several minutes.",
    )
    ap.set_defaults(func=cmd_tibx_verify)

    ap = sub.add_parser(
        "tibx-mount",
        help="Bootstrap NtfsVolume against a .tibx file [experimental].",
    )
    ap.add_argument("tibx")
    ap.set_defaults(func=cmd_tibx_mount)

    ap = sub.add_parser("mount", help="Mount the .tib's NTFS volume read-only.")
    ap.add_argument("tib")
    ap.add_argument("mountpoint")
    ap.add_argument("-f", "--foreground", action="store_true",
                    help="Don't daemonize (default: daemonize).")
    ap.set_defaults(func=cmd_mount)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        from .chunkmap_locator import UnsupportedTibFormat
        if isinstance(e, UnsupportedTibFormat):
            print(f"error: {e}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
