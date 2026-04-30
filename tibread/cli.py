"""
tibread CLI — `tib` command-line entry point.

Subcommands:
  tib info <tib>                       Show .tib structure (header, streams, MFT).
  tib index <tib> [--out IDX]          Build (or rebuild with --force) the partition-direct index.
  tib verify <tib>                     Validate volume header Adler32 + structural checks.
  tib mount <tib> <mountpoint> [opts]  Mount the .tib's NTFS volume read-only via FUSE (Linux).
  tib extract <tib> <path-in-vol> [-o] Extract a single file by NTFS path.
  tib ls <tib> [<path>]                List files in the .tib's filesystem.

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
from .indexer import build_index, open_tib, _default_index_path


def cmd_info(args):
    from .chunkmap_locator import discover_chunkmap_offset, detect_format_era
    from .verify import compute_header_adler32

    tib = Path(args.tib)
    # Validate format up-front so unsupported variants (.tibx, fs-mode,
    # very-legacy) fail with a clean single-line error instead of partial
    # output. compute_header_adler32 raises UnsupportedTibFormat on .tibx
    # and unknown magics; detect_format_era covers very-legacy.
    compute_header_adler32(str(tib))
    print(f"tib file: {tib}  ({tib.stat().st_size:,} bytes)")
    era = detect_format_era(str(tib))
    print(f"  format era: {era}")
    if era == "modern":
        chunkmap_off, chunkmap_size = discover_chunkmap_offset(str(tib))
        print(f"  chunk-map: offset={chunkmap_off:,}  comp_size={chunkmap_size:,}")
    else:
        print(f"  chunk-map: inline (multiple SequentialChunkMap records "
              f"interleaved with the block stream)")
    ok, stored, computed = compute_header_adler32(str(tib))
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
