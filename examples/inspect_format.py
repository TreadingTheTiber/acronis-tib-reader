"""Programmatically inspect a .tib's structure."""
import sys
from tibread import discover_chunkmap_offset, detect_format_era, open_tib

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: inspect_format.py <tib-path>")
    path = sys.argv[1]
    print(f"file: {path}")
    era = detect_format_era(path)
    print(f"  format era: {era}")
    if era == "modern":
        off, size = discover_chunkmap_offset(path)
        print(f"  chunk-map at file offset {off:,}, compressed size {size:,}")
    vol = open_tib(path)
    print(f"  partition size:   {vol.disk.partition_size:,} bytes ({vol.disk.partition_size/1024**3:.1f} GiB)")
    print(f"  block count:      {vol.disk.block_count:,}")
    print(f"  clusters/block:   {vol.disk.clusters_per_block}")
    print(f"  preamble length:  {vol.disk.preamble_len}")
    print(f"  total NTFS files: {vol.total_files:,}")
