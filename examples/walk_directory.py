"""Walk every file in a .tib and print the path + size."""
import sys
from tibread import open_tib

def walk(vol, path=""):
    for entry in vol.list_dir(path):
        if entry.name in (".", ".."):
            continue
        full = (path + "/" + entry.name).lstrip("/")
        if entry.is_dir:
            yield from walk(vol, full)
        else:
            yield full, entry.size

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: walk_directory.py <tib-path>")
    vol = open_tib(sys.argv[1])
    n = 0
    total = 0
    for path, size in walk(vol):
        print(f"{size:>12,}  {path}")
        n += 1
        total += size
    print(f"\n{n:,} files, {total/1024**3:.1f} GiB")
