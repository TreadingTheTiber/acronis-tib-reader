"""Extract files matching a wildcard pattern from a .tib."""
import sys, fnmatch, os
from tibread import open_tib

def walk(vol, path=""):
    for entry in vol.list_dir(path):
        if entry.name in (".", ".."):
            continue
        full = (path + "/" + entry.name).lstrip("/")
        if entry.is_dir:
            yield from walk(vol, full)
        else:
            yield full, entry

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: extract_by_extension.py <tib-path> <glob-pattern> <out-dir>")
    tib_path, pattern, out_dir = sys.argv[1:]
    vol = open_tib(tib_path)
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    for path, entry in walk(vol):
        if fnmatch.fnmatch(path, pattern):
            data = vol.read_file(path)
            out_path = os.path.join(out_dir, os.path.basename(path))
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"  {len(data):>10,}  {out_path}")
            n += 1
    print(f"\nExtracted {n} files matching '{pattern}'")
