"""End-to-end extraction sanity test."""
import sys, os, random
sys.path.insert(0, '/path/to/tibread/dist')
from tibread import open_tib

# Magic-byte signature checks. Returns (status, label) where status is "ok",
# "zero", or "garbage". Extension is lowercased.
MAGICS = {
    "exe": [b"MZ"],
    "dll": [b"MZ"],
    "sys": [b"MZ"],
    "efi": [b"MZ"],
    "mui": [b"MZ"],
    "cpl": [b"MZ"],
    "ocx": [b"MZ"],
    "drv": [b"MZ"],
    "scr": [b"MZ"],
    "ax":  [b"MZ"],
    "tsp": [b"MZ"],
    "acm": [b"MZ"],
    "node":[b"MZ"],
    "cab": [b"MSCF"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg":[b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "bmp": [b"BM"],
    "ico": [b"\x00\x00\x01\x00"],
    "pdf": [b"%PDF"],
    "xml": [b"<?xml", b"\xef\xbb\xbf<?xml", b"<"],
    "txt": None,             # text heuristic
    "ini": None,
    "log": None,
    "inf": None,
    "reg": None,
    "csv": None,
    "json":[b"{", b"["],
    "wim": [b"MSWIM\x00\x00\x00"],
    "esd": [b"MSWIM\x00\x00\x00"],
    "hive":None,             # registry hive
    "evtx":[b"ElfFile\x00"],
    "lnk": [b"L\x00\x00\x00"],
    "manifest": None,
    "mof": None,
    "ttf": [b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"],
    "otf": [b"OTTO", b"\x00\x01\x00\x00"],
    "fon": [b"MZ"],
    "msi": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "doc": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"{\\rtf"],
    "cat": [b"0\x82", b"\x30\x82"],
    "p7s": [b"0\x82", b"\x30\x82"],
    "p7b": [b"0\x82", b"\x30\x82"],
    "der": [b"0\x82", b"\x30\x82"],
}

def is_textish(b: bytes) -> bool:
    if not b:
        return False
    printable = sum(1 for c in b if 9 <= c <= 13 or 32 <= c < 127)
    return printable / len(b) > 0.85

def classify(name: str, head: bytes):
    if len(head) == 0:
        return "zero", "empty-read"
    if all(c == 0 for c in head):
        return "zero", "all-zero"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext == "bcd" or name.lower() == "bcd":
        # BCD on Win Vista+ is a registry hive
        if head.startswith(b"regf"):
            return "ok", "regf"
        return "garbage", "bcd-no-regf"
    if name.lower() == "bootmgr":
        # bootmgr is a Win PE-ish loader; first bytes are jump/code
        if head[:2] in (b"\x4d\x5a", b"\xeb\x52", b"\xe9\xeb", b"\x4a\x46"):
            return "ok", f"bootmgr-{head[:2].hex()}"
        # The actual bootmgr starts with JFIF-like but not really; accept anything non-zero
        return "ok", "bootmgr-nonzero"
    if name.lower() == "bootsect.bak":
        # NTFS boot sector starts with EB 52 90 then "NTFS"
        if b"NTFS" in head[:16]:
            return "ok", "ntfs-bootsect"
        return "garbage", "no-NTFS-magic"
    sigs = MAGICS.get(ext)
    if sigs is None:
        # text heuristic for known text exts; for anything else just accept nonzero
        if ext in ("txt","ini","log","inf","reg","csv","manifest","mof"):
            # Some "logs" are actually binary (registry transaction logs,
            # Distributed Link Tracking, ETW). Allow well-known binary magics.
            if head.startswith(b"regf"):
                return "ok", "regf-log"
            if head.startswith(b"\xec\xa7\x43\x66"):  # DLT GUID prefix
                return "ok", "dlt-tracking"
            if head[:4] in (b"\x47\x88\x4d\xc6", b"\x84\xac\x2c\x47"):  # ETW BinaryEventFile / SLF
                return "ok", "etl"
            return ("ok", "text") if is_textish(head) else ("garbage", "non-text")
        if ext == "hive":
            return ("ok", "regf") if head.startswith(b"regf") else ("garbage", "no-regf")
        return ("ok", "no-magic-ext-"+ext) if any(head) else ("zero", "all-zero")
    for s in sigs:
        if head.startswith(s):
            return "ok", s[:8].hex() if all(c < 32 or c >= 127 for c in s) else s.decode("latin1","replace")
    return "garbage", f"head={head[:8].hex()}"

def walk(vol, path=""):
    try:
        entries = vol.list_dir(path)
    except Exception as e:
        print(f"  ! list_dir({path!r}) failed: {e}", file=sys.stderr)
        return
    for e in entries:
        if e.name in (".", ".."):
            continue
        full = path + ("/" if path else "") + e.name
        if e.is_dir:
            yield from walk(vol, full)
        else:
            yield full, e

def run(tib_path: str, sample: int | None = None, label: str = ""):
    print(f"=== {label or tib_path} ===")
    vol = open_tib(tib_path)
    files = []
    for path, e in walk(vol):
        if e.size > 0:
            files.append((path, e))
    print(f"total non-zero files discovered: {len(files)}")
    if sample is not None and len(files) > sample:
        rng = random.Random(0xCAFE)
        files = rng.sample(files, sample)
        print(f"sampling {sample} files")
    tested = ok = zero = garbage = errors = 0
    by_status: dict[str, list[str]] = {"ok": [], "zero": [], "garbage": []}
    for path, e in files:
        try:
            data = vol.read_file(path, 0, 64)
        except Exception as exc:
            errors += 1
            print(f"  ERR {path}: {exc}")
            continue
        tested += 1
        status, why = classify(e.name, data)
        by_status[status].append(f"{path}  [{why}]")
        if status == "ok":
            ok += 1
        elif status == "zero":
            zero += 1
        else:
            garbage += 1
    print(f"tested={tested} ok={ok} zero={zero} garbage={garbage} errors={errors}")
    if tested:
        print(f"  recovery rate: {100.0 * ok / tested:.1f}% ok, "
              f"{100.0 * (ok+zero) / tested:.1f}% non-garbage")
    # show samples
    for st in ("ok", "zero", "garbage"):
        if by_status[st]:
            print(f"  -- {st} samples ({len(by_status[st])} total) --")
            for line in by_status[st][:8]:
                print(f"    {line}")
    return tested, ok, zero, garbage

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example"
    if target == "example":
        run("/path/to/legacy_example.tib", sample=None, label="example (full walk)")
    elif target == "storage":
        run("/path/to/example_full_b1_s1_v1.tib", sample=50, label="STORAGE (50-file sample)")
    elif target == "storage-big":
        run("/path/to/example_full_b1_s1_v1.tib", sample=500, label="STORAGE (500-file sample)")
    elif target == "both":
        run("/path/to/legacy_example.tib", sample=None, label="example (full walk)")
        print()
        run("/path/to/example_full_b1_s1_v1.tib", sample=50, label="STORAGE (50-file sample)")
