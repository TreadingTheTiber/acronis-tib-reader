#!/usr/bin/env python3
"""
verify_tib_header.py — sanity-check the volume-header Adler32 of a .tib file.

The 32-byte volume header at offset 0 stores a u32 Adler32 at offset 0x18
covering bytes [0..hdr_len) with [0x18..0x1C] zeroed.

Confirmed via decompilation of `product.bin`:
  - Writer:   FUN_08216020  (archive_struct_helper.cpp; zeros [0x18..0x1C],
              calls zlib adler32(0,0,0) then adler32(state, hdr, hdr_len),
              stores the 32-bit result back at [hdr+0x18]).
  - Verifier: FUN_08216280  (caller of CheckVolumeHeader at FUN_082160c0;
              copies header to local buffer, zeroes the field, recomputes
              adler32, then `cmp eax, [hdr+0x18]`).
  - Adler:    FUN_08b6f260  (verbatim zlib adler32 — 0xfff1 mod, 0x15b0 NMAX,
              16-byte unrolled inner loop).

Length used = `hdr_len` = `*(u16 *)(hdr+4)`, clamped to 32 (the writer also
clamps hdr_len). For Mac archives hdr_len may be 0x24 (36); the same
zero-the-checksum-field convention applies.

Usage:
    python3 verify_tib_header.py path/to/file.tib [path/to/another.tib ...]
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

VOLUME_MAGIC_SECTOR = 0xA2B924CE   # sector-mode (.tib image)
VOLUME_MAGIC_FS_V2  = 0x44686EB4   # filesystem-mode v2 (.tib, fixed 12-byte header, no Adler32)
VOLUME_MAGIC_FS_V1  = 0x8F5C36C6   # filesystem-mode v1 (.tib, older fixed 12-byte header)
# NOTE: incremental/differential is NOT encoded in the magic — it's in the
# filename (`_full_`/`_inc_`/`_diff_`) and the metadata XML.
VALID_MAGICS = {VOLUME_MAGIC_SECTOR, VOLUME_MAGIC_FS_V2, VOLUME_MAGIC_FS_V1}
VOLUME_MAGIC = VOLUME_MAGIC_SECTOR  # backwards-compat alias

ADLER_OFFSET = 0x18
ADLER_LEN = 4


def compute_header_adler(header: bytes, hdr_len: int) -> int:
    """
    Replicate the binary's behaviour:
      - take the first hdr_len bytes (clamped to 32 in the writer);
      - zero bytes [0x18..0x1C];
      - return zlib.adler32 over that buffer.
    """
    if hdr_len > 32:
        hdr_len = 32  # writer clamps; verifier reads len from header
    buf = bytearray(header[:hdr_len])
    buf[ADLER_OFFSET:ADLER_OFFSET + ADLER_LEN] = b"\x00\x00\x00\x00"
    return zlib.adler32(bytes(buf)) & 0xFFFFFFFF


def compute_header_adler32(path: str) -> tuple[bool, int, int]:
    """Return (ok, stored, computed) for the volume-header Adler32."""
    with open(path, "rb") as f:
        head = f.read(64)
    if len(head) < 32:
        raise ValueError(f"{path}: file too small ({len(head)} bytes)")
    magic, hdr_len, _version = struct.unpack_from("<IHH", head, 0)
    # Detect .tibx and other non-.tib formats with helpful messages.
    if head[7:12] == b"QARCH":
        from .chunkmap_locator import UnsupportedTibFormat
        raise UnsupportedTibFormat(
            ".tibx (TIB eXtended) is not supported by this reader."
        )
    if magic not in VALID_MAGICS:
        from .chunkmap_locator import UnsupportedTibFormat
        raise UnsupportedTibFormat(
            f"unknown magic {magic:#010x}; not a recognized .tib format."
        )
    stored = struct.unpack_from("<I", head, ADLER_OFFSET)[0]
    computed = compute_header_adler(head[:32], hdr_len)
    return (computed == stored), stored, computed


def verify(path: Path) -> bool:
    with path.open("rb") as f:
        head = f.read(64)
    if len(head) < 32:
        print(f"{path}: ERROR file too small")
        return False

    magic, hdr_len, version = struct.unpack_from("<IHH", head, 0)
    if magic not in VALID_MAGICS:
        print(f"{path}: ERROR bad magic 0x{magic:08x}")
        return False
    if hdr_len not in (0x20, 0x24):
        print(f"{path}: WARNING unusual hdr_len 0x{hdr_len:x}")

    archive_id, vol_id, sequence, stored_adler, block_align = struct.unpack_from(
        "<QIIII", head, 8
    )

    computed = compute_header_adler(head[:32], hdr_len)
    ok = computed == stored_adler

    print(
        f"{path}: magic=0x{magic:08x} ver={version} hdr_len={hdr_len} "
        f"archiveId=0x{archive_id:016x} volumeId=0x{vol_id:08x} seq={sequence} "
        f"stored=0x{stored_adler:08x} computed=0x{computed:08x} "
        f"=> {'OK' if ok else 'MISMATCH'}"
    )
    return ok


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for arg in argv[1:]:
        if not verify(Path(arg)):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
