#!/usr/bin/env python3
"""
discover_chunkmap.py — self-describing locator for the on-disk chunk map
in an Acronis True Image sector-mode .tib backup.

Reverse-engineered from `product.bin` (Acronis True Image binary):
  - `ExtraFileChunkMap`         = FUN_089839b0 (k:/8029/resizer/backup/openimg.cpp)
  - `GetExtraFileImageParameters` = FUN_08984460 (same file)

`GetExtraFileImageParameters` walks an in-memory linked list, finds the node
keyed by tag 5, and returns 12 bytes from offset +0x20C of that node.
Those 12 bytes are `{u64 chunkmap_file_offset, u32 chunkmap_compressed_size}` —
the (offset, size) handed to `ExtraFileChunkMap`.

The on-disk source of those values is the .tib's metadata blob (the 780-byte
TLV blob that sits right before the 41-byte sector trailer body, at file
offset `data_start + metaDataOffset`).

== TLV layout decoded ==

The metadata blob is a TLV with various tags (0x4D, 0xD6, 0xD7, 0x8F, 0x48-
0x4F, 0x58, 0x81, 0x98, 0xA9, ...) describing the source machine, device
model, GUIDs, computer name, etc.  Inside one of those records (after the
"EXAMPLE-PC-Dgs"-style computer-name value in our sample) the chunk-map
locator is encoded as positional length-prefixed fields:

    01 00                 # 1-byte field, value 0x00 (purpose unknown)
    06 <6 byte LE>        # 6-byte LE: chunk-map TLV start, in CONCAT coords
                          # (concat = file - data_start, where data_start = 32)
    01 00                 # 1-byte field, value 0x00
    03 <3 byte LE>        # 3-byte LE: total chunk-map region size
                          # (= TLV preamble length + zlib stream length)
    [ ... rest of chunk-map's own TLV preamble copied here ... ]

The chunk map itself sits at `data_start + concat_offset` in file coords
and consists of:

    [1 byte: preamble_payload_len = 0x13]
    [19 bytes: preamble payload — 0x02-tag fields + the chunk-count etc.]
    [zlib-deflated stream]   <- starts with magic 78 01

The "preamble" is a small StoreReader-style header.  `build_skipmap_from_tib`
seeks past it (preamble_size = 1 + first_byte = 20 in this generation) and
hands the raw zlib stream to `zlib.decompress`.

== Discovery algorithm ==

1. Open the .tib, parse the volume header to get `data_start` (=32 for v0).
2. Parse the volume footer for `slice_size`, then read 8 bytes at
   `data_start + slice_size - 8` to get `trailer_size`.
3. Read the trailer body and parse `metaDataOffset` (offset 3..8, 6-byte LE,
   in concat coords).
4. Compute `metadata_blob_file_offset = data_start + metaDataOffset` and
   read backward to find a 780-ish-byte blob ending at the trailer body start.
   In practice the blob is a known size (we read 1 KiB before the trailer
   body and search the tail for our signature; the blob may be smaller or
   bigger across generations).
5. In that blob, search for the 13-byte signature
       06 <??>{6} 01 00 03 <??>{3}
   where:
     - the 6-byte LE value V is in `(1_000_000_000, metaDataOffset)`
     - the 3-byte LE value S is in `(1024, 100_000_000)`
   This pattern is unique on the test file.
6. Compute:
     chunkmap_tlv_file_offset = data_start + V
     preamble_size            = 1 + first byte at chunkmap_tlv_file_offset
                                (= 0x13 + 1 = 20 on this file)
     zlib_offset              = chunkmap_tlv_file_offset + preamble_size
     zlib_size                = S - preamble_size

Returns `(zlib_offset, zlib_size)` — the args expected by the existing
`build_skipmap_from_tib.decode_chunk_map(...)`.

== Verification on /path/to/example_full_b1_s1_v1.tib ==

  metaDataOffset           = 1,143,108,355,647  (concat)
  V (chunkmap_concat)       = 1,143,065,854,211  (concat; metaDataOffset - 42,501,436)
  S (total_size)            = 1,837,856          (= 20 + 1,837,836)
  preamble_size             = 20
  → zlib_offset             = 1,143,065,854,263  (matches DEFAULT_TIB_OFFSET)
  → zlib_size               = 1,837,836           (matches DEFAULT_COMPRESSED_SIZE)

Output skipmap CSV is byte-identical to the one produced with the
hardcoded constants.
"""
from __future__ import annotations
import os
import struct
from typing import Tuple

VOLUME_MAGIC = 0xA2B924CE
TRAILER_SECTOR = bytes.fromhex("2B8AE194")
TRAILER_FS = bytes.fromhex("2C8AE194")


class UnsupportedTibFormat(ValueError):
    """Raised when a file is identified as a .tib-family format the reader
    cannot handle (e.g., .tibx, filesystem-mode, encrypted)."""
    pass


class LegacyTibFormat(UnsupportedTibFormat):
    """Raised by the modern chunk-map locator when the file is a valid
    sector-mode .tib but pre-dates the modern chunk-map locator (TI 2014/
    2015/2016 era). `detect_format_era` catches this specifically to
    classify the file as 'legacy' — it must NOT be conflated with the
    other UnsupportedTibFormat causes (multi-volume, FS-mode trailer,
    very-legacy 4K sector, .tibx) which represent genuine read failures."""
    pass


def find_last_volume(path: str) -> str:
    """For multi-volume .tib backups (`*_v1.tib`, `*_v2.tib`, …), find the
    file with the highest sequence number. Returns the path unchanged
    when not a multi-volume name.

    Multi-volume backups split the block stream across N files but only
    the LAST one carries the metadata blob + chunk-map. To open the
    archive we always need the last volume.
    """
    import re
    m = re.match(r"^(.*_v)(\d+)(\.tib)$", path)
    if not m:
        return path
    prefix, _, ext = m.groups()
    n = 1
    while True:
        candidate = f"{prefix}{n + 1}{ext}"
        if not os.path.exists(candidate):
            break
        n += 1
    if n == 1:
        return path  # not actually multi-volume
    return f"{prefix}{n}{ext}"


def _read_volume_header(f) -> Tuple[int, int]:
    """Returns (data_start, version). Raises UnsupportedTibFormat for
    non-last volumes of a multi-volume backup."""
    f.seek(0)
    buf = f.read(32)
    magic, hdrlen, version = struct.unpack_from("<IHH", buf, 0)

    # Detect .tibx (TIB eXtended, TI 2020+) by its page envelope:
    #   byte 0 = 0x41 ('A'), byte 1 = page-type tag, byte 2 = 0,
    #   bytes 4..7 = u32 CRC-32C (varies per file),
    #   bytes 8..11 = ASCII signature for that page type.
    # The page-type byte tells us:
    #   0x01 ARCH page (master archive): ASCII "ARCH" at offset 8
    #   0x02 ARCI commit-index (rare to be page 0)
    #   0x03 LEAF page — typical of slice-continuation files (-0002.tibx,
    #         etc. that ship alongside a master)
    #   0x04 LDIR page — likewise a slice-continuation
    # The earlier "QARCH at offset 7" detection was a coincidence — the
    # example sample's CRC happened to end in 0x51 ('Q'). Real detection
    # is the magic at offset 8 plus the page-envelope shape.
    # .tibx page envelope: byte 0 = 0x41 ('A'), bytes 2-3 = 0, bytes 4-7 = CRC32C.
    # Page-type byte at offset 1 distinguishes:
    #   0x01 ARCH  master archive header (the only kind of file standalone-openable)
    #   0x02 ARCI  commit-index page
    #   0x03 LEAF  LSM tree leaf
    #   0x04 LDIR  LSM tree directory
    #   0x05       Golomb dedup filter
    #   0xff       SG segment data
    # Slice-continuation files (`*-NNNN.tibx`) start with any of 0x02..0xff.
    if buf[0] == 0x41 and buf[2] == 0 and buf[3] == 0 and buf[1] in (0x01, 0x02, 0x03, 0x04, 0x05, 0xff):
        page_type = buf[1]
        if page_type == 0x01 and buf[8:12] == b"ARCH":
            raise UnsupportedTibFormat(
                ".tibx (TIB eXtended) sector-mode reader for the master "
                "archive page is in tibread.tibx, not this module. Use "
                "TibxReader or `tib tibx-info` instead. (Detected ARCH "
                "page-type=0x01 at offset 8 + 0x41 page envelope at 0.)"
            )
        else:
            ptype_name = {
                0x01: "ARCH", 0x02: "ARCI", 0x03: "LEAF", 0x04: "LDIR",
                0x05: "GOLOMB", 0xff: "DATA",
            }.get(page_type, f"0x{page_type:02x}")
            raise UnsupportedTibFormat(
                f".tibx slice-continuation file detected (page-type {page_type:#x} "
                f"= {ptype_name}). These auxiliary files (`*-NNNN.tibx`) ship "
                f"alongside a master .tibx (the file WITHOUT a numeric suffix); "
                f"open the master file instead — tibread will load the slices "
                f"automatically when needed."
            )
    # Filesystem-mode .tib variants — known but not yet implemented.
    if magic == 0x44686EB4:
        raise UnsupportedTibFormat(
            "filesystem-mode .tib v2 (magic 0x44686EB4) is not yet implemented. "
            "tibread currently supports sector-mode .tib only."
        )
    if magic == 0x8F5C36C6:
        raise UnsupportedTibFormat(
            "filesystem-mode .tib v1 (magic 0x8F5C36C6) is not yet implemented. "
            "tibread currently supports sector-mode .tib only."
        )
    if magic != VOLUME_MAGIC:
        raise UnsupportedTibFormat(
            f"file does not appear to be an Acronis .tib backup "
            f"(magic={magic:#010x}, expected {VOLUME_MAGIC:#010x} for sector-mode)."
        )

    # Multi-volume detection: only the LAST volume carries the metadata
    # blob + chunk-map. A volume header's `sequence` field at offset 0x14
    # is 1-based; sequence>1 means "definitely not the last volume". For
    # sequence==1 we may still be the FIRST of many — caller must check
    # for sibling `*_vN.tib` files via `find_last_volume()`.
    sequence = struct.unpack_from("<I", buf, 0x14)[0]
    name = getattr(f, "name", "")
    if sequence > 1:
        # Try to point at the actual last volume.
        last = find_last_volume(name) if name else None
        last_hint = (
            f" The last volume of this chain appears to be: {last!r}"
            if last and last != name else ""
        )
        raise UnsupportedTibFormat(
            f"this .tib is volume #{sequence} of a multi-volume backup chain "
            f"(filename pattern `*_v<N>.tib`). Only the LAST volume carries "
            f"the metadata blob + chunk-map needed to open the archive.{last_hint} "
            f"Open the highest-numbered `_vN.tib` file instead."
        )
    # sequence == 1: could be a single-volume backup OR the first of many.
    # If siblings exist (a `_v2.tib` next to us), redirect to the last.
    if sequence == 1 and name:
        last = find_last_volume(name)
        if last != name:
            raise UnsupportedTibFormat(
                f"this .tib is volume #1 of a multi-volume backup chain. "
                f"The metadata + chunk-map live in the LAST volume. "
                f"Open `{os.path.basename(last)}` (sequence detected via "
                f"sibling-file scan) instead."
            )

    # "Very-legacy" detection (TI 2010-2013, builds 12000-15999):
    #   version == 1 AND header u32 at +0x1C == 0x1000 (4 KiB sector_size)
    # Acronis's own reader handles these by destructively MIGRATING the file
    # in-place to the modern format (`ConvertFromLegacyFormat`, FUN_091f6780).
    # We refuse to read them — recommend the user open in TI 2018+ once to
    # migrate, then come back. Per RE agent's recommendation in
    # docs/FORMAT_VERY_LEGACY.md.
    sector_size = struct.unpack_from("<I", buf, 0x1C)[0]
    if version == 1 and sector_size == 0x1000:
        raise UnsupportedTibFormat(
            "this is a very-legacy .tib (TI 2010-2013, version=1 + sector_size=0x1000). "
            "Acronis True Image 2018+ reads these by destructively migrating "
            "them in-place to the modern format. tibread doesn't support "
            "in-place migration. To read this file: open it ONCE in TI 2018+ "
            "(this will rewrite it as a modern .tib in place), then re-run tibread."
        )
    return hdrlen, version


def _read_trailer(f, file_size: int) -> Tuple[int, int, int, int]:
    """Returns (data_start, slice_size, metaDataOffset, trailer_body_size).
    metaDataOffset is in concat coords (relative to data_start)."""
    data_start, version = _read_volume_header(f)
    if version != 0:
        raise ValueError(f"only Windows v0 sector .tib supported (version={version})")

    # Volume footer: last 48 bytes; slice_size at footer offset 8 (LE u64)
    f.seek(file_size - 48)
    footer = f.read(48)
    slice_size = struct.unpack_from("<Q", footer, 8)[0]

    concat_end_file = data_start + slice_size

    # Last 4 bytes of concat = sector magic
    f.seek(concat_end_file - 4)
    magic = f.read(4)
    if magic != TRAILER_SECTOR:
        if magic == TRAILER_FS:
            raise UnsupportedTibFormat(
                "this .tib has a sector-mode volume header (magic 0xA2B924CE) "
                "but a filesystem-mode trailer (magic 0x94E18A2C). This is "
                "the layout Acronis True Image produces when backing up a "
                "file share (NAS / SMB) rather than a block device. The "
                "block-device-style chunk map this code expects does not "
                "exist for this variant. To recover the file CONTENT (without "
                "original filenames — those live in `f` directory records we "
                "haven't reverse-engineered yet) run: "
                "`tib extract-fs <tib> <output-dir>`."
            )
        raise UnsupportedTibFormat(
            f"unrecognized .tib trailer magic {magic.hex()} "
            f"(expected sector-mode {TRAILER_SECTOR.hex()})"
        )

    f.seek(concat_end_file - 8)
    trailer_size = struct.unpack("<I", f.read(4))[0]

    f.seek(concat_end_file - 8 - trailer_size)
    body = f.read(trailer_size)

    # Trailer body byte[2] = length-prefix byte for the metaDataOffset field.
    # For files larger than 4 GB but ≤2⁴⁸ bytes (older small .tib) this is 5;
    # for files needing a 6-byte LE encoding (~256 TB max) it's 6. Accept any
    # plausible value 4..8 to handle the full size range.
    n = body[2]
    if not (4 <= n <= 8):
        raise ValueError(f"unexpected trailer body byte[2]={body[2]:#x} (want 4..8)")
    if 3 + n > len(body):
        raise ValueError(f"trailer body too short for {n}-byte metaDataOffset")
    meta_offset = int.from_bytes(body[3:3 + n], "little")

    return data_start, slice_size, meta_offset, trailer_size


def detect_format_era(tib_path: str) -> str:
    """Returns 'modern' or 'legacy'.

    Detection strategy mirrors product.bin's FUN_08973290: the legacy
    sector-mode `.tib` (TI 2014/2015/2016 era) does NOT carry a modern
    chunk-map locator (`06 V[6] 01 00 03 S[3]`) in its metadata blob;
    the modern format does. We probe the metadata-blob region for the
    13-byte locator signature and classify accordingly.

    Note: this is structurally equivalent to the binary's `tag 0x9b`
    presence test — modern stores tag 0x9b's body as the chunk-map
    locator, and the locator's 13-byte signature is the visible
    fingerprint.
    """
    try:
        _modern_chunkmap_offset(tib_path)
        return "modern"
    except LegacyTibFormat:
        # The locator-not-found case — a real legacy .tib that lacks the
        # 13-byte chunk-map locator signature. Other UnsupportedTibFormat
        # causes (multi-volume non-last, FS-mode trailer, very-legacy 4K,
        # .tibx) propagate so the caller sees the precise reason instead
        # of a misleading "legacy" classification.
        return "legacy"


def discover_chunkmap_offset(tib_path: str) -> Tuple[int, int]:
    """Find the on-disk chunk-map zlib stream's file offset and compressed size.

    Returns (zlib_offset, zlib_size) suitable for
    `build_skipmap_from_tib.decode_chunk_map(tib_path, file_offset, compressed_size)`.

    Raises UnsupportedTibFormat if the chunk-map locator can't be found
    (e.g. legacy format — call `detect_format_era` first to dispatch).
    """
    return _modern_chunkmap_offset(tib_path)


def _modern_chunkmap_offset(tib_path: str) -> Tuple[int, int]:
    file_size = os.path.getsize(tib_path)
    with open(tib_path, "rb") as f:
        data_start, slice_size, meta_offset, trailer_size = _read_trailer(f, file_size)

        # Metadata blob lives between previous-record-end and the trailer body.
        # Read a generous 4 KiB before the trailer body and search its tail for
        # the chunk-map locator signature.  The blob is ~780 bytes in this
        # generation but may be larger in other backups.
        concat_end_file = data_start + slice_size
        trailer_body_start = concat_end_file - 8 - trailer_size
        metadata_blob_end = trailer_body_start
        scan_window = 4096
        scan_start = max(data_start, metadata_blob_end - scan_window)
        f.seek(scan_start)
        blob = f.read(metadata_blob_end - scan_start)

        # Search for the unique signature:
        #   06 <V:6 LE> 01 00 03 <S:3 LE>
        # where:
        #   meta_offset - 1 GiB < V < meta_offset
        #   1024 < S < 100 MiB
        candidates = []
        n = len(blob)
        for i in range(n - 12):
            if (
                blob[i] == 0x06
                and blob[i + 7] == 0x01
                and blob[i + 8] == 0x00
                and blob[i + 9] == 0x03
            ):
                V = int.from_bytes(blob[i + 1 : i + 7], "little")
                S = int.from_bytes(blob[i + 10 : i + 13], "little")
                # V is a concat offset; sane range: positive, less than
                # meta_offset, and within ~1 GiB before it (chunk map is
                # typically tens of MB before the metadata blob).
                if (
                    0 < V < meta_offset
                    and (meta_offset - V) < (1 << 30)
                    and 1024 < S < (100 << 20)
                ):
                    candidates.append((scan_start + i, V, S))

        if not candidates:
            raise LegacyTibFormat(
                "this .tib has a valid sector-mode header but no on-disk "
                "chunk-map locator was found in its metadata blob. "
                "This usually means the file is a pre-2018 Acronis True "
                "Image generation (TI 2014/2015/2016) that predates the "
                "ExtraFileChunkMap feature. The legacy walker handles "
                "these via inline SequentialChunkMap records — call "
                "`detect_format_era` to dispatch."
            )
        if len(candidates) > 1:
            # In practice the signature is unique on the test files we've
            # seen. If we ever see multiple, the chunk map is the one whose
            # V points to the start of the post-data region — i.e. the
            # candidate with the SMALLEST V (farthest from meta_offset).
            candidates.sort(key=lambda c: c[1])
        chosen = candidates[0]

        _blob_pos, V, S = chosen

        # Read first byte of the chunkmap TLV preamble to get its size.
        chunkmap_tlv_file = data_start + V
        f.seek(chunkmap_tlv_file)
        first_byte = f.read(1)[0]
        preamble_size = 1 + first_byte  # 1 length byte + payload

        zlib_offset = chunkmap_tlv_file + preamble_size
        zlib_size = S - preamble_size

        # Sanity: zlib stream should start with 78 01 (or 78 9C / 78 DA)
        f.seek(zlib_offset)
        zhdr = f.read(2)
        if zhdr[:1] != b"\x78":
            raise ValueError(
                f"computed zlib_offset {zlib_offset} doesn't start with 0x78 "
                f"(got {zhdr.hex()}); discovery failed"
            )

        return zlib_offset, zlib_size


def main():
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 discover_chunkmap.py <path_to_tib>")
        sys.exit(1)
    tib = sys.argv[1]
    offset, size = discover_chunkmap_offset(tib)
    print(f"chunk-map zlib stream:")
    print(f"  file offset:     {offset:,}")
    print(f"  compressed size: {size:,}")


if __name__ == "__main__":
    main()
