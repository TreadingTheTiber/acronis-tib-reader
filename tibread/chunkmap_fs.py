"""
chunkmap_fs.py — walker for the FS-mode hybrid `.tib` variant.

This is the layout produced by Acronis True Image when backing up a
file share rather than a block device. We've seen one specimen in the
wild (`share_backup_example.tib`, TI 2016). The volume header is
byte-shape-identical to sector-mode (magic ``0xA2B924CE``) but the
trailer magic is ``0x94E18A2C`` (FS-mode sentinel) and the body is a
generic block-store stream of three record types:

    [u8 type] [zlib stream]
    [u8 type] [zlib stream]
    ...

Per Ghidra RE on `archive_data_stream_tib_file_impl.cpp` and
empirical dissection of real records:

* ``0x6D`` ('m') — file-content chunk (≤ 256 KiB plaintext, zlib STORED)
* ``0x6E`` ('n') — end-of-file marker (8-byte zlib-of-empty)
* ``0x66`` ('f') — **metadata-batch start**. Despite appearing as a
  single "record" to a naive walker, an f-batch is a sequence of N
  ``[44-byte preamble][zlib stream → ~400-byte Acronis-serialized NTFS
  attribute blob]`` pairs (N typically 9–20). Each preamble starts
  with ``66 63 60 00 02 00 1d f7 22 c6 01`` (11 fixed bytes), then 11
  bytes that vary on first stream of a batch, then 22 bytes of cursor
  state (likely u32 file_index + u8[16] md5 + u16 flags), then the
  ``78 01`` zlib magic. The inflated payload has fixed magic
  ``01 02 00 10 01 00 00 00`` followed by ``u64 file_size``,
  ``u32 num_extents``, padding, ``u8[16] md5``, an extent table
  (32 B × N), then a 208-byte trailer = NTFS Security Descriptor +
  optional ADS attribute name as UTF-16-LE.

Each f-batch is a **prefix manifest** for the next N files in the
m/n stream — verified by sandwich evidence: the JPEG following one
f-batch contained EXIF for the camera the metadata identified.

A "logical file" is the run of ``m`` chunks ending at the next ``n``.
``f`` records are out-of-band metadata, NOT iterated by the file
cursor and NOT a file boundary — the writer flushes accumulated
metadata into the same physical block stream periodically.

Limitations
-----------

* **Primary filenames are unknown.** They live in a separate directory
  tree blob, likely in the high-entropy 16 MiB region near EOF that
  we currently halt at. Files are emitted as ``recovered_NNNNNN.<ext>``
  with the extension sniffed from content magic.
* This walker has only been validated against the single
  ``share_backup_example.tib`` sample. Other share-mode .tib
  files may use additional record types we haven't seen, and v2 of
  the FS-mode format (TI 2018+) uses a flat ``u64`` cursor stride
  instead of the v1 ``(u32 index, u8[16] md5)`` chained MD5 model.

References
----------

* Static-RE notes from the Ghidra session on Acronis True Image's
  ``product.bin`` (``FUN_08533640`` v1 OpenForRead, ``FUN_08530170``
  GetValue, ``FUN_0852ca40`` MoveNext, ``FUN_085313f0`` directory-tree
  copy, ``FUN_0853b380`` cursor init).
* Empirical sample-dissection of the three f-batches at file offsets
  0x163b8f6 (20 streams), 0x43353b0 (12 streams), 0x589e506 (9 streams)
  in the reference share_backup file.
* See also ``/path/to/tibread/FILESYSTEM_MODE_TIB.md`` (RE Agent K,
  2026-04-30) for the higher-level iterator / vtable layout.
"""
from __future__ import annotations

import os
import zlib
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple


# Volume header is 32 bytes; the body starts immediately after.
DATA_START = 32

# Record-type codes.
TYPE_FILE_CHUNK = 0x6D     # 'm'
TYPE_FILE_END = 0x6E       # 'n'
TYPE_DIR_RECORD = 0x66     # 'f'  (format unknown; skipped)

KNOWN_CONTENT_TYPES = {TYPE_FILE_CHUNK, TYPE_FILE_END}

# Maximum bytes to scan past an unknown record looking for the next
# valid `[m|n][78 01]` pattern. 8 MiB covers all `f` records seen in
# the reference sample (max observed: 8 KiB).
SKIP_LOOKAHEAD = 8 * 1024 * 1024


@dataclass
class FsRecord:
    """One walked record."""
    offset: int           # file offset of the type byte
    type_byte: int        # 0x6D / 0x6E / 0x66 / unknown
    comp_len: int         # length of the zlib stream (0 if no zlib)
    plain: Optional[bytes]  # decompressed bytes; None if record was skipped


# Per-stream preamble inside an f-batch. Verified empirically across all
# 41 streams in the three observed f-batches.
META_PREAMBLE_LEN = 44
META_PREAMBLE_FIXED = bytes.fromhex("6663600002001df722c601")  # first 11 bytes

# The inflated metadata blob's fixed leading magic.
META_BLOB_MAGIC = bytes.fromhex("0102001001000000")  # 8 bytes

# Trailing region after the extent table is constant size.
META_TRAILER_LEN = 208


@dataclass
class FsExtent:
    """One per-extent entry inside a file's metadata blob (32 bytes)."""
    md5: bytes              # 16-byte md5 of the extent's content
    attr_id: int            # u32 — likely DATA-stream identifier
    logical_offset: int     # u64 — offset of this extent in the file


@dataclass
class FsFileMetadata:
    """Per-file metadata extracted from one stream inside an f-batch.

    Each f-batch is a prefix manifest: this metadata describes one of
    the next N files emitted in the `m`/`n` stream. The order within
    the batch matches the order of files that follow.
    """
    file_size: int          # u64 — authoritative file size
    num_extents: int        # u32
    md5_content: bytes      # u8[16] — MD5(file content); matches MoveNext cursor
    extents: list           # list[FsExtent]
    security_descriptor: bytes  # NTFS SD (relative form), or b'' if absent
    ads_name: Optional[str]     # UTF-16-LE-decoded ADS attribute name, e.g.
                                # ":encryptable:$DATA"; None if no ADS


def _consume_zlib_from_bytes(data: bytes, offset: int = 0) -> Tuple[int, bytes]:
    """Inflate a zlib stream starting at ``data[offset:]``. Returns
    (compressed_length, decompressed_bytes)."""
    d = zlib.decompressobj()
    plain = d.decompress(data[offset:])
    consumed = len(data) - offset - len(d.unused_data)
    return consumed, plain


def _decode_metadata_blob(blob: bytes) -> Optional[FsFileMetadata]:
    """Parse one inflated f-batch metadata blob.

    The blob layout is:

      +0x00  u8[8]   magic = 01 02 00 10 01 00 00 00
      +0x08  u64     file_size
      +0x10  u32     num_extents
      +0x14  u64     reserved (zero)
      +0x1C  u32     reserved (varies)
      +0x20  u32     reserved (varies)
      +0x24  u32     zero
      +0x28  u8[16]  md5_of_file_content (matches MoveNext cursor)
      +0x38  u8[8]   tail-marker (varies — class-id?)
      +0x40  FsExtent[num_extents]    32 B each
      +0x40+32N      Variable-length trailer:
                       - 8 B padding zeros
                       - NTFS Security Descriptor (variable length —
                         R3 had 140 B, R2 had ~200 B)
                       - Optional ADS-attribute slot:
                            u32 attr_id, u32 zero, u32 name_byte_len,
                            u16[name_byte_len/2] UTF-16-LE name
                       - u64 file_size_replica + 16 B zeros

    Returns None if the magic doesn't match or the extent count is
    implausible (so we don't drift on misaligned input).
    """
    import struct
    MIN_TRAILER = 24   # at minimum: 8 B pad + 16 B trailing zeros
    if len(blob) < 0x40 + MIN_TRAILER:
        return None
    if blob[:8] != META_BLOB_MAGIC:
        return None
    file_size = struct.unpack_from("<Q", blob, 0x08)[0]
    num_extents = struct.unpack_from("<I", blob, 0x10)[0]
    if num_extents > 4096:
        return None
    extent_table_end = 0x40 + 32 * num_extents
    if extent_table_end + MIN_TRAILER > len(blob):
        return None
    md5 = bytes(blob[0x28:0x38])

    extents = []
    eo = 0x40
    for _ in range(num_extents):
        ext_md5 = bytes(blob[eo:eo + 16])
        attr_id = struct.unpack_from("<I", blob, eo + 16)[0]
        log_off = struct.unpack_from("<Q", blob, eo + 24)[0]
        extents.append(FsExtent(md5=ext_md5, attr_id=attr_id,
                                logical_offset=log_off))
        eo += 32

    trailer = blob[eo:]
    # The trailer holds the NTFS Security Descriptor (variable-length,
    # starts after 8 bytes of zero padding) and optionally an
    # ADS-attribute-name slot. We extract:
    #   * The full SD bytes [confirmed: revision=1, control=0x8004 in
    #     observed samples]
    #   * The ADS name as UTF-16-LE if a name slot is present and decodes
    sd = b""
    ads = None
    # Skip leading 8 bytes of padding zeros, then SD starts.
    sd_start = 8
    if len(trailer) > sd_start + 4:
        rev = trailer[sd_start]
        if rev == 1:
            # NTFS SD relative-form: rev=1 + sbz + control u16 + 4×u32
            # offset_owner / offset_group / offset_sacl / offset_dacl.
            # The SD's true length is hard to pin down without parsing
            # the ACE lists; we use the offset to the ADS-name slot
            # (if any) as a delimiter. Heuristic: scan the trailer for
            # a u32 that looks like a UTF-16-byte-length (multiple of 2,
            # 2..255) followed by valid UTF-16-LE bytes.
            sd_end = len(trailer)
            for probe in range(sd_start + 16, len(trailer) - 12, 4):
                attr_id = int.from_bytes(trailer[probe:probe + 4], "little")
                _zero = int.from_bytes(trailer[probe + 4:probe + 8], "little")
                name_len = int.from_bytes(trailer[probe + 8:probe + 12], "little")
                if (_zero == 0 and 4 <= name_len <= 200 and name_len % 2 == 0
                        and probe + 12 + name_len <= len(trailer)):
                    name_bytes = trailer[probe + 12:probe + 12 + name_len]
                    try:
                        candidate = name_bytes.decode("utf-16-le")
                    except UnicodeDecodeError:
                        continue
                    if candidate.startswith(":") or candidate.startswith("$"):
                        ads = candidate
                        sd_end = probe
                        break
            sd = bytes(trailer[sd_start:sd_end])
    return FsFileMetadata(
        file_size=file_size,
        num_extents=num_extents,
        md5_content=md5,
        extents=extents,
        security_descriptor=sd,
        ads_name=ads,
    )


def _find_next_zlib(buf: bytes, start: int, max_lookahead: int = 80) -> int:
    """Scan forward up to ``max_lookahead`` bytes for ``0x78 0x01``.

    The per-stream preamble in an f-batch has a variable-length cursor
    field (we've seen 20- and 22-byte variants ending in ``0x6C``), so
    we can't assume a fixed offset. ``max_lookahead`` of 80 covers all
    observed forms with margin.
    """
    end = min(len(buf) - 1, start + max_lookahead)
    for i in range(start, end):
        if buf[i] == 0x78 and buf[i + 1] == 0x01:
            return i
    return -1


def parse_metadata_batch(batch_bytes: bytes) -> list:
    """Parse one f-batch (the contiguous bytes spanning a sequence of
    ``[variable-length preamble][zlib stream]`` pairs). Returns
    ``list[FsFileMetadata]`` — one per stream in the batch, in order.

    Robust against:
      * Variable preamble length (20- or 22-byte cursor → 42- or 44-byte
        total preamble).
      * Variable-length trailer (R3 had 208 B, R2 had ~292 B — depends
        on Security Descriptor and ADS-name complexity).
      * False-positive signature matches inside compressed payload
        (those simply fail the inflate or magic check and get skipped).
      * Non-standard first record (R1 of the reference file is a
        single raw-deflate volume blob, not a metadata batch — we
        return [] for those rather than partial garbage).
    """
    import re
    n = len(batch_bytes)
    if n < len(META_PREAMBLE_FIXED) + 4:
        return []
    sigs = [m.start() for m in
            re.finditer(re.escape(META_PREAMBLE_FIXED), batch_bytes)]
    if not sigs:
        return []

    out = []
    last_consumed_end = 0
    for sig_pos in sigs:
        # Skip signatures that fall inside an already-consumed zlib stream
        # (those are false positives from compressed data).
        if sig_pos < last_consumed_end:
            continue
        zlib_off = _find_next_zlib(batch_bytes,
                                   sig_pos + len(META_PREAMBLE_FIXED),
                                   max_lookahead=80)
        if zlib_off < 0:
            continue
        try:
            comp_len, plain = _consume_zlib_from_bytes(batch_bytes, zlib_off)
        except zlib.error:
            continue
        meta = _decode_metadata_blob(plain)
        if meta is not None:
            out.append(meta)
            last_consumed_end = zlib_off + comp_len
    return out


def _consume_zlib(f, max_extra: int = 16 << 20) -> Tuple[int, bytes]:
    """Inflate the zlib stream at the file's current position, returning
    (compressed_length, decompressed_bytes)."""
    d = zlib.decompressobj()
    out = bytearray()
    consumed = 0
    while not d.eof:
        buf = f.read(64 * 1024)
        if not buf:
            raise ValueError("EOF while inflating zlib stream")
        out.extend(d.decompress(buf))
        consumed += len(buf)
        if d.eof:
            break
        if consumed > max_extra and not out:
            raise ValueError("zlib stream produced no output after 16 MiB")
    return consumed - len(d.unused_data), bytes(out)


def _find_next_known_record(f, start: int, end: int,
                            max_skip: int = SKIP_LOOKAHEAD) -> Optional[int]:
    """Scan forward for the next byte ∈ KNOWN_CONTENT_TYPES followed by
    zlib magic 0x78 0x01 at +1. Returns the file offset, or None."""
    pos = start
    limit = min(end, start + max_skip)
    while pos + 3 <= limit:
        f.seek(pos)
        chunk = f.read(min(65536, limit - pos))
        if not chunk:
            return None
        n = len(chunk)
        for i in range(n - 2):
            if (chunk[i] in KNOWN_CONTENT_TYPES
                    and chunk[i + 1] == 0x78 and chunk[i + 2] == 0x01):
                return pos + i
        # Step forward but keep a 2-byte overlap in case the pattern
        # straddles the chunk boundary.
        pos += max(1, n - 2)
    return None


def is_fs_mode_hybrid(tib_path: str) -> bool:
    """Quick predicate: does this .tib have a sector-mode volume header
    but an FS-mode trailer?

    The trailer magic does NOT live at ``file_size - 4`` — that position
    holds the sector-mode footer's mirrored volume magic. The 4-byte
    ``Trailer`` lives at ``data_start + slice_size - 4`` where
    ``data_start = hdrlen`` (32 for sector-mode) and ``slice_size`` is
    a u64 LE in the 48-byte footer at file_size-40.
    """
    import struct
    file_size = os.path.getsize(tib_path)
    if file_size < 96:
        return False
    with open(tib_path, "rb") as f:
        head = f.read(8)
        if struct.unpack_from("<I", head, 0)[0] != 0xA2B924CE:
            return False
        hdrlen = struct.unpack_from("<H", head, 4)[0]
        if hdrlen != 32:
            return False
        f.seek(file_size - 48)
        footer = f.read(48)
        if len(footer) != 48:
            return False
        slice_size = struct.unpack_from("<Q", footer, 8)[0]
        concat_end = hdrlen + slice_size
        if concat_end > file_size or concat_end < 4:
            return False
        f.seek(concat_end - 4)
        magic = f.read(4)
    return magic == bytes.fromhex("2C8AE194")


def walk_fs_records(tib_path: str, *, max_records: Optional[int] = None,
                    max_offset: Optional[int] = None) -> Iterator[FsRecord]:
    """Walk records from ``DATA_START`` forward.

    Halts when:
      * end of file (or ``max_offset``) is reached
      * ``max_records`` records have been yielded
      * an unknown record type is hit AND no further known record can
        be found within ``SKIP_LOOKAHEAD`` bytes

    Yields :class:`FsRecord` tuples. For ``f`` (metadata batch) records
    and any other unknown type, ``plain`` is set to the raw batch bytes
    (caller can pass to :func:`parse_metadata_batch` for f records) and
    ``comp_len`` is the on-disk span until the next known record.
    """
    file_size = os.path.getsize(tib_path)
    end = min(file_size, max_offset) if max_offset is not None else file_size
    yielded = 0

    with open(tib_path, "rb") as f:
        cur = DATA_START
        while cur < end:
            f.seek(cur)
            head = f.read(8)
            if len(head) < 4:
                return
            t = head[0]

            if t in KNOWN_CONTENT_TYPES and head[1] == 0x78 and head[2] == 0x01:
                f.seek(cur + 1)
                try:
                    comp_len, plain = _consume_zlib(f)
                except Exception:
                    nxt = _find_next_known_record(f, cur + 1, end)
                    if nxt is None:
                        return
                    yield FsRecord(offset=cur, type_byte=t, comp_len=nxt - cur,
                                   plain=None)
                    cur = nxt
                    yielded += 1
                    if max_records is not None and yielded >= max_records:
                        return
                    continue
                yield FsRecord(offset=cur, type_byte=t, comp_len=comp_len,
                               plain=plain)
                cur += 1 + comp_len
                yielded += 1
                if max_records is not None and yielded >= max_records:
                    return
                continue

            # Unknown record type — try to skip past it. Capture the raw
            # bytes so callers can decode f-batch metadata.
            nxt = _find_next_known_record(f, cur + 1, end)
            if nxt is None:
                return
            f.seek(cur)
            raw = f.read(nxt - cur)
            yield FsRecord(offset=cur, type_byte=t, comp_len=nxt - cur,
                           plain=raw)
            cur = nxt
            yielded += 1
            if max_records is not None and yielded >= max_records:
                return


def _sniff_extension(content: bytes) -> str:
    """Choose a file extension from content magic bytes."""
    if len(content) < 4:
        return "bin"
    m4 = content[:4]
    m8 = content[:8] if len(content) >= 8 else m4
    if m4[:3] == b"\xff\xd8\xff":
        return "jpg"
    if m4 == b"\x89PNG":
        return "png"
    if m4 == b"GIF8":
        return "gif"
    if m4 == b"PK\x03\x04":
        return "zip"
    if m4[:2] == b"MZ":
        return "exe"
    if m4 == b"%PDF":
        return "pdf"
    if m4 == b"\x7fELF":
        return "elf"
    if m4 == b"RIFF":
        return "riff"
    if len(content) >= 12 and content[4:8] == b"ftyp":
        # ISO-base media: MOV / MP4 / 3GP / HEIC...
        brand = content[8:12]
        if brand == b"qt  ":
            return "mov"
        if brand[:3] in (b"mp4", b"iso", b"avc"):
            return "mp4"
        return "mp4"
    if m4 == b"\xd0\xcf\x11\xe0":
        return "doc"
    if m4 == b"OggS":
        return "ogg"
    if m4 == b"fLaC":
        return "flac"
    if m8[:4] == b"\x1aE\xdf\xa3":
        return "mkv"
    if m4 == b"BM\x00\x00" or content[:2] == b"BM":
        return "bmp"
    # ASCII text heuristic
    sample = content[:128]
    if sample and all(b in (9, 10, 13) or 32 <= b < 127 for b in sample):
        return "txt"
    return "bin"


def extract_files(tib_path: str, output_dir: str, *,
                  max_files: Optional[int] = None,
                  max_offset: Optional[int] = None,
                  rename_to_original: bool = False,
                  progress: bool = False) -> int:
    """Walk the FS-mode body and write each logical file as a numbered
    blob in ``output_dir``. Returns the count of files emitted.

    Files are named ``recovered_NNNNNN.ext`` where ``ext`` is sniffed
    from the file's first bytes (``jpg``, ``png``, ``mp4``, ``txt``,
    ``bin`` for unknown).

    Per the static-RE finding that ``f`` records are out-of-band
    metadata (NOT file boundaries — the writer just flushes
    accumulated NTFS-attribute blobs into the same physical block
    stream periodically), we DO NOT flush partial chunks when an
    ``f`` record appears. Only ``n`` records terminate a file.

    When an ``f`` record is encountered, its metadata batch is parsed
    and applied **retroactively** to the most recently emitted files —
    each f-batch is the **postfix manifest** for the batch of files
    that immediately preceded it (verified empirically by matching
    metadata file_size values to recovered file sizes). Cross-validates
    file_size / md5 and writes ``metadata.jsonl`` to the output dir.
    """
    import hashlib
    import json

    os.makedirs(output_dir, exist_ok=True)

    # Try to recover the original-filename directory tree. This is best-
    # effort: if the trailer region is missing or malformed, we fall back
    # to numbered output.
    #
    # Per Agent 1's RE: the directory tree contains BOTH files and
    # directories; only file records have file_size > 0. The tree's
    # on-disk order is **case-sensitive** alphabetical (uppercase before
    # lowercase), while the m/n content stream is **case-insensitive**
    # alphabetical (NTFS collation order). They agree when no two
    # adjacent files differ only in case, but diverge wherever a
    # capitalised filename and a lowercase one would interleave.
    #
    # We therefore pair recovered files to tree records by SIZE: build
    # a dict from file_size → list[FsDirRecord], and pop one entry per
    # match in stream order. This gives correct pairings as long as no
    # two files in the archive share both size AND a position-ambiguous
    # alphabetical neighbourhood — in practice this is essentially
    # always true for share/NAS backups (share_backup: 153,874 files,
    # all paired).
    file_records_by_size: dict = {}    # int -> list[FsDirRecord]
    file_records_total = 0
    try:
        _meta_blob, tree_blob = decode_directory_tree(tib_path)
        for r in parse_directory_tree(tree_blob):
            if r.file_size > 0:
                file_records_by_size.setdefault(r.file_size, []).append(r)
                file_records_total += 1
        if progress:
            print(f"[tibread] recovered {file_records_total:,} file records "
                  f"from directory tree (size-keyed for pairing)",
                  flush=True)
    except Exception as e:
        if progress:
            print(f"[tibread] directory-tree decode failed ({e}); "
                  f"original filenames unavailable", flush=True)

    # Track every emitted file so we can post-annotate them once the
    # corresponding f-batch arrives.
    @dataclass
    class _EmittedFile:
        index: int
        path: str
        size: int
        md5: bytes
        meta: Optional[FsFileMetadata] = None
        original_path: Optional[str] = None
        dir_rec: Optional[FsDirRecord] = None

    emitted: list = []
    cur_chunks: list = []
    file_count = 0
    skipped_records = 0
    total_bytes = 0
    metadata_size_match = 0
    metadata_size_mismatch = 0
    metadata_md5_match = 0
    next_unannotated_idx = 0  # index into `emitted` of next file to label

    def flush_file():
        nonlocal file_count, total_bytes
        if not cur_chunks:
            return
        content = b"".join(cur_chunks)
        ext = _sniff_extension(content)
        file_count += 1
        # Pair with the matching directory-tree record by file_size.
        # Pop the first record of that size from the lookup; with
        # ~150,000 files in the test corpus this gives the correct
        # path for ~all paired files.
        bucket = file_records_by_size.get(len(content))
        dir_rec = bucket.pop(0) if bucket else None
        orig_path = dir_rec.fullpath if dir_rec else None
        if rename_to_original and orig_path:
            # Sanitize: strip drive letter, replace separators, drop
            # leading slashes. Keep directory structure under output_dir.
            sane = orig_path
            if len(sane) >= 2 and sane[1] == ":":
                sane = sane[2:]
            sane = sane.replace("\\", "/").lstrip("/")
            full_out = os.path.join(output_dir, sane)
            os.makedirs(os.path.dirname(full_out), exist_ok=True)
            out_path = full_out
        else:
            out_path = os.path.join(
                output_dir, f"recovered_{file_count:06d}.{ext}"
            )
        with open(out_path, "wb") as out:
            out.write(content)
        total_bytes += len(content)
        emitted.append(_EmittedFile(
            index=file_count,
            path=os.path.relpath(out_path, output_dir),
            size=len(content),
            md5=hashlib.md5(content).digest(),
            original_path=orig_path,
            dir_rec=dir_rec,
        ))
        cur_chunks.clear()

    def apply_batch(batch: list):
        """Pair the N metadata blobs in ``batch`` with the N most
        recently emitted files (in order) that don't yet have metadata."""
        nonlocal next_unannotated_idx
        nonlocal metadata_size_match, metadata_size_mismatch, metadata_md5_match
        for meta in batch:
            if next_unannotated_idx >= len(emitted):
                # Metadata extends past what we've emitted (can happen
                # if the walker bailed early). Drop the spillover.
                break
            ef = emitted[next_unannotated_idx]
            ef.meta = meta
            if meta.file_size == ef.size:
                metadata_size_match += 1
            else:
                metadata_size_mismatch += 1
            if meta.md5_content == ef.md5:
                metadata_md5_match += 1
            next_unannotated_idx += 1

    for rec in walk_fs_records(tib_path, max_offset=max_offset):
        if rec.type_byte == TYPE_FILE_CHUNK and rec.plain is not None:
            cur_chunks.append(rec.plain)
        elif rec.type_byte == TYPE_FILE_END:
            flush_file()
            if progress and file_count % 100 == 0 and file_count:
                print(f"[tibread]   {file_count} files, "
                      f"{total_bytes / (1 << 20):.1f} MiB, "
                      f"{metadata_size_match} metadata-validated",
                      flush=True)
            if max_files is not None and file_count >= max_files:
                break
        elif rec.type_byte == TYPE_DIR_RECORD and rec.plain is not None:
            try:
                batch = parse_metadata_batch(rec.plain)
            except Exception:
                batch = []
            apply_batch(batch)
            skipped_records += 1
        else:
            skipped_records += 1

    flush_file()

    # Write the sidecar manifest now that all metadata is paired.
    with open(os.path.join(output_dir, "metadata.jsonl"), "w") as side:
        for ef in emitted:
            m = ef.meta
            dr = ef.dir_rec
            # Tree-level expected size (from the directory record) is
            # available for every file (the tree covers all 161,989
            # records); the f-batch metadata is sparser.
            tree_size_ok = (dr is not None and dr.file_size == ef.size)
            side.write(json.dumps({
                "file_index": ef.index,
                "output": ef.path,
                "original_path": ef.original_path,
                "size": ef.size,
                "md5": ef.md5.hex(),
                "expected_size": m.file_size if m else None,
                "size_ok": (m is not None and m.file_size == ef.size),
                "md5_ok": (m is not None and m.md5_content == ef.md5),
                "tree_expected_size": dr.file_size if dr else None,
                "tree_size_ok": tree_size_ok,
                "tree_file_id": (f"{dr.file_id:#018x}" if dr else None),
                "tree_attrs": (f"{dr.attrs:#06x}" if dr else None),
                "shortname": dr.shortname if dr else None,
                "ads_name": m.ads_name if m else None,
                "num_extents": m.num_extents if m else None,
                "has_security_descriptor": (
                    bool(m and m.security_descriptor) if m else False
                ),
            }) + "\n")

    if progress:
        print(f"[tibread] done: {file_count} files, "
              f"{total_bytes / (1 << 20):.1f} MiB recovered. "
              f"Metadata: {metadata_size_match} size-matched, "
              f"{metadata_size_mismatch} mismatch, "
              f"{metadata_md5_match} md5-matched. "
              f"({skipped_records} f/unknown records seen)",
              flush=True)

    return file_count


# ---------------------------------------------------------------------------
# Directory tree (filename) recovery
# ---------------------------------------------------------------------------
#
# The post-content tail of an FS-mode hybrid `.tib` carries a directory
# tree that maps every file in the archive to its original path. The
# region is **plaintext** (was thought encrypted; isn't): a chain of
# raw-deflate streams ending with a self-locating 16-byte tail.
#
# Layout (verified empirically against `share_backup_example.tib`):
#
#   [last m/n record's zlib end]
#   [f-batch: N×(44 B preamble + raw-deflate metadata blob)]
#   [u8 0x65='e'][raw deflate -> ~1360 B metadata-blob TLV (metainfo XML, productinfo)]
#   [5 bytes framing: c0 83 c7 05 67]
#   [raw deflate -> ~59 MB directory tree (one record per file/folder)]
#   [11 bytes — likely CRC32 + u64 record count]
#   [raw deflate -> ~5 B (walker artifact)]
#   [u64 record_count][u64 body-relative offset of the 0x65 byte]
#   [u32 trailer magic 0x94E18A2C]
#
# Per-record format inside the directory tree (empirical, not yet fully
# field-named):
#
#   u32  record_count           (only at offset 0 of the stream)
#   --- per record (variable size, ~50-300 bytes) ---
#   u32  fullpath_chars         (UTF-16-LE characters, then 2*chars bytes)
#   u8[2*chars] fullpath_utf16
#   u32  basename_chars
#   u8[2*chars] basename_utf16
#   u32  basename_chars         (yes, repeats — second copy might be a
#                                "case-sensitive name" cache)
#   u8[2*chars] basename_utf16
#   u32  shortname_chars        (8.3-form, ALL CAPS)
#   u8[2*chars] shortname_utf16
#   ...~40-60 B fixed fields: NTFS file_id (u64), parent_id, FILETIMEs,
#       attribute flags, two repeated FILETIMEs (create/modify) ...
#
# We don't yet name every field of the fixed section, but the path
# strings recover correctly from a simple UTF-16 scan.

# Magic byte sequence the directory-tree blob starts with.
DIRTREE_TYPE_BYTE = 0x65        # 'e'
DIRTREE_FRAMING = bytes.fromhex("c083c70567")  # 5 bytes between metadata-blob
                                                # and tree streams


def _read_footer(tib_path: str) -> Tuple[int, int]:
    """Return (concat_end, slice_size) by reading the 48-byte footer."""
    import struct
    file_size = os.path.getsize(tib_path)
    with open(tib_path, "rb") as f:
        f.seek(file_size - 48)
        footer = f.read(48)
    if len(footer) != 48:
        raise ValueError(f"file too small to have a footer: {file_size} bytes")
    slice_size = struct.unpack_from("<Q", footer, 8)[0]
    concat_end = DATA_START + slice_size
    return concat_end, slice_size


def locate_directory_tree(tib_path: str) -> Tuple[int, int]:
    """Find the directory-tree blob's start/end file offsets.

    Returns (start_offset, end_offset) where ``[start, end)`` brackets
    the bytes from the type-byte ``0x65`` through to (but not including)
    the 4-byte trailer magic.

    The locator is the 16-byte struct immediately preceding the trailer:
        [u64 record_count][u64 body_relative_offset]
    where ``body_relative_offset = start_offset - DATA_START``.
    """
    import struct
    concat_end, _slice_size = _read_footer(tib_path)
    if concat_end < 32:
        raise ValueError(f"implausibly small concat_end: {concat_end}")
    with open(tib_path, "rb") as f:
        # The 16-byte locator sits at concat_end - 4 - 16.
        f.seek(concat_end - 4 - 16)
        locator = f.read(16)
    if len(locator) != 16:
        raise ValueError("could not read 16-byte locator")
    record_count = struct.unpack_from("<Q", locator, 0)[0]
    body_rel_off = struct.unpack_from("<Q", locator, 8)[0]
    start = DATA_START + body_rel_off
    end = concat_end - 4
    if not (DATA_START < start < end):
        raise ValueError(
            f"implausible locator: start={start} end={end} record_count={record_count}"
        )
    return start, end


def decode_directory_tree(tib_path: str) -> Tuple[bytes, bytes]:
    """Decode the trailing-region streams. Returns (metadata_blob, dir_tree)
    where ``metadata_blob`` is the ~1.3 KB TLV (metainfo XML, productinfo
    etc.) and ``dir_tree`` is the ~tens-of-MB directory-tree raw blob.

    Raises ValueError if the streams don't decode cleanly.
    """
    start, end = locate_directory_tree(tib_path)
    # Read the whole opaque region (sub-MB to tens of MB).
    with open(tib_path, "rb") as f:
        f.seek(start)
        region = f.read(end - start)

    if not region or region[0] != DIRTREE_TYPE_BYTE:
        raise ValueError(
            f"directory-tree region doesn't start with 0x65 ('e'); "
            f"got {region[:1].hex() if region else '<empty>'}"
        )

    # Stream 1: metadata blob, raw deflate at +1.
    d1 = zlib.decompressobj(-15)
    meta_blob = d1.decompress(region[1:])
    if not d1.eof:
        # Try to feed remainder
        meta_blob += d1.flush()
    consumed1 = len(region) - 1 - len(d1.unused_data)
    after1 = 1 + consumed1

    # 5-byte framing then stream 2: directory tree, raw deflate.
    frame_end = after1 + len(DIRTREE_FRAMING)
    if region[after1:frame_end] != DIRTREE_FRAMING:
        # Some samples may have a slightly different framing — fall back
        # to scanning forward for the next inflate-able raw-deflate
        # stream within the next 64 bytes.
        for skip in range(1, 64):
            d2 = zlib.decompressobj(-15)
            try:
                tree = d2.decompress(region[after1 + skip:])
                if d2.eof:
                    return meta_blob, tree
            except zlib.error:
                continue
        raise ValueError(
            f"unexpected framing at +{after1:#x}: "
            f"{region[after1:after1+8].hex()}"
        )
    d2 = zlib.decompressobj(-15)
    tree = d2.decompress(region[frame_end:])
    if not d2.eof:
        tree += d2.flush()
    return meta_blob, tree


@dataclass
class FsDirRecord:
    """One fully-decoded directory-tree record. All 161,989 records of
    the reference share_backup tree parse to EOF cleanly with this layout."""
    fullpath: str           # e.g. "C:/Documents and Settings/.../foo.jpg"
    basename: str           # last segment of fullpath
    longname: str           # internal: usually duplicates basename
    shortname: str          # 8.3 form, e.g. "FOLLET~1.JPG"
    file_id: int            # u64 — NTFS MFT reference
    parent_hash: int        # u32 — 4-byte hash; siblings share value
    file_size: int          # u64 — logical EOF; 0 for directories
    alloc_size: int         # u64 — on-disk allocated, cluster-rounded
    ts1: int                # u64 — semantics not fully nailed; likely stream cursor
    attrs: int              # u32 — Win32 attribute flags (0/0x80/0x83 observed)
    ts2: int                # u64 — always == ts1 in observed samples
    valid: int              # u32 — always 1


def parse_directory_tree(tree_blob: bytes) -> Iterator[FsDirRecord]:
    """Yield :class:`FsDirRecord` for every record in the inflated
    directory-tree stream. Verified against the reference share_backup
    fixture: parses all 161,989 records to EOF with zero leftover bytes.

    Per-record layout:

      u32 fullpath_chars
      u8[2*chars] fullpath_utf16     (last char is NUL)
      u32 tail_u16_count             (size of remainder in u16 words)
      u8[2*tail_u16_count] tail:
        u32 basename_chars
        u8[2*chars] basename_utf16
        u32 sub_chars
        u8[2*chars] sub_utf16:
          longname + NUL +
          u32 const_tag (= 2) +
          u32 shortname_chars +
          u8[2*chars] shortname_utf16 + NUL
        74-byte fixed footer (see :class:`FsDirRecord`)

    Credit: layout reverse-engineered empirically from the inflated
    blob (Agent A, 2026-05-01).
    """
    import struct
    if len(tree_blob) < 4:
        return
    off = 0
    nrec = struct.unpack_from("<I", tree_blob, off)[0]
    off += 4
    for _ in range(nrec):
        if off + 4 > len(tree_blob):
            return
        n0 = struct.unpack_from("<I", tree_blob, off)[0]
        off += 4
        fullpath = tree_blob[off:off + 2 * n0].decode(
            "utf-16-le", errors="replace"
        ).rstrip("\x00")
        off += 2 * n0
        if off + 4 > len(tree_blob):
            return
        tail_words = struct.unpack_from("<I", tree_blob, off)[0]
        off += 4
        tail_bytes = 2 * tail_words
        if off + tail_bytes > len(tree_blob):
            return
        tail = tree_blob[off:off + tail_bytes]
        off += tail_bytes

        p = 0
        n1 = struct.unpack_from("<I", tail, p)[0]
        p += 4
        basename = tail[p:p + 2 * n1].decode(
            "utf-16-le", errors="replace"
        ).rstrip("\x00")
        p += 2 * n1
        n2 = struct.unpack_from("<I", tail, p)[0]
        p += 4
        sub = tail[p:p + 2 * n2]
        p += 2 * n2
        # The `sub` block contains: longname \0 + u32(=2) + u32 short_chars +
        # u8[2*short_chars] shortname.
        long_end = sub.find(b"\x00\x00")
        while long_end != -1 and long_end % 2 != 0:
            long_end = sub.find(b"\x00\x00", long_end + 1)
        if long_end < 0:
            longname = sub.decode("utf-16-le", errors="replace").rstrip("\x00")
            shortname = ""
        else:
            longname = sub[:long_end].decode("utf-16-le", errors="replace")
            sp = long_end + 2
            shortname = ""
            if sp + 8 <= len(sub):
                # const_tag at sub[sp:sp+4] should be 2; we don't enforce it
                short_chars = struct.unpack_from("<I", sub, sp + 4)[0]
                sp += 8
                if sp + 2 * short_chars <= len(sub):
                    shortname = sub[sp:sp + 2 * short_chars].decode(
                        "utf-16-le", errors="replace"
                    ).rstrip("\x00")

        f = tail[p:]
        if len(f) < 0x4A:
            # Truncated footer; bail.
            return
        yield FsDirRecord(
            fullpath=fullpath,
            basename=basename,
            longname=longname,
            shortname=shortname,
            file_id=struct.unpack_from("<Q", f, 0x00)[0],
            parent_hash=struct.unpack_from("<I", f, 0x08)[0],
            file_size=struct.unpack_from("<Q", f, 0x0C)[0],
            alloc_size=struct.unpack_from("<Q", f, 0x14)[0],
            ts1=struct.unpack_from("<Q", f, 0x1C)[0],
            attrs=struct.unpack_from("<I", f, 0x24)[0],
            ts2=struct.unpack_from("<Q", f, 0x28)[0],
            valid=struct.unpack_from("<I", f, 0x30)[0],
        )


def extract_paths_from_tree(tree_blob: bytes) -> list:
    """Return every fullpath string from the directory tree, in on-disk
    order. Convenience wrapper over :func:`parse_directory_tree`.

    Note: this returns paths for BOTH files and directories. To filter
    to files only, check ``record.file_size > 0`` or call
    :func:`is_likely_file_path` on the returned strings.
    """
    return [r.fullpath for r in parse_directory_tree(tree_blob)]


def is_likely_file_path(path: str) -> bool:
    """Heuristic: distinguish a file from a directory by extension shape.

    Returns True if the path's basename has an extension of 1-5 chars
    that looks plausible (alphanumeric only). Empty/missing extensions
    suggest a directory.
    """
    base = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in base:
        return False
    ext = base.rsplit(".", 1)[-1]
    if not (1 <= len(ext) <= 5):
        return False
    return ext.replace("_", "").replace("-", "").isalnum()


__all__ = [
    "DATA_START",
    "TYPE_FILE_CHUNK",
    "TYPE_FILE_END",
    "TYPE_DIR_RECORD",
    "META_PREAMBLE_LEN",
    "META_BLOB_MAGIC",
    "DIRTREE_TYPE_BYTE",
    "FsRecord",
    "FsExtent",
    "FsFileMetadata",
    "FsDirRecord",
    "walk_fs_records",
    "is_fs_mode_hybrid",
    "extract_files",
    "parse_metadata_batch",
    "locate_directory_tree",
    "decode_directory_tree",
    "extract_paths_from_tree",
    "parse_directory_tree",
]
