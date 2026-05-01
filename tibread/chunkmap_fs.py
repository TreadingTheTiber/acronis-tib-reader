"""
chunkmap_fs.py — partial walker for the FS-mode hybrid `.tib` variant.

This is the layout produced by Acronis True Image when backing up a
file share rather than a block device. We've seen exactly one specimen
in the wild (filename `share_backup_example.tib`, TI 2016). The
volume header is byte-shape-identical to sector-mode (magic
``0xA2B924CE``) but the trailer magic is ``0x94E18A2C`` (FS-mode
sentinel) and the body is a sequence of single-byte-tagged zlib
streams rather than a sector-mode block stream:

    [u8 type] [zlib stream]
    [u8 type] [zlib stream]
    ...

Type codes observed (ASCII letters):

* ``0x6D`` ('m') — file-content chunk (≤ 256 KiB plaintext, zlib STORED)
* ``0x6E`` ('n') — end-of-file separator (8-byte zlib-of-empty)
* ``0x66`` ('f') — directory / metadata record. **Format unknown.**
  Empirically these are 3–8 KiB long, appear roughly every 22–25 files,
  and start with a fixed 8-byte signature ``66 63 60 00 02 00 1d f7``.
  We currently skip them by scanning forward for the next valid
  ``[m|n][78 01]`` pattern.

A "logical file" is the run of ``m`` chunks ending at the next ``n``.

Limitations
-----------

* Filenames live in the ``f`` records (presumably) and we don't decode
  them yet, so recovered files are emitted as numbered blobs with a
  content-magic-based extension (``recovered_000001.jpg`` etc.).
* The last ~16 MiB before the trailer is high-entropy — likely an
  encrypted index — and the walker halts when it can no longer find
  valid records. That's typically where the body ends anyway.
* This walker has only been validated against the single
  ``share_backup_example.tib`` sample. Other share-mode .tib files
  may use additional record types we haven't seen.

References
----------

* Static-RE notes from the Ghidra session on Acronis True Image's
  ``product.bin`` (``ChunkMapAndHashImpl`` / ``HybridChunkMapAndHash``
  vtables at RVA ``09578a38`` / ``09576000``).
* Empirical sample-dissection notes from the same investigation.
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

    Yields :class:`FsRecord` tuples. ``f`` records are yielded with
    ``plain=None`` and ``comp_len`` set to the bytes skipped to reach
    the next known record.
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

            # Unknown record type — try to skip past it.
            nxt = _find_next_known_record(f, cur + 1, end)
            if nxt is None:
                return
            yield FsRecord(offset=cur, type_byte=t, comp_len=nxt - cur,
                           plain=None)
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
                  progress: bool = False) -> int:
    """Walk the FS-mode body and write each logical file as a numbered
    blob in ``output_dir``. Returns the count of files emitted.

    Files are named ``recovered_NNNNNN.ext`` where ``ext`` is sniffed
    from the file's first bytes (``jpg``, ``png``, ``mp4``, ``txt``,
    ``bin`` for unknown).
    """
    os.makedirs(output_dir, exist_ok=True)

    cur_chunks: list[bytes] = []
    file_count = 0
    skipped_records = 0
    total_bytes = 0

    for rec in walk_fs_records(tib_path, max_offset=max_offset):
        if rec.type_byte == TYPE_FILE_CHUNK and rec.plain is not None:
            cur_chunks.append(rec.plain)
        elif rec.type_byte == TYPE_FILE_END:
            if cur_chunks:
                content = b"".join(cur_chunks)
                ext = _sniff_extension(content)
                file_count += 1
                out_path = os.path.join(
                    output_dir, f"recovered_{file_count:06d}.{ext}"
                )
                with open(out_path, "wb") as out:
                    out.write(content)
                total_bytes += len(content)
                if progress and file_count % 100 == 0:
                    print(f"[tibread]   {file_count} files, "
                          f"{total_bytes / (1 << 20):.1f} MiB recovered",
                          flush=True)
                cur_chunks = []
                if max_files is not None and file_count >= max_files:
                    break
        else:
            # f record or unknown skip — content boundary unknown; if we
            # had partial chunks, flush them as a recovered fragment.
            skipped_records += 1
            if cur_chunks:
                content = b"".join(cur_chunks)
                ext = _sniff_extension(content)
                file_count += 1
                out_path = os.path.join(
                    output_dir, f"recovered_{file_count:06d}.{ext}"
                )
                with open(out_path, "wb") as out:
                    out.write(content)
                total_bytes += len(content)
                cur_chunks = []
                if max_files is not None and file_count >= max_files:
                    break

    if cur_chunks:
        content = b"".join(cur_chunks)
        ext = _sniff_extension(content)
        file_count += 1
        out_path = os.path.join(output_dir, f"recovered_{file_count:06d}.{ext}")
        with open(out_path, "wb") as out:
            out.write(content)
        total_bytes += len(content)

    if progress:
        print(f"[tibread] done: {file_count} files, "
              f"{total_bytes / (1 << 20):.1f} MiB recovered, "
              f"{skipped_records} unknown/`f` records skipped",
              flush=True)

    return file_count


__all__ = [
    "DATA_START",
    "TYPE_FILE_CHUNK",
    "TYPE_FILE_END",
    "TYPE_DIR_RECORD",
    "FsRecord",
    "walk_fs_records",
    "is_fs_mode_hybrid",
    "extract_files",
]
