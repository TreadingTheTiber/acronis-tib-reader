"""
fs_browse.py — index-and-browse interface for FS-mode hybrid `.tib`.

Provides three building blocks on top of :mod:`tibread.chunkmap_fs`:

1. :func:`build_index` — single-pass scan of the `.tib` body that records
   each file's m-chunk byte offsets and compressed lengths, paired with
   its original path from the directory tree. Result is a list of
   :class:`FsFileEntry` objects that supports random-access extraction.
2. :func:`extract_one` — given an index entry, pull just that file's
   bytes out of the archive. ``O(file_size)`` per call (no full re-walk).
3. :func:`serve` — a stdlib-only HTTP server that renders a folder tree
   from the index and streams individual files on demand.

The index can be persisted to a JSON sidecar (``<archive>.fs.idx``) so
subsequent runs skip the scan. We don't bother with sub-millisecond
optimisation — a 153,000-file index is a couple of MB of JSON, fine.
"""
from __future__ import annotations

import hashlib
import html
import io
import json
import mimetypes
import os
import re
import struct
import sys
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator, List, Optional, Tuple

from .chunkmap_fs import (
    DATA_START,
    TYPE_FILE_CHUNK,
    TYPE_FILE_END,
    TYPE_DIR_RECORD,
    decode_directory_tree,
    is_fs_mode_hybrid,
    parse_directory_tree,
    walk_fs_records,
)

# Bump when the on-disk index format changes incompatibly.
INDEX_FORMAT_VERSION = 1


@dataclass
class FsFileEntry:
    """One indexed file: knows its original path and where its bytes
    live in the archive."""
    path: str                     # Original Windows-style path
    size: int                     # Logical size (bytes)
    chunk_offsets: List[int]      # File offsets of each `0x6D` byte
    chunk_comp_lens: List[int]    # Compressed length of each chunk's
                                  #   zlib stream (excluding the type byte)


@dataclass
class FsArchiveIndex:
    """All information needed to random-access a `.tib` archive."""
    tib_path: str
    tib_size: int
    tib_mtime_ns: int
    files: List[FsFileEntry] = field(default_factory=list)
    format_version: int = INDEX_FORMAT_VERSION

    def by_path(self) -> dict:
        return {e.path: e for e in self.files}


# ---------------------------------------------------------------------------
# Index build / cache
# ---------------------------------------------------------------------------


def _normalize_path(p: str) -> str:
    """Strip drive letter, replace backslashes with forward, drop leading /."""
    if len(p) >= 2 and p[1] == ":":
        p = p[2:]
    p = p.replace("\\", "/").lstrip("/")
    return p


def _skip_zlib_chunk(f, start_off: int) -> Tuple[int, int]:
    """Walk a zlib stream at ``start_off`` reading mostly headers.

    Returns ``(comp_len, plain_len)`` — the byte span of the zlib stream
    (after the 1-byte type tag) and its decompressed length.

    Two paths:

    * **Fast path** (used for `m` content chunks): if every deflate
      block is stored (BTYPE=00), we read 5 bytes per block + skip
      past the payload, never touching it. This is essential for
      remote/SMB archives where every byte costs a round-trip.
    * **Slow path** (used for `n` end-of-file markers, which use a
      fixed-Huffman empty block, BTYPE=01): we fall back to
      ``zlib.decompressobj`` on a small read window. These chunks
      are 8 bytes total so the fallback is cheap.
    """
    f.seek(start_off)
    hdr = f.read(2)
    if len(hdr) < 2 or hdr[0] != 0x78:
        raise ValueError(f"missing zlib magic at offset {start_off}")

    # Peek at the first deflate block header to choose path.
    f.seek(start_off + 2)
    first_bh = f.read(1)
    if not first_bh:
        raise ValueError(f"truncated deflate at {start_off + 2}")
    btype0 = (first_bh[0] >> 1) & 0x03

    if btype0 == 0x00:
        # Fast path: stored-block walk.
        pos = start_off + 2
        plain_len = 0
        while True:
            f.seek(pos)
            bh = f.read(5)
            if len(bh) < 5:
                raise ValueError(f"truncated stored-block header at {pos}")
            bfinal = bh[0] & 0x01
            btype = (bh[0] >> 1) & 0x03
            if btype != 0x00:
                # Mid-stream switch to non-stored — rare; fall back.
                return _slow_zlib_skip(f, start_off)
            length = bh[1] | (bh[2] << 8)
            nlength = bh[3] | (bh[4] << 8)
            if (length ^ 0xFFFF) != nlength:
                raise ValueError(
                    f"stored-block LEN/NLEN mismatch at {pos:#x}: "
                    f"LEN={length:#x} ~LEN={nlength:#x}"
                )
            plain_len += length
            pos += 5 + length
            if bfinal:
                break
        pos += 4   # adler32 trailer
        return pos - start_off, plain_len

    # Slow path: fixed/dynamic Huffman block (e.g. the 'n' end-of-file
    # marker, which is a single fixed-Huffman empty block).
    return _slow_zlib_skip(f, start_off)


def _find_next_m_chunk(f, start: int, bound: int) -> int:
    """Find the file offset of the next valid 'm' content chunk in
    [start, bound), skipping past compressed-data byte noise.

    Scan for the 3-byte signature ``6d 78 01`` (m record + zlib
    header) and validate each hit by **actually decompressing** the
    chunk via ``zlib.decompress``. Header-only validation lets ~1 in
    65,536 random byte positions through, so over a 1 GB f-batch we'd
    accept tens of thousands of false positives; full decompression's
    integrated Adler32 check eliminates them.

    The decompression cost is one full chunk inflate per f-batch
    boundary (≤ 150 such boundaries in NAS_Backup) — negligible
    compared to the cost of a wrong-positioned drift through the rest
    of the archive.

    Returns ``-1`` if no valid candidate is found within ``bound``.
    """
    SIG = b"\x6d\x78\x01"
    READ_SIZE = 65536
    overlap = len(SIG) - 1
    pos = start
    carry = b""
    abs_carry_start = pos
    while pos < bound:
        f.seek(pos)
        chunk = f.read(min(READ_SIZE, bound - pos))
        if not chunk:
            return -1
        haystack = carry + chunk
        search_from = 0
        while True:
            idx = haystack.find(SIG, search_from)
            if idx < 0:
                break
            cand = abs_carry_start + idx
            if cand >= bound:
                return -1
            # Quick reject: 4th byte's BTYPE bits must be 00 (stored).
            if cand + 4 - abs_carry_start <= len(haystack):
                fourth = haystack[cand + 3 - abs_carry_start]
                if (fourth & 0x06) != 0x00:
                    search_from = idx + 1
                    continue
            # Full validation: actually inflate (with Adler32 check).
            f.seek(cand + 1)
            try:
                d = zlib.decompressobj()
                # 1 MB window covers any single m chunk (max 256 KiB
                # plain + zlib overhead).
                buf = f.read(1 << 20)
                plain = d.decompress(buf)
                while not d.eof:
                    more = f.read(64 * 1024)
                    if not more:
                        break
                    plain += d.decompress(more)
                if d.eof and 0 < len(plain) <= 262175:
                    return cand
            except zlib.error:
                pass
            search_from = idx + 1
        carry = haystack[-overlap:] if overlap > 0 else b""
        abs_carry_start = pos + len(chunk) - len(carry)
        pos += len(chunk)
    return -1


def _slow_zlib_skip(f, start_off: int, max_read: int = 65536) -> Tuple[int, int]:
    """Inflate the zlib stream at ``start_off`` and report the
    consumed length + decompressed length. Used as a fallback for non-
    stored deflate streams (fixed/dynamic Huffman) and as a validator
    for f-batch boundary candidates."""
    f.seek(start_off)
    d = zlib.decompressobj()
    plain_chunks = []
    total_input = 0
    while not d.eof:
        buf = f.read(max_read)
        if not buf:
            raise ValueError(f"unexpected EOF in zlib at {start_off}")
        plain_chunks.append(d.decompress(buf))
        total_input += len(buf)
    plain = b"".join(plain_chunks)
    consumed = total_input - len(d.unused_data)
    return consumed, len(plain)


# Backwards-compat alias (old name was misleading once we added the
# slow-path fallback).
_skip_zlib_stored_chunk = _skip_zlib_chunk


def build_index(tib_path: str, *, progress: bool = False) -> FsArchiveIndex:
    """Walk the `.tib` body once, recording per-file chunk offsets, then
    pair each file with a directory-tree record by file_size.

    This costs one **header-only** read of the archive — we seek past
    each chunk's compressed payload rather than decompressing it,
    which is essential for SMB-hosted archives where every byte costs
    a network round-trip. A 173 GB share archive indexes in minutes
    rather than hours.
    """
    if not is_fs_mode_hybrid(tib_path):
        raise ValueError(
            f"{tib_path}: not an FS-mode hybrid .tib (sector-mode header "
            "+ 0x94E18A2C trailer required)."
        )

    # First: load the directory tree so we can pair as we go.
    _meta_blob, tree_blob = decode_directory_tree(tib_path)
    by_size: dict = {}
    for r in parse_directory_tree(tree_blob):
        if r.file_size > 0:
            by_size.setdefault(r.file_size, []).append(r)
    paired = 0
    unpaired = 0

    # Find the trailer to bound the walk.
    file_size = os.path.getsize(tib_path)
    with open(tib_path, "rb") as f:
        f.seek(file_size - 48)
        slice_size = struct.unpack_from("<Q", f.read(48), 8)[0]
        concat_end = DATA_START + slice_size

        # f-batch and trailer-region detection: stop the m/n walk when
        # we hit the first non-m/non-n record, since beyond that lies
        # the f-batches and the directory-tree blob (already decoded
        # separately).
        cur_offsets: List[int] = []
        cur_comp_lens: List[int] = []
        cur_size = 0
        files: List[FsFileEntry] = []
        last_progress = time.monotonic()

        # When we hit a non-m/non-n byte, we're inside an f-batch (per-
        # file metadata records) or another out-of-band region. We
        # don't need its contents for indexing — just need to find the
        # next m/n record. Scan forward looking for that boundary.
        FBATCH_SKIP_LOOKAHEAD = 16 * 1024 * 1024   # plenty for any seen f-batch

        # The trailing directory-tree blob lives at a known offset
        # encoded in the 16-byte self-locator just before the trailer
        # (verified separately by `decode_directory_tree`). The walk
        # ends once we reach that offset.
        f.seek(concat_end - 4 - 16)
        loc = f.read(16)
        body_rel_off = struct.unpack_from("<Q", loc, 8)[0]
        dirtree_start = DATA_START + body_rel_off

        cur = DATA_START
        while cur < dirtree_start:
            f.seek(cur)
            tag = f.read(1)
            if not tag:
                break
            t = tag[0]
            if t in (TYPE_FILE_CHUNK, TYPE_FILE_END):
                try:
                    comp_len, plain_len = _skip_zlib_chunk(f, cur + 1)
                except ValueError:
                    break
                if t == TYPE_FILE_CHUNK:
                    cur_offsets.append(cur)
                    cur_comp_lens.append(comp_len)
                    cur_size += plain_len
                else:  # TYPE_FILE_END
                    if cur_offsets:
                        bucket = by_size.get(cur_size)
                        if bucket:
                            dir_rec = bucket.pop(0)
                            path = _normalize_path(dir_rec.fullpath)
                            paired += 1
                        else:
                            path = f"_unpaired_/recovered_{len(files)+1:06d}"
                            unpaired += 1
                        files.append(FsFileEntry(
                            path=path,
                            size=cur_size,
                            chunk_offsets=cur_offsets,
                            chunk_comp_lens=cur_comp_lens,
                        ))
                        cur_offsets = []
                        cur_comp_lens = []
                        cur_size = 0
                        if progress and time.monotonic() - last_progress > 2.0:
                            pct = 100.0 * cur / concat_end
                            print(f"[tibread]   indexing {pct:5.1f}%  "
                                  f"{len(files):,} files",
                                  flush=True)
                            last_progress = time.monotonic()
                cur += 1 + comp_len
            else:
                # Inside an f-batch or unknown record. f-batches in
                # this corpus always come AFTER a completed file
                # (i.e. after an 'n'), so the next thing we want is
                # the FIRST m chunk of the next batch's first file.
                next_off = _find_next_m_chunk(
                    f, cur + 1,
                    bound=min(dirtree_start, cur + FBATCH_SKIP_LOOKAHEAD),
                )
                if next_off < 0:
                    break
                cur = next_off

    if progress:
        print(f"[tibread] index built: {len(files):,} files "
              f"({paired:,} paired, {unpaired:,} unpaired)",
              flush=True)

    st = os.stat(tib_path)
    return FsArchiveIndex(
        tib_path=os.path.abspath(tib_path),
        tib_size=st.st_size,
        tib_mtime_ns=st.st_mtime_ns,
        files=files,
    )


def _index_cache_path(tib_path: str) -> str:
    return tib_path + ".fs.idx"


def save_index(index: FsArchiveIndex, *, path: Optional[str] = None) -> str:
    """Persist an index to JSON. Returns the path written."""
    out_path = path or _index_cache_path(index.tib_path)
    with open(out_path, "w") as f:
        json.dump(asdict(index), f)
    return out_path


def load_index(tib_path: str) -> Optional[FsArchiveIndex]:
    """Return a cached index for ``tib_path`` if one exists and matches
    the archive's current size + mtime, else None."""
    cache_path = _index_cache_path(tib_path)
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("format_version") != INDEX_FORMAT_VERSION:
        return None
    st = os.stat(tib_path)
    if data.get("tib_size") != st.st_size:
        return None
    if data.get("tib_mtime_ns") != st.st_mtime_ns:
        return None
    files = [FsFileEntry(**e) for e in data["files"]]
    return FsArchiveIndex(
        tib_path=data["tib_path"],
        tib_size=data["tib_size"],
        tib_mtime_ns=data["tib_mtime_ns"],
        files=files,
        format_version=data["format_version"],
    )


def get_or_build_index(tib_path: str, *, progress: bool = False,
                       use_cache: bool = True) -> FsArchiveIndex:
    """Return an index, using the cached sidecar when possible."""
    if use_cache:
        cached = load_index(tib_path)
        if cached is not None:
            if progress:
                print(f"[tibread] using cached index for {tib_path} "
                      f"({len(cached.files):,} files)", flush=True)
            return cached
    if progress:
        print(f"[tibread] building index (one-time scan)...", flush=True)
    idx = build_index(tib_path, progress=progress)
    if use_cache:
        try:
            cache_path = save_index(idx)
            if progress:
                print(f"[tibread] index cached to {cache_path}", flush=True)
        except OSError as e:
            if progress:
                print(f"[tibread] could not cache index: {e}", flush=True)
    return idx


# ---------------------------------------------------------------------------
# Single-file extract via the index
# ---------------------------------------------------------------------------


def iter_file_bytes(tib_path: str, entry: FsFileEntry,
                    *, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
    """Yield the file's raw bytes by inflating its chunks in order."""
    with open(tib_path, "rb") as f:
        for off, comp_len in zip(entry.chunk_offsets, entry.chunk_comp_lens):
            # Each m chunk is [u8 0x6D][zlib stream of comp_len bytes].
            f.seek(off + 1)
            payload = f.read(comp_len)
            if not payload:
                return
            yield zlib.decompress(payload)


def extract_one(tib_path: str, entry: FsFileEntry, out_path: str) -> int:
    """Extract a single file to ``out_path`` using the index. Returns
    the number of bytes written."""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    written = 0
    with open(out_path, "wb") as out:
        for chunk in iter_file_bytes(tib_path, entry):
            out.write(chunk)
            written += len(chunk)
    return written


# ---------------------------------------------------------------------------
# HTTP browse
# ---------------------------------------------------------------------------


@dataclass
class _DirNode:
    name: str
    is_dir: bool
    size: int = 0
    entry: Optional[FsFileEntry] = None
    children: dict = field(default_factory=dict)


def _build_tree(index: FsArchiveIndex) -> _DirNode:
    """Build a hierarchical _DirNode tree from a flat list of entries."""
    root = _DirNode(name="", is_dir=True)
    for entry in index.files:
        parts = [p for p in entry.path.split("/") if p]
        node = root
        for i, part in enumerate(parts):
            is_last = (i == len(parts) - 1)
            if is_last:
                # File leaf
                node.children[part] = _DirNode(
                    name=part, is_dir=False,
                    size=entry.size, entry=entry,
                )
            else:
                if part not in node.children:
                    node.children[part] = _DirNode(name=part, is_dir=True)
                node = node.children[part]
                # Edge case: file path collides with a dir path; we just
                # let the dir win since there's nothing useful to do.
                if not node.is_dir:
                    break
    # Stable sort: directories first, then case-insensitive name.
    def _sort(n: _DirNode):
        n.children = dict(
            sorted(n.children.items(),
                   key=lambda kv: (not kv[1].is_dir, kv[0].lower()))
        )
        for c in n.children.values():
            if c.is_dir:
                _sort(c)
    _sort(root)
    return root


def _resolve_path(root: _DirNode, url_path: str) -> Optional[_DirNode]:
    """Walk ``root`` to the node at ``url_path``. Returns None if not found."""
    parts = [p for p in url_path.split("/") if p]
    node = root
    for part in parts:
        if not node.is_dir:
            return None
        if part not in node.children:
            return None
        node = node.children[part]
    return node


def _humanize_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.2f} GB"


def _render_listing(node: _DirNode, url_path: str, archive_name: str) -> bytes:
    """Render a directory listing as HTML (mobile-friendly, minimal CSS)."""
    crumb_parts = [p for p in url_path.split("/") if p]
    crumbs_html = ['<a href="/">' + html.escape(archive_name) + "</a>"]
    accum = ""
    for part in crumb_parts:
        accum += "/" + part
        crumbs_html.append(
            f'<a href="{html.escape(urllib.parse.quote(accum))}/">'
            f'{html.escape(part)}</a>'
        )
    rows = []
    if crumb_parts:
        parent = "/" + "/".join(crumb_parts[:-1])
        if parent and not parent.endswith("/"):
            parent += "/"
        if parent == "":
            parent = "/"
        rows.append(
            f'<tr><td><a href="{html.escape(parent)}">📁 .. (up)</a></td>'
            f'<td></td></tr>'
        )
    for name, child in node.children.items():
        if child.is_dir:
            link = html.escape(urllib.parse.quote(name)) + "/"
            rows.append(
                f'<tr><td><a href="{link}">📁 {html.escape(name)}/</a></td>'
                f'<td></td></tr>'
            )
        else:
            link = html.escape(urllib.parse.quote(name))
            rows.append(
                f'<tr><td><a href="{link}">📄 {html.escape(name)}</a></td>'
                f'<td>{_humanize_size(child.size)}</td></tr>'
            )
    n_files = sum(1 for c in node.children.values() if not c.is_dir)
    n_dirs = sum(1 for c in node.children.values() if c.is_dir)
    body = (
        '<!doctype html><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>tibread: {html.escape(url_path or "/")}</title>'
        '<style>'
        'body{font-family:-apple-system,Segoe UI,sans-serif;'
        'max-width:900px;margin:24px auto;padding:0 16px;color:#222}'
        'h1{font-size:1.05rem;font-weight:500;color:#666;margin:0 0 16px}'
        'h1 a{color:#0366d6;text-decoration:none}'
        'h1 a:hover{text-decoration:underline}'
        'table{width:100%;border-collapse:collapse}'
        'tr{border-bottom:1px solid #eee}'
        'td{padding:8px 4px}td:nth-child(2){text-align:right;color:#777;'
        'font-variant-numeric:tabular-nums;white-space:nowrap}'
        'a{color:#0366d6;text-decoration:none}a:hover{text-decoration:underline}'
        '.summary{color:#999;font-size:.85rem;margin-top:16px}'
        '</style>'
        f'<h1>{" / ".join(crumbs_html)}/</h1>'
        f'<table>{"".join(rows)}</table>'
        f'<p class="summary">{n_dirs} folders, {n_files} files</p>'
    )
    return body.encode("utf-8")


class _BrowseHandler(BaseHTTPRequestHandler):
    # These are filled in by serve() before binding.
    server_index: FsArchiveIndex = None  # type: ignore[assignment]
    server_tree: _DirNode = None        # type: ignore[assignment]
    archive_name: str = ""

    def log_message(self, fmt, *args):
        # Suppress default per-request stderr noise; we only print
        # high-level status.
        pass

    def do_GET(self) -> None:
        # Strip query string; decode %xx.
        raw = urllib.parse.urlparse(self.path).path
        url_path = urllib.parse.unquote(raw)
        node = _resolve_path(self.server_tree, url_path)
        if node is None:
            self._send_text(404, f"Not found: {url_path}")
            return
        if node.is_dir:
            # Trailing-slash redirect for proper relative links.
            if url_path and not raw.endswith("/"):
                self.send_response(301)
                self.send_header("Location", raw + "/")
                self.end_headers()
                return
            body = _render_listing(node, url_path, self.archive_name)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # File: stream from the archive.
        entry = node.entry
        if entry is None:
            self._send_text(500, "internal: missing entry")
            return
        ctype, _ = mimetypes.guess_type(node.name)
        if ctype is None:
            ctype = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(entry.size))
        # Allow inline preview for images/video/audio/pdf, but treat
        # generic binaries as downloads.
        if ctype.startswith(("image/", "video/", "audio/")) or ctype == "application/pdf":
            self.send_header("Content-Disposition",
                             f'inline; filename="{node.name}"')
        else:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{node.name}"')
        self.end_headers()
        try:
            for chunk in iter_file_bytes(self.server_index.tib_path, entry):
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _send_text(self, code: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(tib_path: str, *, host: str = "127.0.0.1", port: int = 0,
          open_browser: bool = True, use_cache: bool = True,
          progress: bool = True) -> None:
    """Launch a local HTTP browser for a `.tib` archive. Blocks until
    the user interrupts with Ctrl-C.

    On startup, builds (or loads from cache) the index, resolves a free
    port if ``port == 0``, optionally opens the user's default browser
    to ``http://{host}:{port}/``, then serves directory listings and
    streams individual files until interrupted.
    """
    index = get_or_build_index(tib_path, progress=progress,
                                use_cache=use_cache)
    tree = _build_tree(index)
    archive_name = os.path.basename(tib_path)

    handler = type(
        "_BoundBrowseHandler", (_BrowseHandler,),
        {
            "server_index": index,
            "server_tree": tree,
            "archive_name": archive_name,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"\n[tibread] serving {tib_path}")
    print(f"[tibread]   URL: {url}")
    print(f"[tibread]   Files: {len(index.files):,}")
    print(f"[tibread] Press Ctrl-C to stop.\n", flush=True)

    if open_browser:
        # Open the browser in a thread so the server can start serving
        # immediately if the browser is slow to launch.
        def _open():
            time.sleep(0.3)
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[tibread] shutting down.", flush=True)
    finally:
        server.server_close()


__all__ = [
    "INDEX_FORMAT_VERSION",
    "FsFileEntry",
    "FsArchiveIndex",
    "build_index",
    "save_index",
    "load_index",
    "get_or_build_index",
    "iter_file_bytes",
    "extract_one",
    "serve",
]
