"""Tests for the FS-mode index/browse layer."""
from __future__ import annotations

import io
import os
import shutil
import struct
import sys
import tempfile
import unittest
import urllib.request
import zlib

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Reuse the synthetic-tib helper from the chunkmap_fs tests.
from test_chunkmap_fs import _build_minimal_fs_tib  # noqa: E402

from tibread.fs_browse import (  # noqa: E402
    FsArchiveIndex,
    build_index,
    extract_one,
    get_or_build_index,
    iter_file_bytes,
    load_index,
    save_index,
    serve,
    _build_tree,
    _resolve_path,
)


def _build_minimal_fs_tib_with_dirtree(tmpdir, files: list) -> str:
    """Build a synthetic FS-mode .tib that ALSO has a directory-tree
    blob in the trailing region, so build_index can pair files with
    paths.

    Each entry in `files` is a (path, content) tuple. We synthesize
    the directory tree using the layout from chunkmap_fs.parse_directory_tree.
    """
    import struct
    # Build the m/n stream first (no f-batches — we don't decode metadata
    # batches in build_index, so they're optional).
    CHUNK = 256 * 1024
    body = bytearray()

    def stored_zlib(payload: bytes) -> bytes:
        c = zlib.compressobj(level=0)
        return c.compress(payload) + c.flush()

    for _path, content in files:
        for i in range(0, max(1, len(content)), CHUNK):
            chunk = content[i:i + CHUNK]
            body.append(0x6D)
            body.extend(stored_zlib(chunk))
        body.append(0x6E)
        body.extend(stored_zlib(b""))

    # Build the directory tree. Layout per parse_directory_tree:
    #   u32 record_count
    #   per record: u32 fullpath_chars; u8[2*chars] fullpath_utf16
    #               u32 tail_u16_count; u8[2*tail_u16_count] tail
    #   tail: u32 basename_chars; u8[2*chars] basename_utf16
    #         u32 sub_chars; u8[2*chars] sub_utf16
    #         74-byte fixed footer

    def encode_record(path: str, file_size: int) -> bytes:
        # fullpath: NUL-terminated UTF-16-LE
        fp_chars = list(path) + ["\x00"]
        fp_bytes = "".join(fp_chars).encode("utf-16-le")
        fp_count = len(fp_chars)

        basename = path.rsplit("/", 1)[-1]
        bn_chars = list(basename) + ["\x00"]
        bn_bytes = "".join(bn_chars).encode("utf-16-le")
        bn_count = len(bn_chars)

        # sub: longname \0 + u32(=2) + u32 short_chars + shortname\0
        longname = basename
        ln_chars = list(longname) + ["\x00"]
        ln_bytes = "".join(ln_chars).encode("utf-16-le")
        shortname = basename[:8].upper()  # crude 8.3 form
        sn_chars = list(shortname) + ["\x00"]
        sn_bytes = "".join(sn_chars).encode("utf-16-le")
        sub = (
            ln_bytes
            + struct.pack("<II", 2, len(sn_chars))
            + sn_bytes
        )
        # sub_chars is the count of u16s in sub.
        sub_count = len(sub) // 2

        # 74-byte footer.
        footer = bytearray(0x4A)
        struct.pack_into("<Q", footer, 0x00, 0x123456789abcdef0)  # file_id
        struct.pack_into("<I", footer, 0x08, 0xdeadbeef)          # parent_hash
        struct.pack_into("<Q", footer, 0x0C, file_size)
        struct.pack_into("<Q", footer, 0x14, file_size)           # alloc_size
        struct.pack_into("<Q", footer, 0x1C, 0)                    # ts1
        struct.pack_into("<I", footer, 0x24, 0)                    # attrs
        struct.pack_into("<Q", footer, 0x28, 0)                    # ts2
        struct.pack_into("<I", footer, 0x30, 1)                    # valid

        tail_payload = (
            struct.pack("<I", bn_count) + bn_bytes
            + struct.pack("<I", sub_count) + sub
            + bytes(footer)
        )
        # tail_u16_count is the count of u16 words in tail_payload.
        tail_words = len(tail_payload) // 2
        if len(tail_payload) % 2:
            # Should never happen; pad if it does.
            tail_payload += b"\x00"
            tail_words = len(tail_payload) // 2

        return (
            struct.pack("<I", fp_count) + fp_bytes
            + struct.pack("<I", tail_words) + tail_payload
        )

    tree = struct.pack("<I", len(files))
    for path, content in files:
        tree += encode_record(path, len(content))

    # Wrap: [u8 0x65][raw deflate of metadata_blob]
    #       [5-byte framing 0xc0 0x83 0xc7 0x05 0x67]
    #       [raw deflate of tree]
    #       [u64 record_count][u64 body_relative_offset of 0x65]
    #       [u32 trailer magic 0x94E18A2C]
    metadata_blob = b"\x00" * 1360  # Dummy; build_index doesn't read it
    raw_deflate_meta = (
        zlib.compressobj(level=-1, wbits=-15)
    )
    meta_compressed = raw_deflate_meta.compress(metadata_blob) + raw_deflate_meta.flush()

    raw_deflate_tree = zlib.compressobj(level=-1, wbits=-15)
    tree_compressed = raw_deflate_tree.compress(tree) + raw_deflate_tree.flush()

    framing = bytes.fromhex("c083c70567")

    # opaque region structure: type byte 0x65 + meta + framing + tree
    opaque = b"\x65" + meta_compressed + framing + tree_compressed

    # Append opaque to body (after the m/n stream).
    body.extend(opaque)

    # body-relative offset of the 0x65 byte = position of 0x65 in body
    # (which is len(m/n stream)).
    body_rel_off = len(body) - len(opaque)

    # 16-byte locator + 4-byte trailer magic.
    locator = struct.pack("<QQ", len(files), body_rel_off)
    trailer_magic = bytes.fromhex("2C8AE194")
    body.extend(locator)
    body.extend(trailer_magic)

    slice_size = len(body)

    # Volume header: 32 bytes.
    header = struct.pack(
        "<IHH4sQI4sI",
        0xA2B924CE,                # magic
        32, 0,                      # hdrlen, version
        b"\x11\x22\x33\x44",
        0xDEADBEEFCAFEBABE,
        1,                          # sequence
        b"\x00\x00\x00\x00",
        32,                         # block_size flag
    )

    # 48-byte footer with slice_size at +8.
    foot = bytearray(48)
    struct.pack_into("<Q", foot, 8, slice_size)
    struct.pack_into("<I", foot, 44, 0xA2B924CE)

    path = os.path.join(tmpdir, "synth.tib")
    with open(path, "wb") as f:
        f.write(header)
        f.write(body)
        f.write(foot)
    return path


class IndexBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-fs-browse-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_build_index_pairs_paths(self) -> None:
        files = [
            ("C:/Users/alice/photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 100),
            ("C:/Users/alice/notes.txt", b"hello world\n"),
            ("C:/Windows/System32/cmd.exe", b"MZ" + b"\x00" * 200),
        ]
        path = _build_minimal_fs_tib_with_dirtree(self.tmpdir, files)
        idx = build_index(path)
        self.assertEqual(len(idx.files), 3)
        # Paths are normalized (drive letter stripped).
        paths = sorted(e.path for e in idx.files)
        self.assertEqual(
            paths,
            sorted([
                "Users/alice/photo.jpg",
                "Users/alice/notes.txt",
                "Windows/System32/cmd.exe",
            ]),
        )
        # Sizes are correct.
        for e in idx.files:
            if e.path.endswith("notes.txt"):
                self.assertEqual(e.size, len(b"hello world\n"))

    def test_extract_one_round_trips(self) -> None:
        files = [("C:/dir/foo.bin", b"abcdefghij" * 10000)]
        path = _build_minimal_fs_tib_with_dirtree(self.tmpdir, files)
        idx = build_index(path)
        entry = idx.files[0]
        out = os.path.join(self.tmpdir, "out.bin")
        n = extract_one(path, entry, out)
        self.assertEqual(n, len(files[0][1]))
        with open(out, "rb") as f:
            self.assertEqual(f.read(), files[0][1])

    def test_save_load_roundtrip(self) -> None:
        files = [("C:/x.txt", b"alpha")]
        path = _build_minimal_fs_tib_with_dirtree(self.tmpdir, files)
        idx = build_index(path)
        save_path = save_index(idx)
        self.assertTrue(os.path.exists(save_path))
        loaded = load_index(path)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(len(loaded.files), 1)
        self.assertEqual(loaded.files[0].path, "x.txt")

    def test_load_invalidates_on_size_change(self) -> None:
        files = [("C:/x.txt", b"alpha")]
        path = _build_minimal_fs_tib_with_dirtree(self.tmpdir, files)
        idx = build_index(path)
        save_index(idx)
        # Mutate the file: reload should detect mismatch and refuse.
        with open(path, "ab") as f:
            f.write(b"\x00")
        self.assertIsNone(load_index(path))


class TreeAndResolveTests(unittest.TestCase):
    def test_build_tree_groups_paths(self) -> None:
        from tibread.fs_browse import FsFileEntry
        idx = FsArchiveIndex(
            tib_path="x.tib", tib_size=0, tib_mtime_ns=0,
            files=[
                FsFileEntry(path="A/foo.txt", size=10, chunk_offsets=[0], chunk_comp_lens=[10]),
                FsFileEntry(path="A/B/bar.txt", size=20, chunk_offsets=[10], chunk_comp_lens=[10]),
                FsFileEntry(path="C/baz.txt", size=30, chunk_offsets=[20], chunk_comp_lens=[10]),
            ],
        )
        root = _build_tree(idx)
        self.assertIn("A", root.children)
        self.assertIn("C", root.children)
        self.assertIn("foo.txt", root.children["A"].children)
        self.assertIn("B", root.children["A"].children)
        self.assertIn("bar.txt", root.children["A"].children["B"].children)

    def test_resolve_path(self) -> None:
        from tibread.fs_browse import FsFileEntry
        idx = FsArchiveIndex(
            tib_path="x.tib", tib_size=0, tib_mtime_ns=0,
            files=[FsFileEntry(path="A/B/c.txt", size=1, chunk_offsets=[0], chunk_comp_lens=[1])],
        )
        root = _build_tree(idx)
        self.assertEqual(_resolve_path(root, "/").name, "")
        self.assertEqual(_resolve_path(root, "/A").name, "A")
        self.assertEqual(_resolve_path(root, "/A/B").name, "B")
        self.assertEqual(_resolve_path(root, "/A/B/c.txt").name, "c.txt")
        self.assertIsNone(_resolve_path(root, "/A/missing"))


class HttpServerTests(unittest.TestCase):
    """Spin up the server in a thread and make real HTTP requests."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-fs-http-")
        files = [
            ("C:/Users/alice/photo.jpg",
             b"\xff\xd8\xff\xe0" + b"\x00" * 100),
            ("C:/Users/alice/notes.txt",
             b"hello world\n"),
        ]
        self.tib = _build_minimal_fs_tib_with_dirtree(self.tmpdir, files)
        self.expected = {p.replace("C:/", ""): c for p, c in files}

        # Start the server in a daemon thread.
        from tibread.fs_browse import (
            ThreadingHTTPServer, _BrowseHandler, _build_tree,
            build_index,
        )
        self.idx = build_index(self.tib)
        self.tree = _build_tree(self.idx)
        handler = type(
            "_HandlerForTest", (_BrowseHandler,),
            {
                "server_index": self.idx,
                "server_tree": self.tree,
                "archive_name": os.path.basename(self.tib),
            },
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get(self, url_path: str):
        url = f"http://127.0.0.1:{self.port}{url_path}"
        return urllib.request.urlopen(url)

    def test_root_listing(self) -> None:
        resp = self._get("/")
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8")
        self.assertIn("Users", body)

    def test_subdir_listing(self) -> None:
        resp = self._get("/Users/alice/")
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8")
        self.assertIn("photo.jpg", body)
        self.assertIn("notes.txt", body)

    def test_file_download(self) -> None:
        resp = self._get("/Users/alice/notes.txt")
        self.assertEqual(resp.status, 200)
        body = resp.read()
        self.assertEqual(body, self.expected["Users/alice/notes.txt"])

    def test_404_unknown_path(self) -> None:
        try:
            self._get("/does/not/exist")
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


# Imports needed only for the HTTP test class.
import threading  # noqa: E402
import urllib.error  # noqa: E402


if __name__ == "__main__":
    unittest.main(verbosity=2)
