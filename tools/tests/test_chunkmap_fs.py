"""Tests for the FS-mode hybrid .tib walker.

Two layers:

* Predicate / sniff tests run on synthetic minimal byte streams.
* The end-to-end recovery test runs against the real reference file
  (`share_backup_example.tib` on a QNAP share) when accessible,
  capped at 5 files for speed. Skipped on portable / CI machines.
"""
from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile
import unittest
import zlib

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.chunkmap_fs import (  # noqa: E402
    DATA_START,
    TYPE_FILE_CHUNK,
    TYPE_FILE_END,
    META_BLOB_MAGIC,
    META_PREAMBLE_FIXED,
    FsFileMetadata,
    _decode_metadata_blob,
    _sniff_extension,
    is_fs_mode_hybrid,
    walk_fs_records,
    extract_files,
    parse_metadata_batch,
)


def _build_minimal_fs_tib(tmpdir: str, files: list[bytes]) -> str:
    """Build a minimal FS-mode hybrid .tib containing the given files.

    The volume header, footer, and trailer use the layouts decoded from
    the reference share_backup file. Chunk size is fixed at 256 KiB; if a
    file is larger it gets split into multiple `m` records.
    """
    CHUNK = 256 * 1024
    body = bytearray()

    def stored_zlib(payload: bytes) -> bytes:
        # Force zlib STORED-block output (matches what the FS-mode
        # encoder emits; deflate-default would also work for our reader
        # but we want fidelity to the real format).
        c = zlib.compressobj(level=0)
        return c.compress(payload) + c.flush()

    for f in files:
        for i in range(0, max(1, len(f)), CHUNK):
            chunk = f[i : i + CHUNK]
            body.append(TYPE_FILE_CHUNK)
            body.extend(stored_zlib(chunk))
        body.append(TYPE_FILE_END)
        body.extend(stored_zlib(b""))

    # Trailer: 4 bytes of FS-trailer magic at the end of the data
    # region.
    body.extend(bytes.fromhex("2C8AE194"))
    slice_size = len(body)

    # Volume header: 32 bytes. magic | hdrlen=32 | version=0 | guid... |
    # sequence=1 | crc | block_size=32.
    header = struct.pack(
        "<IHH4sQI4sI",
        0xA2B924CE,                # magic
        32,                        # hdrlen
        0,                         # version
        b"\x11\x22\x33\x44",      # guid_lo32
        0xDEADBEEFCAFEBABE,        # guid hi64
        1,                         # sequence
        b"\x00\x00\x00\x00",      # u32 crc
        32,                        # block_size flag
    )
    assert len(header) == 32

    # Footer: 48 bytes. We don't need to mirror the header faithfully
    # for the reader; only the slice_size at +8 and the volume magic at
    # +44 (not actually checked by our walker but emitted for
    # completeness).
    footer = bytearray(48)
    struct.pack_into("<Q", footer, 8, slice_size)
    struct.pack_into("<I", footer, 44, 0xA2B924CE)

    path = os.path.join(tmpdir, "synthetic.tib")
    with open(path, "wb") as out:
        out.write(header)
        out.write(body)
        out.write(footer)
    return path


class IsFsModeHybridTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-fs-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_synthetic_hybrid_recognized(self) -> None:
        path = _build_minimal_fs_tib(self.tmpdir, [b"hello world"])
        self.assertTrue(is_fs_mode_hybrid(path))

    def test_pure_sector_mode_not_recognized(self) -> None:
        # A file with the right header magic but a sector trailer (0x2B)
        # should NOT be classified as fs-mode hybrid.
        path = os.path.join(self.tmpdir, "sector.tib")
        # Build by hand: header + tiny body + sector-trailer + footer.
        header = struct.pack(
            "<IHH4sQI4sI", 0xA2B924CE, 32, 0,
            b"\x11\x22\x33\x44", 0xDEADBEEF, 1, b"\x00\x00\x00\x00", 32,
        )
        body = b"\x6d" + zlib.compress(b"x") + bytes.fromhex("2B8AE194")
        footer = bytearray(48)
        struct.pack_into("<Q", footer, 8, len(body))
        struct.pack_into("<I", footer, 44, 0xA2B924CE)
        with open(path, "wb") as out:
            out.write(header)
            out.write(body)
            out.write(footer)
        self.assertFalse(is_fs_mode_hybrid(path))

    def test_random_garbage_not_recognized(self) -> None:
        path = os.path.join(self.tmpdir, "junk.tib")
        with open(path, "wb") as f:
            f.write(os.urandom(512))
        self.assertFalse(is_fs_mode_hybrid(path))

    def test_too_small_file_not_recognized(self) -> None:
        path = os.path.join(self.tmpdir, "tiny.tib")
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        self.assertFalse(is_fs_mode_hybrid(path))


class WalkAndExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-fs-walk-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_walk_yields_one_record_per_block(self) -> None:
        files = [b"alpha", b"bravo", b"charlie"]
        path = _build_minimal_fs_tib(self.tmpdir, files)
        records = list(walk_fs_records(path))
        # Each file produces 1 'm' + 1 'n' = 2 records. 3 files → 6.
        self.assertEqual(len(records), 6)
        self.assertEqual(
            [r.type_byte for r in records],
            [TYPE_FILE_CHUNK, TYPE_FILE_END] * 3,
        )
        # First file's payload round-trips.
        self.assertEqual(records[0].plain, b"alpha")

    def test_extract_recovers_file_content(self) -> None:
        files = [b"hello", b"world\n", b"binary\x00\x01\x02data"]
        path = _build_minimal_fs_tib(self.tmpdir, files)
        outdir = os.path.join(self.tmpdir, "out")
        n = extract_files(path, outdir)
        self.assertEqual(n, 3)
        recovered = sorted(f for f in os.listdir(outdir)
                           if f.startswith("recovered_"))
        self.assertEqual(len(recovered), 3)
        bodies = []
        for name in recovered:
            with open(os.path.join(outdir, name), "rb") as fh:
                bodies.append(fh.read())
        self.assertEqual(bodies, files)

    def test_large_file_split_across_chunks(self) -> None:
        # 600 KB file → 3 'm' chunks (256+256+88 KB) + 1 'n'.
        big = bytes(range(256)) * (600 * 1024 // 256)
        path = _build_minimal_fs_tib(self.tmpdir, [big])
        outdir = os.path.join(self.tmpdir, "out")
        extract_files(path, outdir)
        recovered = [f for f in os.listdir(outdir)
                     if f.startswith("recovered_")]
        self.assertEqual(len(recovered), 1)
        with open(os.path.join(outdir, recovered[0]), "rb") as fh:
            self.assertEqual(fh.read(), big)


class ExtensionSniffTests(unittest.TestCase):
    def test_jpeg(self) -> None:
        self.assertEqual(_sniff_extension(b"\xff\xd8\xff\xe0blah"), "jpg")

    def test_png(self) -> None:
        self.assertEqual(_sniff_extension(b"\x89PNG\r\n\x1a\n"), "png")

    def test_quicktime(self) -> None:
        self.assertEqual(
            _sniff_extension(b"\x00\x00\x00\x14ftypqt  more"), "mov"
        )

    def test_pdf(self) -> None:
        self.assertEqual(_sniff_extension(b"%PDF-1.4\n"), "pdf")

    def test_text(self) -> None:
        self.assertEqual(_sniff_extension(b"hello world\n"), "txt")

    def test_unknown_binary(self) -> None:
        self.assertEqual(_sniff_extension(b"\x00\xff\x99\xaa\xbb"), "bin")


# ---- end-to-end against the real fixture (best-effort) -------------------

REAL_FIXTURE = (
    "/path/to/archives/"
    "2022.11 Example Backups/examplehost/share_backup_example.tib"
)


@unittest.skipUnless(
    os.path.exists(REAL_FIXTURE),
    "real share_backup fixture not available",
)
class RealFixtureTests(unittest.TestCase):
    def test_real_fixture_classified_as_hybrid(self) -> None:
        self.assertTrue(is_fs_mode_hybrid(REAL_FIXTURE))

    def test_recover_first_few_files(self) -> None:
        outdir = tempfile.mkdtemp(prefix="tibread-fs-real-")
        try:
            n = extract_files(REAL_FIXTURE, outdir, max_files=4)
            self.assertGreaterEqual(n, 4)
            # The first non-metadata file in this archive is a JPEG.
            recovered = sorted(
                f for f in os.listdir(outdir) if f.startswith("recovered_")
            )
            self.assertTrue(recovered[0].endswith(".jpg"))
            with open(os.path.join(outdir, recovered[0]), "rb") as fh:
                head = fh.read(3)
            self.assertEqual(head, b"\xff\xd8\xff")
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def test_metadata_batch_validation(self) -> None:
        """Walking 50 files of the real fixture should pair >= 90% of
        the files emitted before the second f-record with metadata
        whose file_size matches the recovered content size."""
        import json
        outdir = tempfile.mkdtemp(prefix="tibread-fs-real-meta-")
        try:
            extract_files(REAL_FIXTURE, outdir, max_files=50)
            sidecar = os.path.join(outdir, "metadata.jsonl")
            self.assertTrue(os.path.exists(sidecar))
            entries = [json.loads(l) for l in open(sidecar)]
            # Files 1-20 should all have metadata (R1 covers them).
            first_batch = [e for e in entries[:20]]
            with_meta = sum(1 for e in first_batch
                            if e["expected_size"] is not None)
            size_match = sum(1 for e in first_batch if e["size_ok"])
            self.assertGreaterEqual(with_meta, 18,
                                    "expected >= 18 of 20 first-batch files "
                                    "to have metadata paired")
            self.assertGreaterEqual(size_match, 17,
                                    "expected >= 17 of 20 first-batch files "
                                    "to validate by size")
        finally:
            shutil.rmtree(outdir, ignore_errors=True)


# ---- metadata-batch parser unit tests ------------------------------------


def _build_metadata_blob(file_size: int, num_extents: int,
                        md5: bytes = b"\x00" * 16,
                        sd_len: int = 100,
                        ads_name: Optional[str] = None) -> bytes:
    """Build a synthetic metadata blob matching the on-disk layout."""
    import struct
    out = bytearray()
    out.extend(META_BLOB_MAGIC)                   # +0x00
    out.extend(struct.pack("<Q", file_size))       # +0x08
    out.extend(struct.pack("<I", num_extents))     # +0x10
    out.extend(b"\x00" * 8)                        # +0x14 reserved
    out.extend(b"\x00" * 8)                        # +0x1C/+0x20 reserved
    out.extend(b"\x00" * 4)                        # +0x24
    out.extend(md5)                                # +0x28..+0x37
    out.extend(b"\x00" * 8)                        # +0x38..+0x3F tail-marker
    assert len(out) == 0x40
    # extent table (32 B each, all zeros for synthetic test)
    out.extend(b"\x00" * (32 * num_extents))
    # trailer: 8 B padding + SD + (optional ADS) + 16 B trailing zeros
    out.extend(b"\x00" * 8)
    out.extend(b"\x01\x02\x00\x04\x80")           # SD revision + control
    out.extend(b"\x00" * (sd_len - 5))
    if ads_name:
        name_bytes = ads_name.encode("utf-16-le")
        out.extend(struct.pack("<III", 4, 0, len(name_bytes)))
        out.extend(name_bytes)
    out.extend(struct.pack("<Q", file_size))      # file_size_replica
    out.extend(b"\x00" * 16)
    return bytes(out)


class MetadataBlobParserTests(unittest.TestCase):
    def test_decode_basic_blob(self) -> None:
        blob = _build_metadata_blob(file_size=12345, num_extents=3)
        meta = _decode_metadata_blob(blob)
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.file_size, 12345)
        self.assertEqual(meta.num_extents, 3)
        self.assertEqual(len(meta.extents), 3)

    def test_decode_with_ads_name(self) -> None:
        blob = _build_metadata_blob(file_size=99, num_extents=1,
                                    ads_name=":encryptable:$DATA")
        meta = _decode_metadata_blob(blob)
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.ads_name, ":encryptable:$DATA")

    def test_decode_rejects_bad_magic(self) -> None:
        blob = b"\xde\xad\xbe\xef" + b"\x00" * 200
        self.assertIsNone(_decode_metadata_blob(blob))

    def test_decode_rejects_huge_extent_count(self) -> None:
        import struct
        bad = bytearray(_build_metadata_blob(0, 1))
        # Smash num_extents to an absurd value
        struct.pack_into("<I", bad, 0x10, 99999)
        self.assertIsNone(_decode_metadata_blob(bytes(bad)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
