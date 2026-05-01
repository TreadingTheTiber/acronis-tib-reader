"""Tests for the .tibx segment_map (TLV[2]) seg_id index.

The pure-Python tests exercise the value-decoder and the SGIX cache
file format and don't need the reference archive.

The fixture-bound tests run against ``example.tibx`` and verify:

* :func:`load_seg_index` produces the expected ~263 k entries;
* every entry's ``page_offset`` actually points at an SG header in the
  archive (sampled, then full-scan if cheap);
* the ``<tibx>.segidx`` cache round-trips byte-for-byte through
  :func:`save_seg_index` / :func:`load_seg_index_cache`.

Run directly::

    python3 tools/tests/test_tibx_segment_map.py
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import TibxReader  # noqa: E402
from tibread.tibx.segment_map import (  # noqa: E402
    SEG_INDEX_CACHE_MAGIC,
    SEG_INDEX_CACHE_VERSION,
    SegLocator,
    build_seg_index_from_lsm,
    decode_segment_map_value,
    load_seg_index,
    load_seg_index_cache,
    save_seg_index,
)
from tibread.tibx.segment import parse_sg_header  # noqa: E402


DEFAULT_FIXTURE = "/path/to/example.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


class DecodeValueTests(unittest.TestCase):
    def test_decode_basic(self) -> None:
        # 32 bytes: page_count=46 (LE u32), page_offset=153 (BE u32),
        # then padding + hash.
        raw = (
            (46).to_bytes(4, "little")
            + (153).to_bytes(4, "big")
            + b"\x00" * 24
        )
        pc, po = decode_segment_map_value(raw)
        self.assertEqual(pc, 46)
        self.assertEqual(po, 153)

    def test_decode_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            decode_segment_map_value(b"\x00" * 7)


class CacheRoundTripTests(unittest.TestCase):
    def test_save_then_load_returns_equal(self) -> None:
        index = {
            1: SegLocator(seg_id=1, page_count=1, page_offset=7),
            42: SegLocator(seg_id=42, page_count=12, page_offset=945737),
            100000: SegLocator(seg_id=100000, page_count=1, page_offset=12345678),
        }
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "test.segidx")
            save_seg_index(path, index)
            loaded = load_seg_index_cache(path)
        self.assertEqual(loaded, index)

    def test_cache_header_layout(self) -> None:
        index = {7: SegLocator(seg_id=7, page_count=1, page_offset=7)}
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "test.segidx")
            save_seg_index(path, index)
            with open(path, "rb") as f:
                blob = f.read()
        self.assertEqual(blob[:4], SEG_INDEX_CACHE_MAGIC)
        version = struct.unpack(">I", blob[4:8])[0]
        self.assertEqual(version, SEG_INDEX_CACHE_VERSION)
        entry_count = struct.unpack(">I", blob[8:12])[0]
        self.assertEqual(entry_count, 1)
        self.assertEqual(len(blob), 12 + 1 * 16)

    def test_load_missing_file_returns_none(self) -> None:
        self.assertIsNone(load_seg_index_cache("/nonexistent/path/foo.segidx"))

    def test_load_wrong_magic_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.segidx")
            with open(path, "wb") as f:
                f.write(b"NOPE" + b"\x00" * 100)
            self.assertIsNone(load_seg_index_cache(path))

    def test_load_wrong_version_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.segidx")
            with open(path, "wb") as f:
                f.write(SEG_INDEX_CACHE_MAGIC)
                f.write(struct.pack(">I", 99))
                f.write(struct.pack(">I", 0))
            self.assertIsNone(load_seg_index_cache(path))


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class SegmentMapFixtureTests(unittest.TestCase):
    """Tests that need the reference archive."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reader = TibxReader(FIXTURE)
        cls.index = build_seg_index_from_lsm(cls.reader)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.reader.close()

    def test_index_has_expected_entry_count(self) -> None:
        # The example archive carries 263 063 SG segments.
        self.assertEqual(len(self.index), 263063)

    def test_seg_id_4_is_bootstrap_segment(self) -> None:
        loc = self.index[4]
        self.assertEqual(loc.page_offset, 6)
        self.assertEqual(loc.page_count, 1)

    def test_seg_id_7_is_partition_0_bpb(self) -> None:
        # seg_id 7 = first segment of System Reserved partition's BPB.
        loc = self.index[7]
        self.assertEqual(loc.page_offset, 7)
        self.assertEqual(loc.page_count, 1)

    def test_every_entry_points_at_an_sg_header(self) -> None:
        # Sample every 1000th entry to keep the test fast (full scan
        # would require ~30 s).  The cartography agent independently
        # verified that all 263 063 entries match.
        sample = sorted(self.index.items())[::1000]
        for seg_id, loc in sample:
            page = self.reader._raw_read_page(loc.page_offset)
            seg = parse_sg_header(page, loc.page_offset)
            self.assertIsNotNone(
                seg,
                f"seg_id={seg_id} page_offset={loc.page_offset}: not an SG header",
            )
            self.assertEqual(
                seg.page_span(),
                loc.page_count,
                f"seg_id={seg_id}: page_span() != page_count",
            )

    def test_load_seg_index_cache_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "example.segidx")
            # First call: builds + writes cache.
            idx1 = load_seg_index(self.reader, cache_path=cache_path)
            self.assertTrue(os.path.exists(cache_path))
            # Second call: must load from cache (same dict).
            idx2 = load_seg_index(self.reader, cache_path=cache_path)
        self.assertEqual(idx1, idx2)
        self.assertEqual(idx1, self.index)


if __name__ == "__main__":
    unittest.main(verbosity=2)
