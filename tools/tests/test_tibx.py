"""Integration tests for the .tibx LSM-index reader.

These tests run end-to-end against the reference archive
``Jmicron 0102.tibx`` (54 GiB Acronis archive3 v8 file).  They cover:

* :meth:`TibxReader.read_arch_header` — extracts hostname, disk GUID,
  agent build, archive UUID from the page-0/1 metadata.
* :func:`tibread.tibx.lsm.read_archive_header` — parses the latest
  ARCH header (multi-page) and decodes every TLV slot + L-SB.
* :func:`tibread.tibx.lsm.walk_ctree` — descends one ctree top-down
  through LDIR pages and confirms LZ4 page-payload decoding produces a
  positive entry count at each level.
* CRC-32C envelope validation across a 50-page random sample.

Skipped when the reference archive is not present on the host.

Run directly::

    python3 tools/tests/test_tibx.py
"""
from __future__ import annotations

import os
import random
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import (  # noqa: E402
    TibxReader,
    read_archive_header,
    walk_ctree,
)


DEFAULT_FIXTURE = "/mnt/e/Jmicron 0102.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxArchHeaderTests(unittest.TestCase):
    """Exercise :meth:`TibxReader.read_arch_header`."""

    def test_hostname_present(self) -> None:
        with TibxReader(FIXTURE) as r:
            hdr = r.read_arch_header()
        # The reference archive was created on a host called
        # STRIDER-WIN63 (visible in the page-1 metadata strings).
        self.assertIn("hostname", hdr, f"keys: {sorted(hdr.keys())}")
        self.assertEqual(hdr["hostname"], "STRIDER-WIN63")

    def test_archive_uuid_decodes(self) -> None:
        with TibxReader(FIXTURE) as r:
            hdr = r.read_arch_header()
        self.assertIn("archive_uuid", hdr)
        # 16 bytes of UUID -> 32 hex chars
        self.assertEqual(len(hdr["archive_uuid"]), 32)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxLsmIndexTests(unittest.TestCase):
    """Exercise the L-SB superblock + ctree walker on the reference file."""

    def test_archive_header_decodes_all_lsbs(self) -> None:
        with TibxReader(FIXTURE) as r:
            hdr = read_archive_header(r)
        # v8 archive: indices 0..8 are L-SB-bearing; some may be empty
        # but should all be parsed successfully.
        self.assertEqual(hdr.hdr_version, 8)
        self.assertGreaterEqual(len(hdr.lsm_trees), 7)
        # The 9 L-SB-bearing slots must all parse (some may be all-zero
        # mem-tree-only L-SBs but still parse).
        tlv_indices = sorted(sb.tlv_index for sb in hdr.lsm_trees)
        self.assertEqual(tlv_indices, list(range(len(tlv_indices))))

    def test_data_map_schema_bytes(self) -> None:
        """TLV[1] = data_map MUST have key=31, value=10 on disk."""
        with TibxReader(FIXTURE) as r:
            hdr = read_archive_header(r)
        data_map = next(sb for sb in hdr.lsm_trees if sb.tlv_index == 1)
        self.assertEqual(data_map.key_length, 31)
        self.assertEqual(data_map.value_length, 10)
        self.assertEqual(data_map.name, "data_map")

    def test_segment_map_schema_bytes(self) -> None:
        """TLV[2] = segment_map MUST have key=8, value=32 on disk."""
        with TibxReader(FIXTURE) as r:
            hdr = read_archive_header(r)
        seg_map = next(sb for sb in hdr.lsm_trees if sb.tlv_index == 2)
        self.assertEqual(seg_map.key_length, 8)
        self.assertEqual(seg_map.value_length, 32)
        self.assertEqual(seg_map.name, "segment_map")

    def test_walk_data_map_descends_at_least_one_ldir(self) -> None:
        """Walking the data_map ctree must reach a LEAF page successfully.

        We don't require LEAF cells to decode (that's the cell decoder's
        job) — but we DO require:
          * the root LDIR page to LZ4-decompress cleanly,
          * its records to slice as ``[31-byte key, 8-byte child ptr]``,
          * the leftmost child to be reachable,
          * the path to bottom out at a LEAF magic page.
        """
        with TibxReader(FIXTURE) as r:
            hdr = read_archive_header(r)
            data_map = next(sb for sb in hdr.lsm_trees if sb.tlv_index == 1)
            # Find the largest ctree (most pages) — that's the most
            # heavily-populated B-tree, gives the best smoke check.
            populated = [c for c in data_map.ctrees if c.offset is not None]
            self.assertGreater(
                len(populated), 0,
                "data_map has no on-disk ctrees in this archive!",
            )
            for ct in populated:
                stats = walk_ctree(r, ct, data_map.key_length)
                self.assertIsNone(
                    stats.error,
                    f"walk_ctree(root={stats.root_page}) failed: {stats.error}",
                )
                self.assertGreaterEqual(stats.levels_visited, 2,
                    "expected at least one LDIR descent before LEAF")
                self.assertGreater(stats.ldir_entries, 0,
                    "expected the LDIR root to have at least one record")
                self.assertEqual(stats.leaf_pages, 1,
                    "expected the leftmost path to bottom out at a LEAF page")


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxPageCrcSampleTests(unittest.TestCase):
    """Spot-check page CRC validation across 50 random pages."""

    def test_50_random_pages_pass_crc(self) -> None:
        rng = random.Random(0xACE)
        with TibxReader(FIXTURE) as r:
            n = min(50, r.page_count)
            indices = rng.sample(range(r.page_count), n)
            mismatches = []
            for idx in indices:
                ok, stored, computed = r.verify_page(idx)
                if not ok:
                    mismatches.append((idx, stored, computed))
            self.assertEqual(
                mismatches, [],
                f"CRC mismatches in 50-page sample: {mismatches[:5]}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
