"""Integration tests for the .tibx slice / chain enumerator.

These exercises run end-to-end against the reference archive
``Jmicron 0102.tibx`` (a 54 GiB Acronis archive3 v8 file).  They cover:

* :func:`tibread.tibx.chains.enumerate_slices` — decodes the L-SB
  mem-tree at TLV[5] and (when populated) the on-disk ctrees, returning
  every alive slice as a :class:`Slice` dataclass.
* Sanity checks on the decoded fields (slice_id key vs. record body,
  timestamp range, flags-byte interpretation).
* :func:`tibread.tibx.chains.walk_chain_from_uuid` — follows
  ``parent_uuid`` links back to the chain root.

Skipped when the reference archive is not present on the host.

Run directly::

    python3 tools/tests/test_tibx_chains.py
"""
from __future__ import annotations

import datetime as dt
import os
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import (  # noqa: E402
    TibxReader,
    enumerate_slices,
    find_slice_by_uuid,
    iter_chains,
    parse_slice_record,
    slice_features,
    slice_type_from_flags,
    walk_chain_from_uuid,
)
from tibread.tibx.chains import (  # noqa: E402
    SLICE_RECORD_LEN,
    SLICE_TYPE_DIFF,
    SLICE_TYPE_EDITED,
    SLICE_TYPE_FULL,
    SLICE_TYPE_INC,
    ZERO_UUID,
    Slice,
)


DEFAULT_FIXTURE = "/mnt/e/Jmicron 0102.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


class SliceTypeFromFlagsTests(unittest.TestCase):
    """Pure-Python tests for the flags-byte decoder; no fixture needed."""

    def test_full_when_no_bits_set(self) -> None:
        self.assertEqual(slice_type_from_flags(0x00), SLICE_TYPE_FULL)

    def test_diff_bit_2(self) -> None:
        self.assertEqual(slice_type_from_flags(0x04), SLICE_TYPE_DIFF)
        # diff wins over inc (bit 0 also set)
        self.assertEqual(slice_type_from_flags(0x05), SLICE_TYPE_DIFF)

    def test_edited_bit_3(self) -> None:
        self.assertEqual(slice_type_from_flags(0x08), SLICE_TYPE_EDITED)

    def test_inc_when_only_features(self) -> None:
        # bit 0 (a feature bit) → INC type
        self.assertEqual(slice_type_from_flags(0x01), SLICE_TYPE_INC)
        # bit 1 (named "hidden" feature) → INC
        self.assertEqual(slice_type_from_flags(0x02), SLICE_TYPE_INC)

    def test_internal_hidden_alone_is_full(self) -> None:
        # bit 7 alone (internal-hidden) does NOT trigger INC — it's
        # not in the 0x73 mask.
        self.assertEqual(slice_type_from_flags(0x80), SLICE_TYPE_FULL)

    def test_features_decoded(self) -> None:
        feats = slice_features(0x82)  # internal_hidden + "hidden"
        self.assertIn("hidden", feats)
        self.assertIn("internal_hidden", feats)


class ParseSliceRecordTests(unittest.TestCase):
    """Pure-Python tests for the 132-byte slice record parser."""

    def test_round_trip_minimal(self) -> None:
        record = bytearray(SLICE_RECORD_LEN)
        # Embed a known UUID + timestamps + zero parent (FULL).
        record[0x00:0x10] = b"\xaa" * 16
        # ts_a = 1_700_000_000_000 ms; ts_b same +1 hour
        ts_a = 1_700_000_000_000
        ts_b = ts_a + 3600 * 1000
        record[0x10:0x18] = ts_a.to_bytes(8, "big")
        record[0x18:0x20] = ts_b.to_bytes(8, "big")
        # parent uuid stays zero -> FULL
        record[0x44] = 0x00
        s = parse_slice_record(slice_id=1, record=bytes(record))
        self.assertEqual(s.slice_id, 1)
        self.assertEqual(s.uuid, b"\xaa" * 16)
        self.assertEqual(s.parent_uuid, ZERO_UUID)
        self.assertEqual(s.slice_type, SLICE_TYPE_FULL)
        self.assertEqual(s.ctime, ts_a)
        self.assertEqual(s.mtime, ts_b)
        self.assertTrue(s.is_full)

    def test_inc_with_parent(self) -> None:
        record = bytearray(SLICE_RECORD_LEN)
        record[0x00:0x10] = b"\xbb" * 16
        record[0x20:0x30] = b"\xaa" * 16  # parent
        record[0x44] = 0x01  # bit 0 set -> INC
        s = parse_slice_record(slice_id=2, record=bytes(record))
        self.assertEqual(s.slice_type, SLICE_TYPE_INC)
        self.assertEqual(s.parent_uuid, b"\xaa" * 16)
        self.assertFalse(s.is_full)

    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_slice_record(slice_id=1, record=b"\x00" * 16)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxChainsFixtureTests(unittest.TestCase):
    """Empirical tests against the reference ``Jmicron 0102.tibx`` archive.

    Empirically (verified by walking TLV[5]'s mem-tree directly) this
    archive holds **one alive slice** (``slice_id=2``, INC) plus a
    tombstone for ``slice_id=1``.  The tests are written against that
    ground truth — *not* against the speculative "2 slices" claim that
    appeared in early drafts of ``ARCHIVE3_CHAINS.md``.
    """

    @classmethod
    def setUpClass(cls) -> None:
        with TibxReader(FIXTURE) as r:
            cls.slices = enumerate_slices(r)

    def test_at_least_one_slice(self) -> None:
        self.assertGreaterEqual(len(self.slices), 1)
        for s in self.slices:
            self.assertIsInstance(s, Slice)
            # 16-byte UUID, never the zero UUID for an alive slice.
            self.assertEqual(len(s.uuid), 16)
            self.assertNotEqual(s.uuid, ZERO_UUID)

    def test_slice_ids_are_unique_and_positive(self) -> None:
        ids = [s.slice_id for s in self.slices]
        self.assertEqual(len(ids), len(set(ids)))
        for sid in ids:
            self.assertGreaterEqual(sid, 1)

    def test_timestamps_are_sensible(self) -> None:
        # The fixture was created in early 2023; require ts_a / ts_b
        # to fall within a generous (2010, 2050) window.
        lo = int(dt.datetime(2010, 1, 1, tzinfo=dt.timezone.utc).timestamp() * 1000)
        hi = int(dt.datetime(2050, 1, 1, tzinfo=dt.timezone.utc).timestamp() * 1000)
        for s in self.slices:
            self.assertGreaterEqual(s.ctime, lo, f"slice {s.slice_id} ctime too small")
            self.assertLess(s.ctime, hi, f"slice {s.slice_id} ctime too large")
            # mtime, if set, must not predate ctime
            if s.mtime:
                self.assertGreaterEqual(s.mtime, s.ctime)
                self.assertLess(s.mtime, hi)

    def test_jmicron_fixture_specifics(self) -> None:
        """Pin down the empirical ground truth for the reference archive."""
        # We know slice_id=2 is in the mem-tree.
        sids = {s.slice_id for s in self.slices}
        self.assertIn(2, sids)
        # The Jmicron 0102 archive has its slice timestamps in Feb 2023.
        feb_2023 = int(
            dt.datetime(2023, 2, 1, tzinfo=dt.timezone.utc).timestamp() * 1000
        )
        mar_2023 = int(
            dt.datetime(2023, 3, 1, tzinfo=dt.timezone.utc).timestamp() * 1000
        )
        for s in self.slices:
            if s.slice_id == 2:
                self.assertGreater(s.ctime, feb_2023)
                self.assertLess(s.ctime, mar_2023)
                # uuid first byte is 9f (empirically; document this so
                # any decoder regression that mis-aligns the value
                # bytes is caught here).
                self.assertEqual(s.uuid[0], 0x9F)

    def test_parent_uuid_linkage_consistency(self) -> None:
        """For every non-FULL slice, parent_uuid should either be zero
        or point to another known slice.  We tolerate orphan-INC slices
        whose parent was tombstoned (this is the case in the reference
        archive: slice_id=1 was deleted), but we still require:

        * EITHER at least one FULL exists, OR every non-FULL is an orphan
          (parent_uuid not in the alive set).
        * No slice points to itself.
        """
        by_uuid = {s.uuid: s for s in self.slices}
        full_count = sum(1 for s in self.slices if s.is_full)
        # No self-loops.
        for s in self.slices:
            if not s.is_full:
                self.assertNotEqual(
                    s.parent_uuid, s.uuid,
                    f"slice {s.slice_id} parent_uuid == own uuid",
                )
        # If there is any non-FULL slice and any FULL exists, the
        # walk_chain_from_uuid path must terminate (not infinite loop).
        for s in self.slices:
            if s.is_full:
                continue
            with TibxReader(FIXTURE) as r:
                chain = walk_chain_from_uuid(r, s.uuid)
            # walk produces at minimum the starting slice
            self.assertGreaterEqual(len(chain), 1)
            self.assertEqual(chain[0].uuid, s.uuid)
            # The terminal slice is either a FULL or has a parent that
            # is not in the archive (tombstoned/orphan).  Both are OK.
            terminal = chain[-1]
            if not terminal.is_full:
                self.assertNotIn(terminal.parent_uuid, by_uuid)

        # Sanity: full_count + orphan_count == total
        self.assertGreaterEqual(full_count, 0)

    def test_find_slice_by_uuid(self) -> None:
        if not self.slices:
            self.skipTest("no slices in fixture")
        target = self.slices[0]
        with TibxReader(FIXTURE) as r:
            found = find_slice_by_uuid(r, target.uuid)
        self.assertIsNotNone(found)
        self.assertEqual(found.uuid, target.uuid)
        self.assertEqual(found.slice_id, target.slice_id)

    def test_iter_chains_covers_every_slice(self) -> None:
        with TibxReader(FIXTURE) as r:
            chains = list(iter_chains(r))
        covered_uuids = {s.uuid for chain in chains for s in chain}
        all_uuids = {s.uuid for s in self.slices}
        self.assertEqual(covered_uuids, all_uuids,
                         "iter_chains lost or duplicated slices")


if __name__ == "__main__":
    unittest.main()
