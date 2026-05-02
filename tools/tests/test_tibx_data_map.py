"""Tests for the .tibx data_map (TLV[1]) extent-index decoder.

The pure-Python tests exercise :func:`decode_key` / :func:`decode_value`
round-trip behaviour and don't need the reference archive.

The fixture-bound tests run against ``example.tibx`` and verify a
handful of empirically-known lookups:

* For volume 10 (the main partition stream) at source byte 0, the
  ``lookup_le`` answer is the MBR-bearing extent in segment 0x58.
* At source byte 0x100000 the answer is the next extent in segment 0x5d.
* For a non-existent volume id, ``lookup_le`` returns ``None``.

These specific seg_ids were verified by the data_map decoder agent
against the archive3.dll Ghidra anchors ``lsm_key2dmap_ext`` (0x1800485d0)
and ``dmap_ext2ondisk`` (0x180048240).  See
``docs/legacy/ARCHIVE3_DATA_MAP.md``.

Skipped when the reference archive is not present on the host.

Run directly::

    python3 tools/tests/test_tibx_data_map.py
"""
from __future__ import annotations

import os
import struct
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import (  # noqa: E402
    DataMapEntry,
    DataMapKey,
    DataMapValue,
    TibxReader,
    decode_key,
    decode_value,
    load_extents,
    lookup_le,
)
from tibread.tibx.data_map import (  # noqa: E402
    DATA_MAP_KEY_FIELD3_DEFAULT,
    DATA_MAP_KEY_SIZE,
    DATA_MAP_VALUE_INDEX_SENTINEL,
    DATA_MAP_VALUE_SIZE,
    encode_key,
)


DEFAULT_FIXTURE = "/path/to/example.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


def _encode_value(value: DataMapValue) -> bytes:
    """Local helper: serialise a DataMapValue back to its 10-byte form.

    Mirrors ``dmap_ext_info2ondisk`` in archive3.dll.  Kept here (rather
    than in the module) because the production code path only needs to
    *read* values; this exists purely to assert decode/encode symmetry.
    """
    return struct.pack(">Q", value.segment_id) + struct.pack(
        ">H", value.extent_index
    )


class DecodeKeyRoundTripTests(unittest.TestCase):
    """Pure-Python tests: encode/decode symmetry for keys."""

    def test_decode_then_encode_is_identity(self) -> None:
        # Hand-crafted 31 raw bytes covering every field.
        raw = (
            (0x000000000000000A).to_bytes(8, "big")  # volume_id = 10
            + (0x0000000000000000).to_bytes(8, "big")  # source_offset = 0
            + (0x100000).to_bytes(3, "big")          # extent_length = 1 MiB
            + (0x00000002).to_bytes(4, "big")         # field3 = 2
            + (0x00000000DEADBEEF).to_bytes(8, "big")  # extent_id
        )
        self.assertEqual(len(raw), DATA_MAP_KEY_SIZE)
        key = decode_key(raw)
        self.assertEqual(key.volume_id, 10)
        self.assertEqual(key.source_offset, 0)
        self.assertEqual(key.extent_length, 0x100000)
        self.assertEqual(key.field3, DATA_MAP_KEY_FIELD3_DEFAULT)
        self.assertEqual(key.extent_id, 0xDEADBEEF)
        # encode_key should reproduce the exact input bytes.
        self.assertEqual(encode_key(key), raw)

    def test_encode_then_decode_is_identity(self) -> None:
        original = DataMapKey(
            volume_id=12,
            source_offset=0xAB_CDEF_0011_2233,
            extent_length=0xFFFFFE,
            field3=DATA_MAP_KEY_FIELD3_DEFAULT,
            extent_id=0x0123_4567_89AB_CDEF,
        )
        round_tripped = decode_key(encode_key(original))
        self.assertEqual(round_tripped, original)

    def test_wrong_size_raises(self) -> None:
        with self.assertRaises(ValueError):
            decode_key(b"\x00" * 30)
        with self.assertRaises(ValueError):
            decode_key(b"\x00" * 32)


class DecodeValueRoundTripTests(unittest.TestCase):
    """Pure-Python tests: encode/decode symmetry for values."""

    def test_decode_then_encode_is_identity(self) -> None:
        raw = (
            (0x0000000000000058).to_bytes(8, "big")  # segment_id = 0x58
            + (0xFFFF).to_bytes(2, "big")            # extent_index sentinel
        )
        self.assertEqual(len(raw), DATA_MAP_VALUE_SIZE)
        value = decode_value(raw)
        self.assertEqual(value.segment_id, 0x58)
        self.assertEqual(value.extent_index, DATA_MAP_VALUE_INDEX_SENTINEL)
        self.assertEqual(_encode_value(value), raw)

    def test_encode_then_decode_is_identity(self) -> None:
        original = DataMapValue(segment_id=0x12345678ABCDEF01, extent_index=7)
        round_tripped = decode_value(_encode_value(original))
        self.assertEqual(round_tripped, original)

    def test_wrong_size_raises(self) -> None:
        with self.assertRaises(ValueError):
            decode_value(b"\x00" * 9)
        with self.assertRaises(ValueError):
            decode_value(b"\x00" * 11)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxDataMapFixtureTests(unittest.TestCase):
    """Integration tests against the reference ``example.tibx``.

    Ground truth (verified by the data_map decoder agent):
    * The data_map tree contains many extents covering volume 10.
    * lookup_le(volume_id=10, source_byte=0)         -> seg_id 0x58 (MBR).
    * lookup_le(volume_id=10, source_byte=0x100000)  -> seg_id 0x5d.
    * lookup_le(volume_id=99, source_byte=0)         -> None.
    """

    @classmethod
    def setUpClass(cls) -> None:
        with TibxReader(FIXTURE) as r:
            cls.entries = load_extents(r)

    def test_load_extents_returns_at_least_one_entry(self) -> None:
        self.assertGreater(len(self.entries), 0)
        for e in self.entries:
            self.assertIsInstance(e, DataMapEntry)

    def test_extents_are_sorted_by_volume_then_offset(self) -> None:
        keys = [(e.key.volume_id, e.key.source_offset) for e in self.entries]
        self.assertEqual(keys, sorted(keys),
                         "load_extents must return entries sorted")

    def test_lookup_volume_10_byte_zero_is_mbr_segment_0x58(self) -> None:
        hit = lookup_le(self.entries, volume_id=10, byte_offset=0)
        self.assertIsNotNone(hit, "expected MBR extent at volume 10 / byte 0")
        self.assertEqual(hit.key.volume_id, 10)
        self.assertEqual(hit.key.source_offset, 0)
        self.assertEqual(
            hit.value.segment_id, 0x58,
            f"MBR extent should be in segment 0x58, got "
            f"0x{hit.value.segment_id:x}",
        )

    def test_lookup_volume_10_byte_1mib_is_segment_0x5d(self) -> None:
        hit = lookup_le(self.entries, volume_id=10, byte_offset=0x100000)
        self.assertIsNotNone(hit, "expected an extent at volume 10 / 1 MiB")
        self.assertEqual(hit.key.volume_id, 10)
        self.assertEqual(
            hit.value.segment_id, 0x5D,
            f"extent at 1 MiB should be in segment 0x5d, got "
            f"0x{hit.value.segment_id:x}",
        )

    def test_lookup_nonexistent_volume_returns_none(self) -> None:
        # volume_id 99 doesn't exist in the fixture; lookup_le must
        # refuse to "fall through" to a different volume.
        hit = lookup_le(self.entries, volume_id=99, byte_offset=0)
        self.assertIsNone(hit)


if __name__ == "__main__":
    unittest.main()
