"""Integration tests for :class:`tibread.tibx.TibxDiskAdapter`.

Verifies that the adapter's surface area (``read``, ``partition_size``,
``block_count``) is wired correctly to :class:`TibxReader` and that the
known-failure path (reads past the bootstrap segment) raises a clear
:class:`ChunkMapNotImplemented`.

These tests are skipped when the reference archive isn't available on
the host (CI runners, non-developer checkouts, etc.).

Run directly::

    python3 tools/tests/test_tibx_adapter.py
"""
from __future__ import annotations

import os
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import (  # noqa: E402
    BOOTSTRAP_LEN,
    ChunkMapNotImplemented,
    TibxDiskAdapter,
)


# Reference archive path.  Override with TIBREAD_TIBX_FIXTURE if needed.
DEFAULT_FIXTURE = "/mnt/e/Jmicron 0102.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxDiskAdapterTests(unittest.TestCase):
    """Exercise the bootstrap-only adapter surface."""

    def test_read_mbr(self) -> None:
        """``read(0, 512)`` returns a valid MBR (0x55AA at offset 510)."""
        with TibxDiskAdapter(FIXTURE) as a:
            mbr = a.read(0, 512)
        self.assertEqual(len(mbr), 512)
        self.assertEqual(
            mbr[510:512],
            b"\x55\xaa",
            f"MBR signature missing; got {mbr[510:512]!r}",
        )

    def test_read_unaligned_inside_bootstrap(self) -> None:
        """Byte-unaligned reads inside the bootstrap region work."""
        with TibxDiskAdapter(FIXTURE) as a:
            # Read 32 bytes starting at offset 510 — straddles the MBR sig.
            buf = a.read(510, 32)
        self.assertEqual(len(buf), 32)
        # Bytes [0:2] of buf must be the MBR signature 0x55AA.
        self.assertEqual(buf[:2], b"\x55\xaa")

    def test_read_past_bootstrap_raises(self) -> None:
        """Reads at or past ``BOOTSTRAP_LEN`` raise ``ChunkMapNotImplemented``."""
        with TibxDiskAdapter(FIXTURE) as a:
            with self.assertRaises(ChunkMapNotImplemented):
                a.read(BOOTSTRAP_LEN, 1)

    def test_read_straddling_bootstrap_raises(self) -> None:
        """Reads that cross the bootstrap boundary also raise."""
        with TibxDiskAdapter(FIXTURE) as a:
            with self.assertRaises(ChunkMapNotImplemented):
                a.read(BOOTSTRAP_LEN - 100, 200)

    def test_read_invalid_args(self) -> None:
        with TibxDiskAdapter(FIXTURE) as a:
            with self.assertRaises(ValueError):
                a.read(-1, 512)
            with self.assertRaises(ValueError):
                a.read(0, 0)

    def test_partition_size_reports_disk_size(self) -> None:
        """``partition_size`` is non-trivial and at least the bootstrap span."""
        with TibxDiskAdapter(FIXTURE) as a:
            size = a.partition_size
        # The reference archive is a ~167 GiB JMicron disk; we only
        # assert that the reported size is plausibly disk-scale.
        self.assertGreater(size, BOOTSTRAP_LEN)
        self.assertGreater(size, 1 << 30)  # > 1 GiB

    def test_block_count_matches_partition_size(self) -> None:
        with TibxDiskAdapter(FIXTURE) as a:
            self.assertEqual(a.block_count, a.partition_size // 4096)

    def test_list_mbr_partitions(self) -> None:
        with TibxDiskAdapter(FIXTURE) as a:
            parts = a.list_mbr_partitions()
        # The reference disk has two NTFS primary partitions.
        self.assertGreaterEqual(len(parts), 1)
        for p in parts:
            self.assertIn("type", p)
            self.assertIn("first_lba", p)
            self.assertIn("byte_offset", p)
            self.assertIn("byte_size", p)
            self.assertGreater(p["byte_size"], 0)

    def test_partition_offset_view_translates(self) -> None:
        """Adapter with ``partition_offset`` resolves to a real partition.

        Uses the first MBR partition's byte offset so the adapter can
        auto-discover its data_map volume_id.  The BPB at offset 0 of
        the partition view must start with the NTFS magic
        ``EB 52 90 'NTFS    '``.
        """
        with TibxDiskAdapter(FIXTURE) as a:
            parts = a.list_mbr_partitions()
        if not parts:
            self.skipTest("no MBR partitions to probe")
        p0 = parts[0]
        with TibxDiskAdapter(FIXTURE, partition_offset=p0["byte_offset"]) as pa:
            bpb = pa.read(0, 512)
        self.assertEqual(bpb[:3], b"\xeb\x52\x90")
        self.assertEqual(bpb[3:11], b"NTFS    ")
        self.assertEqual(bpb[510:512], b"\x55\xaa")

    def test_ntfs_volume_instantiation_fails_cleanly(self) -> None:
        """``NtfsVolume`` against the whole-disk adapter fails predictably.

        The MBR isn't an NTFS BPB, so either:
        * the BPB parse raises ``ValueError`` ("not NTFS") on garbage
          OEM bytes, or
        * the BPB parse passes but produces a wild ``mft_lcn`` whose
          read overflows past the bootstrap and raises
          ``ChunkMapNotImplemented``.

        Either is acceptable here — the test exists to confirm the
        adapter's :meth:`read` actually drives ``NtfsVolume`` end-to-end
        without unexpected exceptions (TypeError, AttributeError, etc.).
        """
        from tibread.ntfs import NtfsVolume

        adapter = TibxDiskAdapter(FIXTURE)
        try:
            with self.assertRaises((ChunkMapNotImplemented, ValueError, IOError)):
                NtfsVolume(adapter, build_index=False)
        finally:
            adapter.close()

    def test_ntfs_bpb_parse_via_partial_volume(self) -> None:
        """``NtfsVolume`` bootstraps end-to-end on partition 0.

        After data_map / segment_map wiring landed, a partition-view
        adapter can satisfy reads beyond the bootstrap region; the BPB
        parser succeeds, the ``$MFT`` LCN is read from the BPB, and
        MFT record 0 is fetched and validated as a ``FILE`` record.
        """
        from tibread.ntfs import NtfsVolume

        with TibxDiskAdapter(FIXTURE) as a:
            parts = a.list_mbr_partitions()
        if not parts:
            self.skipTest("no MBR partitions to probe")
        padapter = TibxDiskAdapter(
            FIXTURE, partition_offset=parts[0]["byte_offset"]
        )
        try:
            vol = NtfsVolume(padapter, build_index=False)
            self.assertEqual(vol.cluster_size, 4096)
            self.assertGreater(vol.mft_lcn, 0)
            mft_rec0 = padapter.read(
                vol.mft_lcn * vol.cluster_size, vol.mft_record_size
            )
            self.assertEqual(mft_rec0[:4], b"FILE")
        finally:
            padapter.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
