"""Integration tests for :mod:`tibread.tibx.disk_image`.

Verifies that :meth:`TibxReader.read_lba_range` correctly returns the
MBR signature from the source disk in the reference archive
``example.tibx``.

These tests are skipped when the reference archive isn't available on
the host (CI runners, non-developer checkouts, etc.).

Run directly::

    python3 tools/tests/test_tibx_disk_image.py
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
    TibxReader,
)


# Reference archive path.  Override with TIBREAD_TIBX_FIXTURE if needed
# (e.g. for CI machines that mount the file at a different path).
DEFAULT_FIXTURE = "/path/to/example.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


@unittest.skipUnless(
    os.path.exists(FIXTURE),
    f"reference archive not available at {FIXTURE}",
)
class TibxReadLbaRangeTests(unittest.TestCase):
    """Exercise the bootstrap-only read_lba_range path."""

    def test_mbr_signature(self) -> None:
        """The first 512 bytes of LBA 0 must end with the 0x55AA MBR mark."""
        with TibxReader(FIXTURE) as r:
            mbr = r.read_lba_range(0, 512)
        self.assertEqual(len(mbr), 512)
        self.assertEqual(
            mbr[510:512],
            b"\x55\xaa",
            f"MBR signature missing; got {mbr[510:512]!r}",
        )

    def test_first_16k_starts_with_mbr_boot_code(self) -> None:
        """A 16 KiB read starting at LBA 0 begins with the MBR boot code."""
        with TibxReader(FIXTURE) as r:
            buf = r.read_lba_range(0, 16384)
        self.assertEqual(len(buf), 16384)
        # The first byte of the MS-MBR boot code in this archive is 0x33.
        self.assertEqual(buf[0], 0x33)
        # Re-confirm the partition-table signature is still in the MBR.
        self.assertEqual(buf[510:512], b"\x55\xaa")

    def test_offset_read_inside_bootstrap(self) -> None:
        """A read at a non-zero LBA inside the bootstrap region works."""
        # LBA 1 = byte 512..1024.
        with TibxReader(FIXTURE) as r:
            sec1 = r.read_lba_range(1, 512)
        self.assertEqual(len(sec1), 512)
        # LBAs 1..2047 are typically all-zero filler before the first
        # partition; assert that at least the read succeeded with the
        # right length.

    def test_bootstrap_boundary_just_fits(self) -> None:
        """Reading exactly up to BOOTSTRAP_LEN must succeed."""
        with TibxReader(FIXTURE) as r:
            buf = r.read_lba_range(0, BOOTSTRAP_LEN)
        self.assertEqual(len(buf), BOOTSTRAP_LEN)
        self.assertEqual(buf[510:512], b"\x55\xaa")

    def test_past_bootstrap_raises(self) -> None:
        """Reading beyond the bootstrap segment raises until LSM walker lands."""
        with TibxReader(FIXTURE) as r:
            with self.assertRaises(ChunkMapNotImplemented):
                r.read_lba_range(0, BOOTSTRAP_LEN + 1)

    def test_invalid_args(self) -> None:
        with TibxReader(FIXTURE) as r:
            with self.assertRaises(ValueError):
                r.read_lba_range(-1, 512)
            with self.assertRaises(ValueError):
                r.read_lba_range(0, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
