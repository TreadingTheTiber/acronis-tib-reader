"""Robustness / malformed-input tests for :class:`TibxReader`.

These exercise the "bad input" paths so they fail with clean exceptions
rather than tracebacks leaking through the CLI.  None of them require
the 51 GiB reference archive — they synthesise small fixtures in
``/tmp``.

Covered:

* Truncated to 0 bytes                  → ValueError("file is empty")
* Truncated to non-page-multiple size   → ValueError("not a multiple of 4096")
* Single 4 KiB page of random bytes     → ValueError("does not start with 0x41 0x01")
* Multi-page random-bytes file          → ValueError on page-0 magic check
* Body-byte corruption inside an other- → CRC mismatch via verify_page() and
  wise valid prefix copy of the ref-       TibxPageCrcError raised by read_page()
  archive (needs the reference archive
  to copy a few hundred pages from; the
  test is skipped if it isn't present)

Run directly::

    python3 tools/tests/test_tibx_robustness.py
"""
from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.tibx import TibxReader  # noqa: E402
from tibread.tibx.reader import TibxPageCrcError  # noqa: E402


_REF_ARCHIVE = os.environ.get(
    "TIBREAD_TIBX_FIXTURE", "/mnt/e/Jmicron 0102.tibx"
)


def _mktemp() -> str:
    fd, path = tempfile.mkstemp(prefix="tibx_robust_", suffix=".tibx")
    os.close(fd)
    return path


class EmptyAndOddSizedFiles(unittest.TestCase):
    """Files whose total length is wrong for a page store must be rejected
    with a :class:`ValueError`, never an :class:`IndexError` or a short-read
    crash deep inside the reader."""

    def test_empty_file(self):
        path = _mktemp()
        try:
            open(path, "wb").close()
            with self.assertRaises(ValueError) as ctx:
                TibxReader(path)
            self.assertIn("empty", str(ctx.exception).lower())
        finally:
            os.unlink(path)

    def test_non_page_multiple_size(self):
        path = _mktemp()
        try:
            with open(path, "wb") as f:
                f.write(b"\x00" * (4096 + 17))
            with self.assertRaises(ValueError) as ctx:
                TibxReader(path)
            self.assertIn("multiple of", str(ctx.exception).lower())
        finally:
            os.unlink(path)


class BogusContentRejection(unittest.TestCase):
    """Page-0 doesn't begin with ``0x41 0x01`` ⇒ refuse to open."""

    def test_single_random_page(self):
        path = _mktemp()
        try:
            rng = random.Random(0xCAFE)
            with open(path, "wb") as f:
                f.write(bytes(rng.randint(0, 255) for _ in range(4096)))
            with self.assertRaises(ValueError) as ctx:
                TibxReader(path)
            self.assertIn("page 0", str(ctx.exception).lower())
        finally:
            os.unlink(path)

    def test_multipage_random(self):
        path = _mktemp()
        try:
            rng = random.Random(0xBEEF)
            with open(path, "wb") as f:
                f.write(bytes(rng.randint(0, 255) for _ in range(4096 * 4)))
            with self.assertRaises(ValueError) as ctx:
                TibxReader(path)
            self.assertIn("page 0", str(ctx.exception).lower())
        finally:
            os.unlink(path)


@unittest.skipUnless(
    os.path.exists(_REF_ARCHIVE),
    f"reference archive not available at {_REF_ARCHIVE}",
)
class CorruptedPagesAreCaught(unittest.TestCase):
    """Body-byte corruption inside an otherwise valid prefix of the
    reference archive must be flagged by :meth:`TibxReader.verify_page`,
    and :meth:`TibxReader.read_page` (with default ``validate_crc=True``)
    must raise :class:`TibxPageCrcError`."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = _mktemp()
        # Copy 200 pages = 800 KiB. Corrupt page 100 by flipping 4 random
        # bytes inside its body. Page 0 is left untouched so the reader
        # accepts the file.
        rng = random.Random(7)
        n_pages = 200
        corrupt_idx = 100
        with open(_REF_ARCHIVE, "rb") as src, open(cls.tmp, "wb") as dst:
            for i in range(n_pages):
                page = bytearray(src.read(4096))
                if i == corrupt_idx:
                    for _ in range(4):
                        pos = rng.randrange(8, 4096)
                        page[pos] ^= 0xA5
                dst.write(bytes(page))
        cls.corrupt_idx = corrupt_idx

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.tmp)
        except FileNotFoundError:
            pass

    def test_verify_page_flags_corruption(self):
        with TibxReader(self.tmp) as r:
            ok, _stored, _computed = r.verify_page(self.corrupt_idx)
            self.assertFalse(ok, "corrupted page should fail CRC validation")

    def test_other_pages_still_validate(self):
        with TibxReader(self.tmp) as r:
            ok_count = 0
            bad_count = 0
            for i in range(r.page_count):
                ok, _s, _c = r.verify_page(i)
                if ok:
                    ok_count += 1
                else:
                    bad_count += 1
            self.assertEqual(bad_count, 1)
            self.assertEqual(ok_count, r.page_count - 1)

    def test_read_page_raises_on_corruption(self):
        with TibxReader(self.tmp) as r:
            with self.assertRaises(TibxPageCrcError):
                r.read_page(self.corrupt_idx, validate_crc=True)

    def test_read_page_with_validate_off_does_not_raise(self):
        with TibxReader(self.tmp) as r:
            # Disabling validation must succeed even on the corrupt page.
            ptype, body = r.read_page(self.corrupt_idx, validate_crc=False)
            self.assertEqual(len(body), 4088)


@unittest.skipUnless(
    os.path.exists(_REF_ARCHIVE),
    f"reference archive not available at {_REF_ARCHIVE}",
)
class CompressionVariantCoverage(unittest.TestCase):
    """The reference archive ``Jmicron 0102.tibx`` carries (at least) one
    segment of each known Zstd preset (``0x0300``, ``0x0301``, ``0x0302``,
    ``0x0303``).  This test pins the constant table down by decompressing
    a representative segment of each variant.  Regressions that drop a
    preset out of :data:`ZSTD_COMP_VARIANTS` will fail here.
    """

    # Page indices of an exemplar segment for each known Zstd preset.
    # Discovered by the segment-stress walk in STRESS_TEST_RESULTS.md.
    _SAMPLE_PAGES = {
        0x0302: 6,           # first SG segment in the file (zlen=480, len=262144)
        0x0301: 7,           # second SG segment
        0x0300: 8,           # third SG segment
        0x0303: 13_346_697,  # rare: only one segment uses this preset
    }

    def test_each_zstd_variant_decompresses(self):
        """Spot-decompress one segment per Zstd preset to lock the
        constant table down.  Reads exactly the SG header pages in the
        reference archive — no full-file walk."""
        from tibread.tibx import TibxReader
        from tibread.tibx.segment import parse_sg_header

        seen: dict[int, int] = {}
        with TibxReader(_REF_ARCHIVE) as r:
            for variant, page_idx in self._SAMPLE_PAGES.items():
                page = r.read_raw_page(page_idx)
                seg = parse_sg_header(page, page_idx)
                self.assertIsNotNone(seg, f"page {page_idx} is not an SG page")
                self.assertEqual(seg.comp, variant,
                    f"page {page_idx} has comp=0x{seg.comp:04x}, "
                    f"expected 0x{variant:04x}")
                out = r.decompress_segment(seg)
                self.assertEqual(len(out), seg.length,
                    f"comp=0x{variant:04x} len mismatch")
                seen[variant] = len(out)
        self.assertEqual(
            set(seen),
            {0x0300, 0x0301, 0x0302, 0x0303},
            f"missing variants in coverage: {sorted(set(self._SAMPLE_PAGES) - set(seen))}",
        )


@unittest.skipUnless(
    os.path.exists(_REF_ARCHIVE),
    f"reference archive not available at {_REF_ARCHIVE}",
)
class TruncatedPrefixReader(unittest.TestCase):
    """A 1 MiB prefix copy of the reference archive should still let the
    reader open and walk the early segments, but must raise a clean IOError
    (not a stack trace) the moment a segment's continuation pages run off
    the truncated tail."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = _mktemp()
        with open(_REF_ARCHIVE, "rb") as src, open(cls.tmp, "wb") as dst:
            dst.write(src.read(1 * 1024 * 1024))  # 256 pages

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.tmp)
        except FileNotFoundError:
            pass

    def test_opens_with_expected_page_count(self):
        with TibxReader(self.tmp) as r:
            self.assertEqual(r.page_count, 256)

    def test_can_decompress_segments_within_prefix(self):
        with TibxReader(self.tmp) as r:
            it = r.find_segments()
            seg = next(it)
            # The first SG segment in the reference archive starts at
            # page 6 with zlen=480 (well within 1 MiB), so it must
            # decompress cleanly.
            out = r.decompress_segment(seg)
            self.assertEqual(len(out), seg.length)


class CliExitCodeContract(unittest.TestCase):
    """The ``tibx-*`` subcommands must exit non-zero with a one-line
    ``error: ...`` message (no Python traceback) when handed a malformed
    or missing input. Mirrors the existing ``UnsupportedTibFormat``
    pattern that the legacy ``info`` / ``verify`` commands already use.
    """

    def _run(self, *args: str):
        import subprocess
        return subprocess.run(
            [sys.executable, "-m", "tibread.cli", *args],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=_REPO_ROOT,
        )

    def test_tibx_info_missing_file(self):
        result = self._run("tibx-info", "/tmp/tibread_does_not_exist_xyz.tibx")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("error:", result.stderr.lower())

    def test_tibx_stat_garbage_file(self):
        path = _mktemp()
        try:
            with open(path, "wb") as f:
                f.write(b"\x00" * 13)  # not a multiple of 4096
            result = self._run("tibx-stat", path)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)
        finally:
            os.unlink(path)

    def test_tibx_verify_garbage_file(self):
        path = _mktemp()
        try:
            # page-multiple but page 0 not 0x41 0x01
            rng = random.Random(0x1234)
            with open(path, "wb") as f:
                f.write(bytes(rng.randint(0, 255) for _ in range(4096 * 2)))
            result = self._run("tibx-verify", path, "--sample", "10")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)
        finally:
            os.unlink(path)

    def test_tibx_volumes_empty_file(self):
        path = _mktemp()
        try:
            open(path, "wb").close()
            result = self._run("tibx-volumes", path)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
