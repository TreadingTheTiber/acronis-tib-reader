"""CLI and error-path unit tests.

These exercise:
  * ``tibread.chunkmap_locator.UnsupportedTibFormat`` for the four well-known
    "we definitely can't read this" inputs (truncated, bogus magic, .tibx,
    very-legacy v1+0x1000).
  * The ``tib`` CLI's exit-code contract for ``--version``, ``--help``,
    ``info <missing>`` and ``verify <fake>``.
  * ``tibread`` package-level public re-exports and ``__version__``.
  * Round-trip loading of any ``blocks*.idx`` files that happen to live next
    to the user's repo (skipped if absent so the suite stays portable).

The goal isn't comprehensive coverage of the format -- it's making sure the
"easy to silently break" surfaces (CLI shape, package exports, the four
clean-error gates) regress loudly.

Run directly:
    python tools/tests/test_cli_and_errors.py
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import unittest

# Make `import tibread` work whether or not the package is pip-installed.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread.chunkmap_locator import UnsupportedTibFormat, discover_chunkmap_offset


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_temp(data: bytes) -> str:
    """Write ``data`` to a NamedTemporaryFile in /tmp and return its path.
    Caller is responsible for ``os.unlink``ing it."""
    f = tempfile.NamedTemporaryFile(
        prefix="tibread_test_", suffix=".tib", delete=False, dir="/tmp"
    )
    try:
        f.write(data)
    finally:
        f.close()
    return f.name


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke the CLI as ``python -m tibread.cli ...`` and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "tibread.cli", *args],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=_REPO_ROOT,
    )


# ---------------------------------------------------------------------------
# Format-detection error paths
# ---------------------------------------------------------------------------


class UnsupportedFormatTests(unittest.TestCase):
    """Each of these inputs must raise UnsupportedTibFormat with a clean
    message rather than crashing with a struct.error / IndexError / etc."""

    def setUp(self):
        self._tmp_paths = []

    def tearDown(self):
        for p in self._tmp_paths:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def _make(self, data: bytes) -> str:
        path = _write_temp(data)
        self._tmp_paths.append(path)
        return path

    def test_truncated_file_raises_unsupported_format(self):
        # Just 16 zero bytes -- magic field will read as 0x00000000, which
        # is rejected by the "unknown magic" branch.
        path = self._make(b"\x00" * 16)
        with self.assertRaises(UnsupportedTibFormat) as ctx:
            discover_chunkmap_offset(path)
        self.assertIn("magic", str(ctx.exception).lower())

    def test_bogus_magic_raises_unsupported_format(self):
        # 4 random-ish bytes for the magic, then zero padding.
        path = self._make(b"\xde\xad\xbe\xef" + b"\x00" * 124)
        with self.assertRaises(UnsupportedTibFormat) as ctx:
            discover_chunkmap_offset(path)
        # Should mention the unrecognised magic, not a stack trace.
        self.assertIn("magic", str(ctx.exception).lower())

    def test_tibx_format_raises_unsupported_format(self):
        # .tibx signature: 7 zero bytes, then ASCII "QARCH" at offset 7.
        path = self._make(b"\x00" * 7 + b"QARCH" + b"\x00" * 256)
        with self.assertRaises(UnsupportedTibFormat) as ctx:
            discover_chunkmap_offset(path)
        msg = str(ctx.exception)
        self.assertIn(".tibx", msg)

    def test_very_legacy_v1_4k_sector_raises_unsupported_format(self):
        # Sector magic + version=1 + sector_size at +0x1C == 0x1000.
        # That combo is the TI 2010-2013 "very-legacy" variant, which
        # Acronis itself only reads by destructively migrating the file.
        buf = bytearray(64)
        struct.pack_into("<IHH", buf, 0, 0xA2B924CE, 32, 1)  # magic, hdrlen, version
        struct.pack_into("<I", buf, 0x1C, 0x1000)            # sector_size
        path = self._make(bytes(buf))
        with self.assertRaises(UnsupportedTibFormat) as ctx:
            discover_chunkmap_offset(path)
        self.assertIn("very-legacy", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# CLI exit-code contract
# ---------------------------------------------------------------------------


class CliExitCodeTests(unittest.TestCase):
    """The CLI's exit code is part of its contract for shell scripting."""

    def test_version_flag_exits_zero(self):
        result = _run_cli("--version")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # argparse prints `--version` output to stdout.
        self.assertIn("tibread 0.2.0", result.stdout)

    def test_help_flag_exits_zero(self):
        result = _run_cli("--help")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # Help mentions at least one of the subcommands.
        self.assertTrue(
            any(sub in result.stdout for sub in ("info", "verify", "ls", "extract")),
            msg=f"unexpected --help output: {result.stdout[:200]!r}",
        )

    def test_info_missing_file_exits_nonzero(self):
        # Use a path that definitely doesn't exist.
        result = _run_cli("info", "/tmp/tibread_does_not_exist_xyz.tib")
        self.assertNotEqual(result.returncode, 0)

    def test_verify_fake_file_exits_nonzero(self):
        # A file that exists but isn't a real .tib (random bytes) should
        # be rejected by `verify`'s header check, not crash silently.
        with tempfile.NamedTemporaryFile(
            prefix="tibread_test_fake_", suffix=".tib", delete=False, dir="/tmp"
        ) as f:
            f.write(os.urandom(256))
            fake_path = f.name
        try:
            result = _run_cli("verify", fake_path)
            self.assertNotEqual(
                result.returncode,
                0,
                msg=f"verify should reject random bytes; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )
        finally:
            os.unlink(fake_path)


# ---------------------------------------------------------------------------
# Package-level imports & version
# ---------------------------------------------------------------------------


class PackageImportTests(unittest.TestCase):
    """Top-level re-exports are part of the public API; if they break,
    every downstream `from tibread import ...` line breaks."""

    def test_documented_symbols_import_cleanly(self):
        # Re-import inside the test so a regression at import time fails
        # this test rather than the whole module.
        from tibread import (
            open_tib,
            build_index,
            TibReader,
            NtfsVolume,
            discover_chunkmap_offset,
            decode_chunk_map,
            detect_format_era,
        )
        for sym in (
            open_tib,
            build_index,
            TibReader,
            NtfsVolume,
            discover_chunkmap_offset,
            decode_chunk_map,
            detect_format_era,
        ):
            self.assertTrue(callable(sym), f"{sym!r} should be callable")

    def test_version_string(self):
        import tibread
        self.assertEqual(tibread.__version__, "0.2.0")


# ---------------------------------------------------------------------------
# Optional: index format compatibility with on-disk .idx files
# ---------------------------------------------------------------------------


_BLOCKS_IDX = "/home/colin/tibread/blocks.idx"
_BLOCKS_V10_IDX = "/home/colin/tibread/blocks_v10.idx"


class IndexFormatCompatibilityTests(unittest.TestCase):
    """If the user's local blocks*.idx files are present, sanity-check that
    `TibReader` still parses them. Skipped on portable / CI machines."""

    @unittest.skipIf(not os.path.exists(_BLOCKS_IDX), "blocks.idx not present")
    def test_blocks_idx_loads(self):
        from tibread.reader import TibReader
        # tib_path doesn't have to exist; TibReader only opens it on read.
        r = TibReader("/dev/null", _BLOCKS_IDX, cache_blocks=1)
        self.assertGreater(r.block_count, 0)
        self.assertGreater(r.partition_size, 0)

    @unittest.skipIf(not os.path.exists(_BLOCKS_V10_IDX), "blocks_v10.idx not present")
    def test_blocks_v10_idx_loads(self):
        from tibread.reader import TibReader
        r = TibReader("/dev/null", _BLOCKS_V10_IDX, cache_blocks=1)
        self.assertGreater(r.block_count, 0)
        self.assertGreater(r.partition_size, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
