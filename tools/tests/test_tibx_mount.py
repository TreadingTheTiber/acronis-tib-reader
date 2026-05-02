"""Tests for the unified ``tib mount`` routing (.tib + .tibx).

Covers two pieces:

* :func:`tibread.mount.fuse.is_tibx_file` — the dispatch predicate that
  picks between the legacy ``open_tib`` path and the new
  ``TibxDiskAdapter`` path.  Tested both by extension and by the
  ``QARCH`` magic header sniff (so a ``.tibx`` archive renamed to
  something else still routes correctly).

* The ``--partition`` CLI flag — exercises ``tibread.cli.main``'s
  argparse wiring without actually invoking FUSE (we monkey-patch
  ``fuse_mount`` to capture its arguments).

Live FUSE behaviour is not exercised here — that requires libfuse2
loaded into the runtime, which isn't a hard test dependency.  See
``tools/tests/test_tibx_adapter.py`` for the disk-adapter end-to-end
checks against the reference fixture.

Run directly::

    python3 tools/tests/test_tibx_mount.py
"""
from __future__ import annotations

import io
import os
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tibread import cli  # noqa: E402
from tibread.mount import fuse as mount_fuse  # noqa: E402


DEFAULT_FIXTURE = "/path/to/example.tibx"
FIXTURE = os.environ.get("TIBREAD_TIBX_FIXTURE", DEFAULT_FIXTURE)


class IsTibxFileTests(unittest.TestCase):
    """Verify the ``.tibx`` detection predicate."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-mount-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ---- extension-based detection ------------------------------------

    def test_extension_lower_tibx(self) -> None:
        # File doesn't have to exist for an extension-only test, but we
        # touch it so the function never short-circuits on OSError.
        path = os.path.join(self.tmpdir, "backup.tibx")
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        self.assertTrue(mount_fuse.is_tibx_file(path))

    def test_extension_upper_TIBX(self) -> None:
        path = os.path.join(self.tmpdir, "BACKUP.TIBX")
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        self.assertTrue(mount_fuse.is_tibx_file(path))

    def test_extension_tib_is_not_tibx(self) -> None:
        path = os.path.join(self.tmpdir, "backup.tib")
        # Real .tib magic isn't QARCH (it's "BBBB" / 0x4242 4242).
        with open(path, "wb") as f:
            f.write(b"BBBB" + b"\x00" * 12)
        self.assertFalse(mount_fuse.is_tibx_file(path))

    # ---- magic-byte detection -----------------------------------------

    def test_magic_in_renamed_file(self) -> None:
        """A ``.tibx`` renamed to ``.bin`` is still detected by magic."""
        # Page-0 envelope: 0x41 <type=01 ARCH> 0x00 0x00 [4-byte CRC]
        # then ASCII "ARCH" at offset 8.
        path = os.path.join(self.tmpdir, "renamed.bin")
        with open(path, "wb") as f:
            f.write(b"\x41\x01\x00\x00" + b"\xde\xad\xbe\xef" + b"ARCH")
        self.assertTrue(mount_fuse.is_tibx_file(path))

    def test_no_magic_no_tibx_extension(self) -> None:
        path = os.path.join(self.tmpdir, "random.bin")
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        self.assertFalse(mount_fuse.is_tibx_file(path))

    def test_missing_file_returns_false(self) -> None:
        """A non-existent path with a non-.tibx extension is not a .tibx."""
        path = os.path.join(self.tmpdir, "nope.bin")
        self.assertFalse(mount_fuse.is_tibx_file(path))

    def test_missing_file_with_tibx_extension_still_true(self) -> None:
        """Extension wins even if the file doesn't exist (we'd error
        later in the open path with a clearer message)."""
        path = os.path.join(self.tmpdir, "nope.tibx")
        self.assertTrue(mount_fuse.is_tibx_file(path))

    @unittest.skipUnless(
        os.path.exists(FIXTURE),
        f"reference archive not available at {FIXTURE}",
    )
    def test_real_tibx_fixture(self) -> None:
        self.assertTrue(mount_fuse.is_tibx_file(FIXTURE))


class CliPartitionFlagTests(unittest.TestCase):
    """Verify ``tib mount --partition N`` is parsed and forwarded."""

    def _run_with_captured_fuse_mount(self, argv):
        """Invoke ``cli.main(argv)`` with ``fuse_mount`` mocked.

        Returns the kwargs the CLI dispatched to ``fuse_mount``.
        """
        captured: dict = {}

        def fake_fuse_mount(tib_path, mountpoint, *, foreground=False,
                            cache_blocks=128, partition=1):
            captured["tib_path"] = tib_path
            captured["mountpoint"] = mountpoint
            captured["foreground"] = foreground
            captured["cache_blocks"] = cache_blocks
            captured["partition"] = partition
            return 0

        with mock.patch("tibread.mount.fuse.fuse_mount", new=fake_fuse_mount):
            rc = cli.main(argv)
        return rc, captured

    def test_default_partition_is_1(self) -> None:
        rc, captured = self._run_with_captured_fuse_mount(
            ["mount", "/some/file.tibx", "/mnt/x"]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(captured["partition"], 1)
        self.assertEqual(captured["tib_path"], "/some/file.tibx")
        self.assertEqual(captured["mountpoint"], "/mnt/x")
        self.assertFalse(captured["foreground"])

    def test_explicit_partition_0(self) -> None:
        rc, captured = self._run_with_captured_fuse_mount(
            ["mount", "/some/file.tibx", "/mnt/x", "--partition", "0"]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(captured["partition"], 0)

    def test_explicit_partition_2(self) -> None:
        rc, captured = self._run_with_captured_fuse_mount(
            ["mount", "/some/file.tibx", "/mnt/x", "--partition", "2"]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(captured["partition"], 2)

    def test_foreground_flag_forwarded(self) -> None:
        rc, captured = self._run_with_captured_fuse_mount(
            ["mount", "/some/file.tib", "/mnt/x", "-f"]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(captured["foreground"])

    def test_partition_requires_int(self) -> None:
        # argparse exits with SystemExit(2) on a type error.
        with mock.patch("tibread.mount.fuse.fuse_mount", new=lambda *a, **k: 0):
            with self.assertRaises(SystemExit):
                cli.main(["mount", "/x.tibx", "/mnt/x", "--partition", "abc"])


class FuseMountRoutingTests(unittest.TestCase):
    """Verify ``fuse_mount`` dispatches based on file type.

    We patch out the actual ``FUSE()`` call and the heavy openers so
    only the routing logic runs.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="tibread-mount-route-")
        self.mountpoint = os.path.join(self.tmpdir, "mnt")
        os.makedirs(self.mountpoint, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tib_file_routes_to_open_tib(self) -> None:
        tib_path = os.path.join(self.tmpdir, "backup.tib")
        with open(tib_path, "wb") as f:
            # Plausibly-shaped .tib header (not QARCH).
            f.write(b"BBBB" + b"\x00" * 32)

        fake_vol = mock.MagicMock()
        fake_vol.total_files = 42
        fake_vol.disk.partition_size = 1 << 30

        with mock.patch("tibread.mount.fuse.open_tib",
                        return_value=fake_vol) as p_open, \
             mock.patch("tibread.mount.fuse.FUSE",
                        new=mock.MagicMock()):
            rc = mount_fuse.fuse_mount(tib_path, self.mountpoint,
                                       foreground=False, partition=1)
        self.assertEqual(rc, 0)
        p_open.assert_called_once()
        # The first positional arg to open_tib was the .tib path.
        self.assertEqual(p_open.call_args.args[0], tib_path)

    def test_tibx_file_routes_to_tibx_adapter(self) -> None:
        tibx_path = os.path.join(self.tmpdir, "backup.tibx")
        with open(tibx_path, "wb") as f:
            f.write(b"\x41\x01\x00\x00" + b"\xde\xad\xbe\xef" + b"ARCH")

        fake_vol = mock.MagicMock()
        fake_vol.total_files = 7
        fake_vol.disk.partition_size = 1 << 30
        fake_adapter = mock.MagicMock()

        with mock.patch(
            "tibread.mount.fuse._open_tibx_volume",
            return_value=(fake_vol, fake_adapter),
        ) as p_open, mock.patch(
            "tibread.mount.fuse.FUSE", new=mock.MagicMock()
        ):
            rc = mount_fuse.fuse_mount(
                tibx_path, self.mountpoint, foreground=False, partition=2
            )
        self.assertEqual(rc, 0)
        p_open.assert_called_once_with(tibx_path, 2)
        # Adapter must be closed when FUSE returns.
        fake_adapter.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
