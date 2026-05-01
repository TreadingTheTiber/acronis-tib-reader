"""
tibread.tibx.reader — :class:`TibxReader`, the entry point for reading
Acronis archive3 ``.tibx`` page-store files.

The reader exposes only the page-level and segment-level primitives
needed to extract bulk Zstd payloads.  It deliberately does *not* yet
implement the LSM-tree walk or chunk enumeration; those are follow-up
work.  What is implemented here is enough to:

* read any page by index, with envelope and a best-effort checksum field
  exposed to callers,
* iterate every SG segment in the file (or in a page range),
* decompress a segment to its plaintext payload (handling
  multi-page-spanning Zstd frames),
* decode the human-friendly fields out of the page-1 archive metadata
  record (disk GUID, hostname, agent build, install GUID).
"""

from __future__ import annotations

import os
import re
import struct
from typing import Dict, Iterator, List, Optional

from .format import (
    ENVELOPE_SIZE,
    INNER_MAGIC_ARCH,
    INNER_MAGIC_QARCH,
    INNER_MAGIC_SG,
    PAGE_BODY_SIZE,
    PAGE_SIZE,
    PAGE_TYPE_ARCH,
    PAGE_TYPE_DATA,
    SG_HEADER_OFFSET,
    compute_page_crc32,
    crc32c,
    read_stored_page_crc32,
)
from .segment import (
    SgSegment,
    decompress_segment,
    parse_sg_header,
    read_segment_compressed_bytes,
)


# Strings on the metadata page are stored as length-prefixed UTF-8 (or
# C-strings); we extract them with a regex that walks runs of printable
# ASCII at least 6 bytes long.  This is robust to layout variants we
# haven't fully decoded.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")
_GUID_RE = re.compile(
    rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


class TibxPageCrcError(IOError):
    """Raised when a page's stored CRC does not match the computed CRC.

    Carries the page index, the stored CRC, and the (re-)computed CRC so
    callers can decide whether to retry with FEC, log, or surface a
    user-visible corruption error.
    """

    def __init__(self, page_idx: int, stored: int, computed: int) -> None:
        self.page_idx = page_idx
        self.stored = stored
        self.computed = computed
        super().__init__(
            f"page {page_idx}: CRC mismatch "
            f"(stored=0x{stored:08x}, computed=0x{computed:08x})"
        )


def _attempt_single_bit_fec(page: bytes, stored: int) -> Optional[tuple[bytes, str]]:
    """Try to recover ``page`` from a single-bit corruption.

    Returns ``(corrected_page_bytes, description)`` on success, or
    ``None`` if no single-bit flip restores the stored CRC.

    Two cases (matching the C implementation in archive3.dll):
      1. The bit-flip is in the stored CRC field itself — detected by
         testing whether ``stored XOR computed`` has popcount 1.
      2. The bit-flip is somewhere in the 4096-byte page body — brute-
         forced by walking every (byte, bit) position and recomputing
         the page CRC.
    """
    # Case 1: bit flip in the stored CRC.
    buf = bytearray(page)
    buf[4:8] = b"\x00\x00\x00\x00"
    computed = crc32c(bytes(buf))
    diff = computed ^ stored
    if diff != 0 and (diff & (diff - 1)) == 0:
        # Single bit set in the difference => the page payload is fine,
        # only the on-disk CRC field is wrong.  Patch it.
        fixed = bytearray(page)
        fixed[4:8] = computed.to_bytes(4, "big")
        return bytes(fixed), f"bit flip in stored CRC field (diff=0x{diff:08x})"

    # Case 2: bit flip in the body.  Try every byte and every bit.
    # We work on the page with the CRC field already zeroed because
    # ``computed`` was calculated that way.  When we hit a candidate we
    # apply the flip to the *original* page (preserving the stored CRC
    # value as well).
    for byte_idx in range(PAGE_SIZE):
        # Skip the CRC field — case 1 already covered single-bit flips
        # there, and any flip here would also change the post-zero-fill
        # CRC computation, but case 1 has tighter logic.
        if 4 <= byte_idx < 8:
            continue
        original_byte = buf[byte_idx]
        for bit in range(8):
            buf[byte_idx] = original_byte ^ (1 << bit)
            cand = crc32c(bytes(buf))
            if cand == stored:
                # Apply to the real page bytes.
                fixed = bytearray(page)
                fixed[byte_idx] ^= 1 << bit
                desc = (
                    f"single-bit flip at byte 0x{byte_idx:03x} bit {bit} "
                    f"(value {(original_byte >> bit) & 1} -> "
                    f"{((original_byte ^ (1 << bit)) >> bit) & 1})"
                )
                # Restore buf for cleanliness (not strictly needed).
                buf[byte_idx] = original_byte
                return bytes(fixed), desc
        buf[byte_idx] = original_byte

    return None


class TibxReader:
    """Read-only reader for Acronis archive3 ``.tibx`` files.

    Parameters
    ----------
    path : str
        Path to the ``.tibx`` file.

    Notes
    -----
    The reader keeps the underlying file open for its lifetime.  Use it
    as a context manager to ensure the file handle is released::

        with TibxReader(path) as r:
            print(r.read_arch_header())
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "rb", buffering=0)
        self.file_size = os.fstat(self._fh.fileno()).st_size
        if self.file_size % PAGE_SIZE != 0:
            raise ValueError(
                f"{path}: file size {self.file_size} is not a multiple of "
                f"{PAGE_SIZE} (not a valid .tibx page store)"
            )
        self.page_count = self.file_size // PAGE_SIZE
        # Validate that page 0 looks like an ARCH/QARCH page so we fail
        # early on obviously-wrong inputs.
        page0 = self._raw_read_page(0)
        if page0[0] != 0x41 or page0[1] != PAGE_TYPE_ARCH:
            raise ValueError(
                f"{path}: page 0 does not start with the expected "
                f"0x41 0x01 ARCH page magic (got {page0[:4].hex()})"
            )
        if page0[SG_HEADER_OFFSET - 1 : SG_HEADER_OFFSET + 4] != b"Q" + INNER_MAGIC_ARCH:
            # Tolerate plain ARCH on page 0 (some archives may not use the
            # leading Q qualifier), but warn via a soft check.
            pass

    # ------------------------------------------------------------------ #
    # Resource management
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None  # type: ignore[assignment]

    def __enter__(self) -> "TibxReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Page-level primitives
    # ------------------------------------------------------------------ #

    def _raw_read_page(self, page_idx: int) -> bytes:
        if page_idx < 0 or page_idx >= self.page_count:
            raise IndexError(
                f"page index {page_idx} out of range "
                f"(file has {self.page_count} pages)"
            )
        self._fh.seek(page_idx * PAGE_SIZE)
        page = self._fh.read(PAGE_SIZE)
        if len(page) != PAGE_SIZE:
            raise IOError(
                f"short read on page {page_idx}: got {len(page)} bytes"
            )
        return page

    def read_page(
        self,
        page_idx: int,
        *,
        validate_crc: bool = True,
        attempt_fec: bool = False,
    ) -> tuple[int, bytes]:
        """Return ``(page_type, body_bytes)`` for one page.

        ``body_bytes`` is the 4088-byte body following the 8-byte
        envelope.  The CRC is **CRC-32C (Castagnoli)** stored big-endian
        at envelope offset 0x04, computed over the whole 4 KiB page with
        that field zero-filled.

        Parameters
        ----------
        page_idx : int
            Page number to read.
        validate_crc : bool, optional
            If True (default), verify the page's stored CRC matches the
            computed CRC.  Raises :class:`TibxPageCrcError` on mismatch
            unless ``attempt_fec=True`` recovers a single-bit corruption.
        attempt_fec : bool, optional
            If True, on CRC mismatch attempt brute-force single-bit
            recovery (matches the algorithm in ``archive3.dll``).  Only
            consulted when ``validate_crc=True``.  Defaults to False
            (fail fast on corruption).
        """
        page = self._raw_read_page(page_idx)
        if page[0] != 0x41:
            raise IOError(
                f"page {page_idx} does not start with 0x41 magic (got 0x{page[0]:02x})"
            )
        if validate_crc:
            page = self._validate_or_recover_crc(
                page_idx, page, attempt_fec=attempt_fec
            )
        page_type = page[1]
        return page_type, page[ENVELOPE_SIZE:]

    def read_raw_page(
        self,
        page_idx: int,
        *,
        validate_crc: bool = False,
        attempt_fec: bool = False,
    ) -> bytes:
        """Return the full 4096 raw bytes of one page (envelope included).

        Parameters
        ----------
        page_idx : int
            Page number to read.
        validate_crc : bool, optional
            If True, verify the CRC.  Defaults to False because most
            callers of this low-level helper want the raw bytes for
            inspection regardless of whether the page validates.
        attempt_fec : bool, optional
            See :meth:`read_page`.
        """
        page = self._raw_read_page(page_idx)
        if validate_crc:
            page = self._validate_or_recover_crc(
                page_idx, page, attempt_fec=attempt_fec
            )
        return page

    def page_envelope(self, page_idx: int) -> tuple[int, int]:
        """Return ``(page_type, stored_checksum)`` from the envelope.

        ``stored_checksum`` is the page's CRC-32C as stored on disk —
        i.e. the big-endian u32 at envelope offset 0x04, returned as a
        Python int.
        """
        page = self._raw_read_page(page_idx)
        page_type = page[1]
        checksum = read_stored_page_crc32(page)
        return page_type, checksum

    # ------------------------------------------------------------------ #
    # CRC validation / FEC
    # ------------------------------------------------------------------ #

    def _validate_or_recover_crc(
        self,
        page_idx: int,
        page: bytes,
        *,
        attempt_fec: bool,
    ) -> bytes:
        """Validate the CRC; on mismatch optionally attempt single-bit FEC.

        Returns the (possibly corrected) 4 KiB page bytes.  Raises
        :class:`TibxPageCrcError` if the CRC does not match and FEC was
        either disabled or unable to recover.
        """
        stored = read_stored_page_crc32(page)
        computed = compute_page_crc32(page)
        if computed == stored:
            return page
        if attempt_fec:
            recovery = _attempt_single_bit_fec(page, stored)
            if recovery is not None:
                fixed_page, _desc = recovery
                # Cache nothing — just return the corrected bytes so the
                # caller observes a valid page.  We deliberately do not
                # silently rewrite the on-disk file (the reader is
                # read-only).
                return fixed_page
        raise TibxPageCrcError(page_idx, stored, computed)

    def verify_page(self, page_idx: int) -> tuple[bool, int, int]:
        """Return ``(ok, stored_crc, computed_crc)`` for one page.

        Useful for bulk integrity scans where we want a tally rather
        than an exception.  Does *not* attempt FEC.
        """
        page = self._raw_read_page(page_idx)
        stored = read_stored_page_crc32(page)
        computed = compute_page_crc32(page)
        return computed == stored, stored, computed

    # ------------------------------------------------------------------ #
    # Segment iteration / decompression
    # ------------------------------------------------------------------ #

    def find_segments(
        self, page_range: Optional[range] = None
    ) -> Iterator[SgSegment]:
        """Yield every SG segment header in ``page_range``.

        After each segment is yielded, the iterator skips over its
        continuation pages (using ``zlen`` from the parsed header) so
        that segments are reported only once.

        Parameters
        ----------
        page_range : range, optional
            Range of page indices to scan.  Defaults to the entire file.
        """
        if page_range is None:
            page_range = range(self.page_count)

        # Walk pages, but allow jumping forward when an SG segment is
        # found so we don't accidentally re-parse continuation bytes as
        # if they were a new SG record.
        it = iter(page_range)
        try:
            page_idx = next(it)
        except StopIteration:
            return
        last = page_range[-1] if len(page_range) else -1

        while page_idx <= last:
            page = self._raw_read_page(page_idx)
            if (
                page[0] == 0x41
                and page[1] == PAGE_TYPE_DATA
                and page[SG_HEADER_OFFSET : SG_HEADER_OFFSET + 4] == INNER_MAGIC_SG
            ):
                seg = parse_sg_header(page, page_idx)
                if seg is not None:
                    yield seg
                    # Advance past the continuation pages.
                    page_idx += seg.page_span()
                    continue
            page_idx += 1

    def decompress_segment(self, seg: SgSegment) -> bytes:
        """Return the plaintext payload of one segment.

        Spans multiple pages automatically when ``seg.zlen`` exceeds the
        bytes available on the segment's first page.
        """
        return decompress_segment(self._fh, seg, file_size=self.file_size)

    def read_segment_compressed_bytes(self, seg: SgSegment) -> bytes:
        """Return the still-compressed Zstd frame bytes for a segment."""
        return read_segment_compressed_bytes(
            self._fh, seg, file_size=self.file_size
        )

    # ------------------------------------------------------------------ #
    # ARCH header decoding
    # ------------------------------------------------------------------ #

    def read_arch_header(self) -> Dict[str, object]:
        """Decode the human-friendly fields from the archive header.

        Page 0 carries a fixed-format QARCH record (archive UUID,
        creation timestamps, version block) and page 1 carries the
        archive metadata payload (disk GUID, hostname, agent build,
        install GUID).  Both are merged into the returned dict.

        Returns
        -------
        dict
            Keys (presence depends on what the archive actually stored):
            ``archive_uuid`` (hex), ``version`` (tuple),
            ``created_unix_ms`` / ``modified_unix_ms`` (ints),
            ``disk_guid``, ``hostname``, ``agent_build``,
            ``install_guid``, ``strings`` (raw printable runs found on
            page 1 — useful for diagnostics).
        """
        page0 = self._raw_read_page(0)
        # Page 0 layout (offsets are page-relative):
        #   +0x07  "QARCH" (5 bytes)
        #   +0x10  version block? big-endian u32 0x00080200 + u32 0x01010000
        #   +0x18  BE u64 timestamp (created)
        #   +0x20  BE u64 timestamp (modified)
        #   +0x28  16-byte archive UUID / fingerprint
        out: Dict[str, object] = {}
        # The QARCH magic appears at offset 7 on the first archive of
        # the file; later archive pages drop the leading Q.  We accept
        # either form.
        if page0[7:12] == INNER_MAGIC_QARCH:
            magic_end = 12
            out["header_magic"] = "QARCH"
        elif page0[8:12] == INNER_MAGIC_ARCH:
            magic_end = 12
            out["header_magic"] = "ARCH"
        else:
            magic_end = 8
            out["header_magic"] = page0[8:12].decode("latin1", "replace")

        # Best-effort field decode.  These offsets are observed
        # empirically from the test archive; alternate archives may
        # vary in field placement, so we wrap in try/except and only
        # populate what looks plausible.
        try:
            ver_block = page0[0x10:0x18]
            out["version"] = (
                int.from_bytes(ver_block[:4], "big"),
                int.from_bytes(ver_block[4:8], "big"),
            )
        except Exception:
            pass
        try:
            ts1 = struct.unpack(">Q", page0[0x18:0x20])[0]
            ts2 = struct.unpack(">Q", page0[0x20:0x28])[0]
            # Sanity: a Unix-ms timestamp in this millennium is between
            # 1e12 and 5e12.  Otherwise drop the field.
            if 1_000_000_000_000 <= ts1 <= 5_000_000_000_000:
                out["created_unix_ms"] = ts1
            if 1_000_000_000_000 <= ts2 <= 5_000_000_000_000:
                out["modified_unix_ms"] = ts2
        except Exception:
            pass
        try:
            archive_uuid = page0[0x28:0x38]
            if any(archive_uuid):
                out["archive_uuid"] = archive_uuid.hex()
        except Exception:
            pass

        # Page 1: archive metadata payload.
        if self.page_count >= 2:
            page1 = self._raw_read_page(1)
            strings = [m.group().decode("ascii", "replace")
                       for m in _PRINTABLE_RUN_RE.finditer(page1)]
            out["strings"] = strings

            # Heuristic field extraction.  GUIDs are easy to identify by
            # shape; the first GUID is the source disk and the last is
            # the install/agent GUID.  Hostname and agent build are the
            # remaining strings.
            guids = [m.group().decode("ascii") for m in _GUID_RE.finditer(page1)]
            non_guid = [s for s in strings if not _GUID_RE.fullmatch(s.encode())]

            if guids:
                out["disk_guid"] = guids[0]
            if len(guids) > 1:
                out["install_guid"] = guids[-1]
            # Pick the first non-GUID printable run as the hostname.
            if non_guid:
                out["hostname"] = non_guid[0]
            # Build string typically contains "ACPHO" or version-like text.
            for s in non_guid[1:]:
                if any(c.isdigit() for c in s) and "." in s:
                    out["agent_build"] = s
                    break

        return out

    # ------------------------------------------------------------------ #
    # Source-disk LBA reads (bootstrap-only until LSM walker lands)
    # ------------------------------------------------------------------ #

    def read_lba_range(
        self,
        start_lba: int,
        length: int,
        *,
        sector_size: int = 512,
    ) -> bytes:
        """Read ``length`` bytes from the source disk image.

        Currently supports only the bootstrap range
        ``[0, 262144)`` (the first SG segment, which is empirically the
        MBR plus the first 256 KiB of source-disk content).  Reads
        outside that range require the ``segment_map`` LSM-tree walker
        and raise
        :class:`tibread.tibx.disk_image.ChunkMapNotImplemented`.

        See :mod:`tibread.tibx.disk_image` for full notes on the
        chunk-map design and what needs to land before this becomes a
        general random-access primitive.
        """
        # Local import keeps :mod:`disk_image` optional and avoids a
        # circular import (``disk_image`` imports ``TibxReader`` only
        # for type-checking).
        from .disk_image import read_lba_range as _read_lba_range

        return _read_lba_range(
            self, start_lba, length, sector_size=sector_size
        )

    # ------------------------------------------------------------------ #
    # File map summary
    # ------------------------------------------------------------------ #

    def file_map_summary(self, sample_first: int = 8, sample_last: int = 4) -> Dict[str, object]:
        """Return a coarse summary of the file's page layout.

        Walks a small sample of pages at the head and tail to identify
        the major regions (header, ARCI, LEAF run, footer).  This is
        intended for ``tib tibx-info`` output, not for index walking.
        """
        head_types: List[tuple[int, int]] = []
        for i in range(min(sample_first, self.page_count)):
            head_types.append((i, self._raw_read_page(i)[1]))
        tail_types: List[tuple[int, int]] = []
        for i in range(
            max(0, self.page_count - sample_last), self.page_count
        ):
            tail_types.append((i, self._raw_read_page(i)[1]))

        # Locate the trailing LEAF region.  In practice it is not one
        # strictly-contiguous run: a small number of non-LEAF index
        # pages (types 0x04, 0x05) may be sprinkled in among LEAF
        # pages.  We therefore scan backwards from the final footer
        # tolerating short gaps, and report the inclusive [start, end]
        # bracket of all LEAF pages found.
        leaf_end = None
        leaf_start = None
        leaf_count = 0
        FOOTER_SCAN_CAP = 32   # how far back to look for the first LEAF
        GAP_TOLERANCE = 16     # consecutive non-LEAF pages that end the run
        idx = self.page_count - 1
        steps = 0
        while idx >= 0 and steps < FOOTER_SCAN_CAP:
            if self._raw_read_page(idx)[1] == 0x03:
                leaf_end = idx
                break
            idx -= 1
            steps += 1
        if leaf_end is not None:
            leaf_count = 1
            leaf_start = leaf_end
            idx = leaf_end - 1
            gap = 0
            while idx >= 0 and gap < GAP_TOLERANCE:
                if self._raw_read_page(idx)[1] == 0x03:
                    leaf_start = idx
                    leaf_count += 1
                    gap = 0
                else:
                    gap += 1
                idx -= 1

        return {
            "page_count": self.page_count,
            "file_size": self.file_size,
            "head_page_types": head_types,
            "tail_page_types": tail_types,
            "leaf_run_start": leaf_start,
            "leaf_run_end": leaf_end,
            "leaf_run_pages": (leaf_end - leaf_start + 1)
            if (leaf_start is not None and leaf_end is not None)
            else 0,
            "leaf_page_count": leaf_count,
        }


__all__ = ["TibxReader", "TibxPageCrcError"]
