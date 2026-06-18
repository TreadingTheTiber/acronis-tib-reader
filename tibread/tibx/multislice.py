"""Virtual concatenated reader for split multi-file ``.tibx`` archives.

Acronis stores a versioned ``.tibx`` backup as a tiny ARCH "pointer" file
(``NAME.tibx``) plus a series of large data slices (``NAME-0001.tibx`` …).
Together the slices form ONE logical 4 KiB-page store addressed by a
*global* page index.  Each slice physically holds a contiguous window of
that space; the window's starting global page is recorded in the slice's
own tail ARCH header (body offset 0x210, BE u64) — exposed by
:class:`TibxReader` as ``global_base``.

This module presents all present slices as a single virtual file in global
byte order, so the existing single-file machinery (LSM walk, segment
decompression — both of which address by ``global_page * 4096``) works
unchanged.  Pruned/absent slices leave holes; reads there raise, which the
LSM walker and disk adapter already tolerate.
"""
from __future__ import annotations

import glob
import os
import re
from typing import List, Tuple

from .reader import TibxReader
from .format import PAGE_SIZE

_SLICE_RE = re.compile(r"^(?P<stem>.+)-(?P<num>\d{4})\.tibx$", re.IGNORECASE)


class _ConcatSlices:
    """File-like view over several slice file handles placed at their
    global byte offsets.  Supports the seek/tell/read subset the readers
    use."""

    def __init__(self, segments: List[Tuple[int, int, object]]):
        # segments: (global_start_byte, global_end_byte, fh) sorted by start
        self._segs = sorted(segments, key=lambda s: s[0])
        self._pos = 0

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = off
        elif whence == 1:
            self._pos += off
        elif whence == 2:
            end = self._segs[-1][1] if self._segs else 0
            self._pos = end + off
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._segs[-1][1] - self._pos if self._segs else 0
        out = bytearray()
        pos = self._pos
        end = pos + n
        for start, stop, fh in self._segs:
            if stop <= pos:
                continue
            if start >= end:
                break
            if start > pos:
                # hole before this segment — stop; caller sees short read
                break
            lo = pos - start
            take = min(stop, end) - pos
            fh.seek(lo)
            chunk = fh.read(take)
            out.extend(chunk)
            pos += len(chunk)
            if len(chunk) < take or pos >= end:
                break
        self._pos = pos
        return bytes(out)

    def close(self) -> None:
        for _s, _e, fh in self._segs:
            try:
                fh.close()
            except Exception:
                pass


class MultiSliceTibxReader(TibxReader):
    """A :class:`TibxReader` whose page space spans every present slice of
    a split ``.tibx`` archive, addressed by global page index."""

    def __init__(self, any_slice_path: str):
        directory = os.path.dirname(os.path.abspath(any_slice_path))
        base_name = os.path.basename(any_slice_path)
        m = _SLICE_RE.match(base_name)
        if not m:
            raise ValueError(
                f"{base_name}: not a NAME-NNNN.tibx data slice"
            )
        stem = m.group("stem")
        pattern = os.path.join(directory, f"{stem}-[0-9][0-9][0-9][0-9].tibx")

        self.path = any_slice_path
        self.global_base = 0
        self._slices = []          # keep sub-readers alive
        segments: List[Tuple[int, int, object]] = []
        known = []                 # (base, pc, path, fh)
        unresolved = []            # (path, fh, pc)
        for p in sorted(glob.glob(pattern)):
            try:
                sub = TibxReader(p)
            except Exception:
                continue
            self._slices.append(sub)
            base = sub.global_base
            pc = sub.page_count
            if base:
                known.append((base, pc, p, sub._fh))
            else:
                # base not recovered from this slice's own header; fill by
                # contiguity after sorting the resolved ones.
                unresolved.append((p, sub, pc))

        if not known:
            raise ValueError(
                f"{base_name}: no slice exposed a global base; cannot "
                f"reconstruct the address space"
            )
        known.sort()
        # Resolve any unresolved slice by slotting it into a gap between
        # known contiguous ranges (its page_count must match the gap).
        for p, sub, pc in unresolved:
            ends = {b + c for b, c, _p, _f in known}
            placed = False
            for b, c, _p, _f in sorted(known):
                gap_start = b + c
                # next known base after gap_start
                nexts = sorted(bb for bb, _c, _pp, _ff in known if bb > gap_start)
                if nexts and (nexts[0] - gap_start) == pc:
                    known.append((gap_start, pc, p, sub._fh))
                    placed = True
                    break
            if not placed:
                # last resort: assume it abuts the highest known range
                hb, hc, _hp, _hf = max(known)
                known.append((hb + hc, pc, p, sub._fh))
            known.sort()

        for base, pc, _p, fh in known:
            segments.append((base * PAGE_SIZE, (base + pc) * PAGE_SIZE, fh))

        self._fh = _ConcatSlices(segments)
        self.page_count = max(b + c for b, c, _p, _f in known)
        self.file_size = self.page_count * PAGE_SIZE
        self._slice_ranges = [(b, b + c, _p) for b, c, _p, _f in sorted(known)]

    def close(self) -> None:
        for sub in getattr(self, "_slices", []):
            try:
                sub.close()
            except Exception:
                pass
