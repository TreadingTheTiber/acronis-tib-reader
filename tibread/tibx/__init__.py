"""
tibread.tibx — read-only access to Acronis archive3 ``.tibx`` page-store files.

This subpackage is **experimental**.  It can read a known-plaintext
``.tibx`` archive (key=0 throughout) by iterating SG segments and
Zstd-decompressing them.  It does *not* yet walk the LSM index or
expose a logical-byte/file-system interface — for that, build on top of
:class:`TibxReader`.

Public surface:

    >>> from tibread.tibx import TibxReader
    >>> with TibxReader("/path/to/backup.tibx") as r:
    ...     hdr = r.read_arch_header()
    ...     print(hdr["hostname"], hdr.get("disk_guid"))
    ...     for seg in r.find_segments():
    ...         data = r.decompress_segment(seg)
    ...         break
"""
from .format import (
    PAGE_SIZE,
    ENVELOPE_SIZE,
    PAGE_BODY_SIZE,
    PAGE_TYPE_ARCH,
    PAGE_TYPE_ARCI,
    PAGE_TYPE_LEAF,
    PAGE_TYPE_LDIR,
    PAGE_TYPE_LSM5,
    PAGE_TYPE_DATA,
    compute_page_crc32,
    crc32c,
)
from .reader import TibxReader, TibxPageCrcError
from .segment import SgSegment, decompress_segment, parse_sg_header

__all__ = [
    "TibxReader",
    "TibxPageCrcError",
    "SgSegment",
    "decompress_segment",
    "parse_sg_header",
    "compute_page_crc32",
    "crc32c",
    "PAGE_SIZE",
    "ENVELOPE_SIZE",
    "PAGE_BODY_SIZE",
    "PAGE_TYPE_ARCH",
    "PAGE_TYPE_ARCI",
    "PAGE_TYPE_LEAF",
    "PAGE_TYPE_LDIR",
    "PAGE_TYPE_LSM5",
    "PAGE_TYPE_DATA",
]
