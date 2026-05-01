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
    PAGE_TYPE_GOLOMB,
    PAGE_TYPE_LSM5,
    PAGE_TYPE_DATA,
    META_KEYS_MAX,
    META_KEY_NAMES,
    VolumeTableEntry,
    compute_page_crc32,
    crc32c,
    parse_meta_keys,
    parse_meta_keys_dict,
    parse_volume_table,
)
from .reader import TibxReader, TibxPageCrcError
from .segment import SgSegment, decompress_segment, parse_sg_header
from .disk_image import (
    BOOTSTRAP_LEN,
    ChunkMapNotImplemented,
    read_lba_range,
)
from .disk_adapter import TibxDiskAdapter, TibxAdapterError
from .lsm import (
    ArchiveHeader,
    CTreeRef,
    CTreeWalkStats,
    LsmPageHeader,
    LsmSuperblock,
    TlvSlot,
    decode_lsm_page_payload,
    parse_ldir_records,
    parse_leaf,
    parse_leaf_header,
    parse_tlv_directory,
    read_archive_header,
    read_lsm_superblocks,
    walk_ctree,
    walk_lsm_region,
    walk_lsm_tree,
)
from .chains import (
    Slice,
    enumerate_slices,
    find_slice_by_uuid,
    iter_chains,
    parse_slice_record,
    slice_features,
    slice_type_from_flags,
    walk_chain_from_uuid,
)

__all__ = [
    "TibxReader",
    "TibxPageCrcError",
    "SgSegment",
    "decompress_segment",
    "parse_sg_header",
    "BOOTSTRAP_LEN",
    "ChunkMapNotImplemented",
    "read_lba_range",
    "TibxDiskAdapter",
    "TibxAdapterError",
    "compute_page_crc32",
    "crc32c",
    "PAGE_SIZE",
    "ENVELOPE_SIZE",
    "PAGE_BODY_SIZE",
    "PAGE_TYPE_ARCH",
    "PAGE_TYPE_ARCI",
    "PAGE_TYPE_LEAF",
    "PAGE_TYPE_LDIR",
    "PAGE_TYPE_GOLOMB",
    "PAGE_TYPE_LSM5",       # back-compat alias for PAGE_TYPE_GOLOMB
    "PAGE_TYPE_DATA",
    # TLV[9] meta_keys + TLV[18] volume_table (format.py)
    "META_KEYS_MAX",
    "META_KEY_NAMES",
    "VolumeTableEntry",
    "parse_meta_keys",
    "parse_meta_keys_dict",
    "parse_volume_table",
    # LSM tree parser (lsm.py)
    "ArchiveHeader",
    "CTreeRef",
    "CTreeWalkStats",
    "LsmPageHeader",
    "LsmSuperblock",
    "TlvSlot",
    "decode_lsm_page_payload",
    "parse_ldir_records",
    "parse_leaf",
    "parse_leaf_header",
    "parse_tlv_directory",
    "read_archive_header",
    "read_lsm_superblocks",
    "walk_ctree",
    "walk_lsm_region",
    "walk_lsm_tree",
    # Chain / slice enumeration (chains.py)
    "Slice",
    "enumerate_slices",
    "find_slice_by_uuid",
    "iter_chains",
    "parse_slice_record",
    "slice_features",
    "slice_type_from_flags",
    "walk_chain_from_uuid",
]
