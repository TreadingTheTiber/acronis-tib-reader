"""
tibread — pure-Python read-only access to Acronis True Image .tib backups.

Quick start:
    >>> from tibread import open_tib
    >>> vol = open_tib("/path/to/backup_full_b1_s1_v1.tib")
    >>> for entry in vol.list_dir(""):       # "" lists the volume root
    ...     print(entry.name)
    >>> data = vol.read_file("Some/File.txt")  # returns bytes

Lower-level access:
    >>> from tibread.reader import TibReader
    >>> from tibread.ntfs import NtfsVolume
    >>> from tibread.indexer import build_index
"""
from .reader import TibReader
from .ntfs import NtfsVolume
from .indexer import build_index, open_tib
from .chunkmap_locator import discover_chunkmap_offset, detect_format_era
from .chunkmap import decode_chunk_map

__version__ = "0.1.0"

__all__ = [
    "TibReader",
    "NtfsVolume",
    "build_index",
    "open_tib",
    "discover_chunkmap_offset",
    "detect_format_era",
    "decode_chunk_map",
]
