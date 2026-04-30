#!/usr/bin/env python3
"""
ntfsread - pure-Python read-only NTFS reader.

Operates against any object exposing `.read(offset, length) -> bytes` over a
flat NTFS partition image. Supports:
    - Boot sector (BPB) parsing
    - MFT record parsing with USA fixups
    - Resident & non-resident attributes
    - $STANDARD_INFORMATION, $FILE_NAME, $DATA, $INDEX_ROOT, $INDEX_ALLOCATION
    - Mapping-pair (run-list) decoding incl. sparse runs
    - Directory enumeration via INDX b-tree
    - Path resolution (case-insensitive)
    - File reads (resident or non-resident, sparse-aware)

Limitations:
    - No EFS encryption (encrypted attrs are skipped)
    - No $ATTRIBUTE_LIST chasing (records that overflow into other MFT
      records will be incomplete; rare for normal user files but happens
      for very fragmented files / huge directories)
    - Case-insensitive matching is ASCII-folded only (no upcase table)

Compression support:
    - NTFS attribute compression (LZNT1) is decompressed transparently via
      `tibread.lznt1`. Compression units (typically 16 clusters / 64 KB)
      are decoded on demand and cached LRU.
    - WOF / Compact-OS Xpress-compressed files (reparse tag 0x80000017,
      providers Xpress4K / Xpress8K / Xpress16K) are decompressed via
      `tibread.xpress`. Reads on the (sparse) unnamed $DATA are rerouted
      to the named `:WofCompressedData` ADS. WOF/LZX is not supported.
"""
from __future__ import annotations

import os
import struct
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from .lznt1 import lznt1_decompress
from . import xpress as _xpress

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Attribute types
AT_STANDARD_INFORMATION = 0x10
AT_ATTRIBUTE_LIST       = 0x20
AT_FILE_NAME            = 0x30
AT_OBJECT_ID            = 0x40
AT_SECURITY_DESCRIPTOR  = 0x50
AT_VOLUME_NAME          = 0x60
AT_VOLUME_INFORMATION   = 0x70
AT_DATA                 = 0x80
AT_INDEX_ROOT           = 0x90
AT_INDEX_ALLOCATION     = 0xA0
AT_BITMAP               = 0xB0
AT_REPARSE_POINT        = 0xC0
AT_END                  = 0xFFFFFFFF

# Reparse-point tags (Microsoft-defined)
IO_REPARSE_TAG_WOF = 0x80000017  # Windows Overlay Filter / Compact OS

# WOF FILE_PROVIDER algorithm enum (per ntifs.h)
WOF_FILE_PROVIDER_COMPRESSION_XPRESS4K  = 0
WOF_FILE_PROVIDER_COMPRESSION_LZX       = 1
WOF_FILE_PROVIDER_COMPRESSION_XPRESS8K  = 2
WOF_FILE_PROVIDER_COMPRESSION_XPRESS16K = 3
_WOF_XPRESS_CHUNK_SIZE = {
    WOF_FILE_PROVIDER_COMPRESSION_XPRESS4K:  4096,
    WOF_FILE_PROVIDER_COMPRESSION_XPRESS8K:  8192,
    WOF_FILE_PROVIDER_COMPRESSION_XPRESS16K: 16384,
}

# MFT record flags
MFT_FLAG_IN_USE     = 0x01
MFT_FLAG_DIRECTORY  = 0x02

# Attribute flags
ATTR_FLAG_COMPRESSED = 0x0001
ATTR_FLAG_ENCRYPTED  = 0x4000
ATTR_FLAG_SPARSE     = 0x8000

# Index entry flags
IDX_FLAG_HAS_SUBNODE = 0x01
IDX_FLAG_LAST        = 0x02

# Filename namespaces (priority for picking the "best" name)
NS_POSIX     = 0
NS_WIN32     = 1
NS_DOS       = 2
NS_WIN32_DOS = 3
_NS_PRIORITY = {NS_WIN32: 0, NS_WIN32_DOS: 1, NS_POSIX: 2, NS_DOS: 3}

# Root directory MFT record number (NTFS standard)
ROOT_MFT_RECORD = 5

# FILETIME epoch (1601-01-01) in unix seconds
_FILETIME_EPOCH_DELTA = 11644473600


def filetime_to_unix(ft: int) -> float:
    """Convert Windows FILETIME (100ns ticks since 1601-01-01) to unix epoch seconds."""
    if ft == 0:
        return 0.0
    return ft / 10_000_000.0 - _FILETIME_EPOCH_DELTA


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    name: str
    size: int
    is_dir: bool
    mtime: float = 0.0
    atime: float = 0.0
    ctime: float = 0.0   # MFT entry change time
    btime: float = 0.0   # creation (birth) time
    file_attributes: int = 0
    mft_record: int = 0

    def __repr__(self) -> str:
        kind = "DIR" if self.is_dir else "FILE"
        return f"<FileEntry {kind} name={self.name!r} size={self.size} rec={self.mft_record}>"


# ---------------------------------------------------------------------------
# Internal record / attribute structures
# ---------------------------------------------------------------------------

@dataclass
class _ParsedAttr:
    type: int
    name: str
    flags: int
    non_resident: bool
    # Resident
    content: bytes = b""
    # Non-resident
    first_vcn: int = 0
    last_vcn: int = 0
    alloc_size: int = 0
    real_size: int = 0
    init_size: int = 0
    runs: list = field(default_factory=list)  # list of (vcn_count, lcn_or_None)
    # Compression: log2 of CU size in clusters (typ. 4 = 16 clusters = 64 KB).
    # 0 means uncompressed.
    compression_unit_size: int = 0


@dataclass
class _MftRecord:
    rec_num: int
    in_use: bool
    is_dir: bool
    seq: int
    attrs: list = field(default_factory=list)  # list[_ParsedAttr]
    # Convenience extracted fields
    si_btime: int = 0
    si_mtime: int = 0
    si_ctime: int = 0
    si_atime: int = 0
    si_attrs: int = 0
    # Best filename (highest priority namespace)
    best_name: Optional[str] = None
    parent_ref: int = 0
    fn_btime: int = 0
    fn_mtime: int = 0
    fn_ctime: int = 0
    fn_atime: int = 0
    fn_real_size: int = 0
    fn_attrs: int = 0
    # All filenames (parent_ref, namespace, name) for parent linking
    file_names: list = field(default_factory=list)
    # WOF / Compact OS reparse info (set if the record has IO_REPARSE_TAG_WOF
    # with a supported Xpress provider). When set, `read_file` reroutes to the
    # named :WofCompressedData $DATA attribute and decompresses on the fly.
    wof_uncompressed_size: int = 0
    wof_chunk_size: int = 0   # 4096 / 8192 / 16384; 0 = not WOF / unsupported
    wof_algorithm: int = -1


# ---------------------------------------------------------------------------
# Mapping-pair (run-list) decoder
# ---------------------------------------------------------------------------

def _scan_block_for_filerec(disk_reader, bi: int, expected_rec_num: int, struct_mod) -> Optional[int]:
    """Scan one decompressed block for a cluster-aligned FILE0 record whose
    rec_num field matches expected_rec_num. If found, return the reader LCN of
    that cluster. Otherwise None."""
    try:
        block = disk_reader._decompress_block(bi)
    except Exception:
        return None
    if not block:
        return None
    for off in range(0, len(block), 1024):
        if off + 48 > len(block):
            break
        if block[off:off + 4] != b'FILE':
            continue
        rn = struct_mod.unpack_from("<I", block, off + 44)[0]
        if rn == expected_rec_num:
            _, p, _ = disk_reader._get_record(bi)
            local_present_idx = off // 4096
            cnt = 0
            for b_idx in range(128):
                if p[b_idx >> 3] & (1 << (b_idx & 7)):
                    if cnt == local_present_idx:
                        return bi * 128 + b_idx
                    cnt += 1
    return None


def _decode_runs(buf: bytes, off: int) -> list:
    """Decode a run list starting at buf[off:]. Returns list of (length, lcn_or_None)."""
    runs = []
    cur_lcn = 0
    p = off
    while p < len(buf):
        header = buf[p]
        p += 1
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        if len_size == 0:
            # Malformed
            break
        if p + len_size + off_size > len(buf):
            break
        # Length: unsigned (always positive)
        length = int.from_bytes(buf[p:p + len_size], "little", signed=False)
        p += len_size
        if off_size == 0:
            # Sparse run
            runs.append((length, None))
        else:
            delta = int.from_bytes(buf[p:p + off_size], "little", signed=True)
            p += off_size
            cur_lcn += delta
            runs.append((length, cur_lcn))
    return runs


# ---------------------------------------------------------------------------
# Disk + volume
# ---------------------------------------------------------------------------

class _FileDisk:
    """Adapter that exposes a flat file as `.read(offset, length)`."""
    def __init__(self, path: str):
        self._f = open(path, "rb")
        self._f.seek(0, os.SEEK_END)
        self._size = self._f.tell()

    def read(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if offset >= self._size:
            return b"\x00" * length
        self._f.seek(offset)
        data = self._f.read(length)
        if len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def close(self):
        self._f.close()


class NtfsVolume:
    """Read-only NTFS volume reader."""

    def __init__(self, disk_reader, build_index: bool = True,
                 mft_lcn_override: Optional[int] = None,
                 lcn_shift: int = 0,
                 mft_extent_overrides: Optional[list] = None,
                 lcn_shift_map: Optional[list] = None):
        """
        :param mft_lcn_override: Use this LCN for MFT bootstrap instead of BPB's value.
        :param lcn_shift: Add this offset to every LCN before reading from disk. Useful
            when the .tib's data is uniformly shifted relative to BPB / MFT-record run lists
            (some Acronis sector backups appear to do this). If mft_lcn_override is given
            and lcn_shift is 0, lcn_shift is auto-derived from (override - BPB_value).
        :param mft_extent_overrides: Optional list of (run_index, actual_reader_lcn) pairs
            that override the MFT $DATA runs. Useful when the .tib has multi-segment compaction
            where each MFT extent lives at a different shift. After the bootstrap reads record 0
            and parses its runs, those runs are patched to point at the actual reader LCNs.
        :param lcn_shift_map: Optional piecewise shift map: list of (orig_lcn_threshold, shift)
            tuples sorted by threshold ascending. For a given original LCN X, the applicable
            shift is the one paired with the LARGEST threshold <= X. This supports .tib files
            with non-uniform compaction (multiple MFT extents at different shifts).
            Example: [(0, 0), (786432, -16256), (366639004, -149885824)] means:
              - orig LCN [0..786431]   -> reader_lcn = orig_lcn (no shift)
              - orig LCN [786432..366639003] -> reader_lcn = orig_lcn - 16256
              - orig LCN [366639004..]  -> reader_lcn = orig_lcn - 149885824
            If provided, supersedes lcn_shift for non-MFT data.
        """
        self.disk = disk_reader
        self._parse_boot_sector()
        bpb_mft_lcn = self.mft_lcn
        self._bpb_mft_lcn = bpb_mft_lcn  # remember for compaction-aware run reading
        if mft_lcn_override is not None:
            self.mft_lcn = mft_lcn_override
            if lcn_shift == 0:
                lcn_shift = mft_lcn_override - bpb_mft_lcn
        self.lcn_shift = lcn_shift
        self._lcn_shift_map = sorted(lcn_shift_map) if lcn_shift_map else None
        self._mft_extent_overrides = mft_extent_overrides or []
        # Cache: rec_num -> _MftRecord
        self._mft_cache: dict[int, _MftRecord] = {}
        # path index: built lazily
        self._path_index_built = False
        self._children: dict[int, dict[str, int]] = {}  # parent_rec -> {lower_name: rec_num}
        self._all_recs: set[int] = set()

        # Resolve $MFT (record 0) so we can fetch any record by VCN -> LCN
        self._mft_runs: list = []
        self._bootstrap_mft()

        if build_index:
            self._build_path_index()

    @staticmethod
    def find_mft_extent2(disk_reader, expected_first_record: int = 19200,
                         search_radius_clusters: int = 100000,
                         shift_hint: int = -16256) -> Optional[int]:
        """Locate the actual reader-LCN where MFT extent 2 begins (i.e., where
        record `expected_first_record` lives). The .tib may have additional
        compaction gaps that move extent 2 to a different LCN than the BPB-shift
        would predict.

        Strategy:
          1. Read MFT record 0 (already located via find_mft_lcn) to get its
             $DATA runs.
          2. The 2nd run's claimed LCN, after shift_hint, is our first guess.
          3. Read at that guess. If we find FILE magic with rec_num matching
             expected_first_record, return guess.
          4. Otherwise, scan ±search_radius for FILE0 + correct rec_num.

        Returns the reader-LCN where extent 2 starts, or None if not found.
        """
        import struct
        # Re-bootstrap a temporary view of MFT record 0 to get its runs
        # We'll build a minimal NtfsVolume just to parse record 0
        tmp_vol = NtfsVolume.__new__(NtfsVolume)
        tmp_vol.disk = disk_reader
        tmp_vol._parse_boot_sector()
        bpb_mft = tmp_vol.mft_lcn
        actual_mft = NtfsVolume.find_mft_lcn(disk_reader)
        # Parse rec 0
        raw = disk_reader.read(actual_mft * tmp_vol.cluster_size, tmp_vol.mft_record_size)
        if raw[:4] != b"FILE":
            return None
        first_attr_off = struct.unpack_from("<H", raw, 20)[0]
        runs = None
        pos = first_attr_off
        while pos < len(raw):
            atype = struct.unpack_from("<I", raw, pos)[0]
            if atype == 0xFFFFFFFF: break
            alen = struct.unpack_from("<I", raw, pos + 4)[0]
            if alen == 0: break
            non_resident = raw[pos + 8]
            name_len = raw[pos + 9]
            if atype == AT_DATA and name_len == 0 and non_resident:
                mp_off = struct.unpack_from("<H", raw, pos + 32)[0]
                runs = _decode_runs(raw[pos:pos + alen], mp_off)
                break
            pos += alen
        if not runs or len(runs) < 2:
            return None
        # Run 1's claimed LCN
        _, claimed_lcn = runs[1]
        if claimed_lcn is None:
            return None
        # Helper: validate that a candidate LCN starts MFT extent 2
        def _verify(reader_lcn):
            data = disk_reader.read(reader_lcn * tmp_vol.cluster_size,
                                     tmp_vol.mft_record_size)
            if data[:4] != b"FILE": return False
            rn = struct.unpack_from("<I", data, 44)[0]
            return rn == expected_first_record
        # First guess: claimed + shift_hint, clamped to valid range
        if not (hasattr(disk_reader, 'block_count') and hasattr(disk_reader, '_decompress_block')):
            return None
        max_lcn = disk_reader.block_count * 128
        guess = claimed_lcn + shift_hint
        if 0 <= guess < max_lcn and _verify(guess):
            return guess

        # Linear scan — walk all blocks looking for cluster-aligned FILE0 with
        # exact rec_num match. This is slow (~minutes for 1 TB) but robust.
        # Skip blocks before extent 1 (we know extent 2 is past extent 1).
        start_block = max(0, actual_mft // 128)
        end_block = disk_reader.block_count
        if search_radius_clusters and search_radius_clusters < end_block * 128:
            # Use radius-based search for moderate ranges
            target_block_guess = max(0, min(disk_reader.block_count - 1, guess // 128))
            for delta_block in range(0, min(end_block, search_radius_clusters // 128 + 1)):
                for sign in (-1, 1) if delta_block else (1,):
                    bi = target_block_guess + sign * delta_block
                    if not (start_block <= bi < end_block):
                        continue
                    found = _scan_block_for_filerec(disk_reader, bi, expected_first_record, struct)
                    if found is not None:
                        return found
            return None
        # Otherwise full linear scan
        for bi in range(start_block, end_block):
            found = _scan_block_for_filerec(disk_reader, bi, expected_first_record, struct)
            if found is not None:
                return found
        return None

    @staticmethod
    def find_dense_file0_regions(disk_reader, min_blocks: int = 100):
        """Scan the entire disk_reader for blocks containing dense FILE0 records.
        Returns a list of (start_block, num_blocks, total_records) for each
        contiguous run of FILE0-containing blocks (above min_blocks size).
        Slow — walks every block. Cache the result."""
        # This expects disk_reader to be a TibReader-like object exposing
        # block_count and _decompress_block / _get_record.
        if not (hasattr(disk_reader, 'block_count') and hasattr(disk_reader, '_decompress_block')):
            return []
        clusters = []
        for bi in range(disk_reader.block_count):
            try:
                _, p, _ = disk_reader._get_record(bi)
            except Exception:
                continue
            if sum(bin(b).count("1") for b in p) == 0:
                continue
            try:
                block = disk_reader._decompress_block(bi)
            except Exception:
                continue
            cnt = sum(1 for off in range(0, len(block), 1024) if block[off:off+4] == b"FILE")
            if cnt > 0:
                clusters.append((bi, cnt))
        # Coalesce contiguous block runs
        runs = []
        i = 0
        while i < len(clusters):
            start = clusters[i][0]
            count = clusters[i][1]
            j = i + 1
            while j < len(clusters) and clusters[j][0] == clusters[j-1][0] + 1:
                count += clusters[j][1]
                j += 1
            if (j - i) >= min_blocks:
                runs.append((start, j - i, count))
            i = j
        return runs

    @staticmethod
    def find_mft_lcn(disk_reader, search_radius_clusters: int = 100000) -> int:
        """Search the disk for the actual $MFT location (FILE0 magic).
        Useful when BPB's MFT-LCN field is wrong (volume defragmented or backup
        format may have rewritten it). Returns the LCN of MFT record 0.

        Reads the BPB to learn cluster size and BPB-claimed MFT LCN, then
        scans backward from there in 4KB steps looking for FILE0 magic at the
        start of a cluster, then verifies the candidate by parsing record 0.
        """
        boot = disk_reader.read(0, 512)
        bps = struct.unpack_from("<H", boot, 0x0B)[0]
        spc = boot[0x0D]
        cluster_size = bps * spc
        bpb_mft = struct.unpack_from("<Q", boot, 0x30)[0]

        # Fast path: if the BPB's MFT_LCN points at a valid record-0 FILE0
        # record, just use that. Avoids picking up the MFT_MIRR (4 records
        # at LCN bpb_mftmirr) when MFT_MIRR sits before MFT in the disk.
        cand = disk_reader.read(bpb_mft * cluster_size, max(cluster_size, 1024))
        if cand[:4] == b"FILE":
            rec_num = struct.unpack_from("<I", cand, 44)[0]
            if rec_num == 0:
                return bpb_mft

        # Slow path: BPB's MFT_LCN doesn't validate (e.g. defrag-shifted volume
        # or weird Acronis re-mapping). Scan forward from a window before
        # bpb_mft, but SKIP candidate matches at MFT_MIRR (4 records at
        # bpb_mftmirr) so we don't lock onto the mirror.
        bpb_mftmirr = struct.unpack_from("<Q", boot, 0x38)[0]
        clusters_per_mft = struct.unpack_from("<b", boot, 0x40)[0]
        if clusters_per_mft < 0:
            mft_record_size = 1 << (-clusters_per_mft)
        else:
            mft_record_size = max(1, clusters_per_mft) * cluster_size
        # MFT_MIRR holds 4 records; skip that LCN range from the scan.
        mirr_clusters = max(1, (4 * mft_record_size) // cluster_size)
        mirr_range = (bpb_mftmirr, bpb_mftmirr + mirr_clusters)

        window_clusters = search_radius_clusters
        scan_lcn_start = max(0, bpb_mft - window_clusters)
        chunk_clusters = 256  # 1 MB at 4KB clusters
        chunk_bytes = chunk_clusters * cluster_size
        lcn = scan_lcn_start
        while lcn < bpb_mft + window_clusters:
            data = disk_reader.read(lcn * cluster_size, chunk_bytes)
            if not data:
                break
            for i in range(0, len(data), cluster_size):
                if data[i:i + 4] == b"FILE":
                    rec_num = struct.unpack_from("<I", data, i + 44)[0]
                    if rec_num == 0:
                        cand_lcn = lcn + i // cluster_size
                        if not (mirr_range[0] <= cand_lcn < mirr_range[1]):
                            return cand_lcn
            lcn += chunk_clusters
        raise ValueError(
            f"could not find $MFT (record 0) within {search_radius_clusters} "
            f"clusters of LCN {bpb_mft}"
        )

    # ----- boot sector ------------------------------------------------------

    def _parse_boot_sector(self):
        boot = self.disk.read(0, 512)
        if len(boot) < 512:
            raise ValueError("disk too small to contain boot sector")
        # OEM ID at offset 3 should be "NTFS    "
        oem = boot[3:11]
        self.bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
        self.sectors_per_cluster = boot[0x0D]
        self.total_sectors = struct.unpack_from("<Q", boot, 0x28)[0]
        self.mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
        self.mftmirr_lcn = struct.unpack_from("<Q", boot, 0x38)[0]
        clusters_per_mft = struct.unpack_from("<b", boot, 0x40)[0]
        clusters_per_idx = struct.unpack_from("<b", boot, 0x44)[0]

        if self.bytes_per_sector == 0 or self.sectors_per_cluster == 0:
            raise ValueError(f"invalid BPB: bps={self.bytes_per_sector} spc={self.sectors_per_cluster}")
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        if clusters_per_mft < 0:
            self.mft_record_size = 1 << (-clusters_per_mft)
        else:
            self.mft_record_size = clusters_per_mft * self.cluster_size

        if clusters_per_idx < 0:
            self.index_record_size = 1 << (-clusters_per_idx)
        else:
            self.index_record_size = clusters_per_idx * self.cluster_size

        if oem != b"NTFS    ":
            # Not fatal — some volumes have variants; warn via attribute.
            self.oem_warning = f"unexpected OEM id: {oem!r}"
        else:
            self.oem_warning = None

    # ----- low-level MFT access --------------------------------------------

    def _bootstrap_mft(self):
        """Read MFT record 0 directly from the boot-sector pointer to get $DATA runs."""
        mft_off = self.mft_lcn * self.cluster_size
        raw = self.disk.read(mft_off, self.mft_record_size)
        rec0 = self._parse_mft_record(raw, expected_rec_num=0)
        if rec0 is None:
            raise ValueError("could not parse $MFT (record 0)")
        # Find unnamed $DATA
        for a in rec0.attrs:
            if a.type == AT_DATA and a.name == "" and a.non_resident:
                self._mft_runs = a.runs
                self._mft_real_size = a.real_size
                break
        if not self._mft_runs:
            raise ValueError("$MFT has no non-resident $DATA")
        # Apply per-run overrides for multi-extent MFTs where each extent lives
        # at a different reader-LCN due to additional compaction gaps. Each override
        # entry can be either:
        #   (run_idx, actual_reader_lcn) — replace just the LCN, keep length
        #   (run_idx, actual_reader_lcn, sparse_prefix_clusters, length_override)
        #     — replace LCN, insert N sparse clusters BEFORE this run (keeping the
        #     extent's total length), and use length_override (or original length) clusters
        #     of stored data. Useful when Acronis omitted free clusters at the start of
        #     an MFT extent.
        if self._mft_extent_overrides:
            patched = list(self._mft_runs)
            override_indices = set()
            # Process from highest index down to keep indices stable
            for entry in sorted(self._mft_extent_overrides, key=lambda x: -x[0]):
                run_idx = entry[0]
                actual_reader_lcn = entry[1]
                sparse_prefix = entry[2] if len(entry) > 2 else 0
                length_override = entry[3] if len(entry) > 3 else None
                if not (0 <= run_idx < len(patched)):
                    continue
                orig_len, _ = patched[run_idx]
                stored_len = length_override if length_override is not None else (orig_len - sparse_prefix)
                if sparse_prefix > 0:
                    # Replace single run with: [sparse_prefix as sparse run] + [stored run]
                    new_runs = [(sparse_prefix, None), (stored_len, actual_reader_lcn)]
                    # Indices shift by +1 for runs after run_idx
                    patched = patched[:run_idx] + new_runs + patched[run_idx + 1:]
                    override_indices.add(run_idx + 1)  # the stored run is at run_idx + 1
                else:
                    patched[run_idx] = (stored_len, actual_reader_lcn)
                    override_indices.add(run_idx)
            self._mft_runs_override_indices = override_indices
            self._mft_runs = patched
        else:
            self._mft_runs_override_indices = set()
        self._mft_cache[0] = rec0

    def _read_mft_record_raw(self, rec_num: int) -> bytes:
        """Read raw 1024-byte MFT record bytes (with USA not yet applied)."""
        if not self._mft_runs:
            # Bootstrap path: only record 0 reachable directly
            mft_off = self.mft_lcn * self.cluster_size + rec_num * self.mft_record_size
            return self.disk.read(mft_off, self.mft_record_size)

        # Convert rec_num -> byte offset within $MFT data stream -> partition offset via runs
        offset_in_mft = rec_num * self.mft_record_size
        return self._read_via_runs(self._mft_runs, offset_in_mft, self.mft_record_size, is_mft=True)

    def _shift_for_lcn(self, orig_lcn: int) -> int:
        """Look up the piecewise shift map for the given original LCN.
        Returns the applicable shift. Falls back to legacy single-shift logic if no map."""
        if self._lcn_shift_map:
            # Find largest threshold <= orig_lcn
            import bisect
            # _lcn_shift_map is sorted by threshold (first element of tuple)
            thresholds = [t for t, _ in self._lcn_shift_map]
            idx = bisect.bisect_right(thresholds, orig_lcn) - 1
            if idx < 0:
                # Below all thresholds — return 0 (or first entry's shift)
                return self._lcn_shift_map[0][1]
            return self._lcn_shift_map[idx][1]
        # Legacy: shift only applies past bpb_mft
        bpb_mft = getattr(self, '_bpb_mft_lcn', None)
        if bpb_mft is None or self.lcn_shift == 0:
            return 0
        if orig_lcn >= bpb_mft:
            return self.lcn_shift
        # In the gap (bpb_mft + shift <= orig < bpb_mft) → conceptually unreachable;
        # caller handles separately. Otherwise shift = 0.
        return 0

    def _read_via_runs(self, runs, stream_offset: int, length: int, is_mft: bool = False) -> bytes:
        """Read `length` bytes from a non-resident attribute starting at `stream_offset` in the stream.
        is_mft: if True, apply self.lcn_shift to LCNs (used for $MFT bootstrap because the BPB
        and MFT-record-0's $DATA runs may point to a stale LCN). For regular file $DATA, the
        runs already point to where data actually lives, so no shift."""
        if length <= 0:
            return b""
        out = bytearray()
        remaining = length
        cur_stream_off = stream_offset
        # Walk to the right starting cluster
        cs = self.cluster_size
        # Build cumulative VCN map: each run entry covers `length` VCNs
        cur_vcn = 0
        # MFT runs may have per-run override flags (skip the per-LCN shift logic)
        override_indices = getattr(self, '_mft_runs_override_indices', set()) if is_mft else set()
        for run_idx, (run_len, lcn) in enumerate(runs):
            run_start_vcn = cur_vcn
            run_end_vcn = cur_vcn + run_len
            run_start_byte = run_start_vcn * cs
            run_end_byte = run_end_vcn * cs
            cur_vcn = run_end_vcn
            if cur_stream_off >= run_end_byte:
                continue
            if remaining <= 0:
                break
            # Read overlap
            overlap_start = max(cur_stream_off, run_start_byte)
            overlap_end = min(cur_stream_off + remaining, run_end_byte)
            if overlap_end <= overlap_start:
                continue
            chunk_len = overlap_end - overlap_start
            in_run_off = overlap_start - run_start_byte
            if lcn is None:
                out.extend(b"\x00" * chunk_len)
            elif run_idx in override_indices:
                # Run was overridden — lcn IS the actual reader-LCN, no shift.
                out.extend(self.disk.read(lcn * cs + in_run_off, chunk_len))
            elif self._lcn_shift_map and not is_mft:
                # Piecewise shift map: each cluster may have a different shift depending on
                # which region it falls into. Process cluster-by-cluster.
                pos = 0
                sub_off = in_run_off
                while pos < chunk_len:
                    orig_lcn = lcn + (sub_off // cs)
                    within_cluster = sub_off % cs
                    bytes_in_this_cluster = min(cs - within_cluster, chunk_len - pos)
                    shift_here = self._shift_for_lcn(orig_lcn)
                    reader_lcn = orig_lcn + shift_here
                    if reader_lcn < 0:
                        out.extend(b"\x00" * bytes_in_this_cluster)
                    else:
                        out.extend(self.disk.read(reader_lcn * cs + within_cluster,
                                                   bytes_in_this_cluster))
                    sub_off += bytes_in_this_cluster
                    pos += bytes_in_this_cluster
            else:
                # The .tib's data layout is COMPACTED relative to the original disk:
                # the MFT-zone "reserved but unused" gap (lcn_shift clusters between the
                # logical end of pre-MFT data and the BPB-claimed MFT start) was omitted.
                # All original-disk LCNs >= bpb_mft_lcn are stored at LCN+lcn_shift in our
                # reader's view. Original LCNs in [bpb_mft_lcn + lcn_shift, bpb_mft_lcn)
                # don't exist in the .tib (return zeros).
                bpb_mft = getattr(self, '_bpb_mft_lcn', None)
                shift = self.lcn_shift
                run_first_lcn = lcn + (in_run_off // cs)
                run_last_lcn = lcn + ((in_run_off + chunk_len - 1) // cs)
                # Decide which transform applies
                if bpb_mft is None or shift == 0:
                    # No compaction known; use legacy behavior
                    eff_lcn = lcn + shift if is_mft else lcn
                    out.extend(self.disk.read(eff_lcn * cs + in_run_off, chunk_len))
                elif run_first_lcn >= bpb_mft:
                    # Entire chunk past the gap: shift everything by lcn_shift
                    eff_lcn = lcn + shift
                    out.extend(self.disk.read(eff_lcn * cs + in_run_off, chunk_len))
                elif run_last_lcn < bpb_mft + shift:
                    # Entire chunk in faithful pre-gap region: no shift
                    out.extend(self.disk.read(lcn * cs + in_run_off, chunk_len))
                else:
                    # Straddles the gap or hits the empty zone — handle cluster-by-cluster
                    pos = 0
                    sub_off = in_run_off
                    while pos < chunk_len:
                        orig_lcn = lcn + (sub_off // cs)
                        within_cluster = sub_off % cs
                        bytes_in_this_cluster = min(cs - within_cluster, chunk_len - pos)
                        if orig_lcn >= bpb_mft:
                            reader_lcn = orig_lcn + shift
                            out.extend(self.disk.read(reader_lcn * cs + within_cluster,
                                                       bytes_in_this_cluster))
                        elif orig_lcn >= bpb_mft + shift:
                            # In the gap — zeros
                            out.extend(b"\x00" * bytes_in_this_cluster)
                        else:
                            out.extend(self.disk.read(orig_lcn * cs + within_cluster,
                                                       bytes_in_this_cluster))
                        sub_off += bytes_in_this_cluster
                        pos += bytes_in_this_cluster
            cur_stream_off = overlap_end
            remaining = length - len(out)
            if remaining <= 0:
                break
        if remaining > 0:
            out.extend(b"\x00" * remaining)
        return bytes(out)

    # ----- compressed (LZNT1) attribute read -------------------------------

    _CU_CACHE_MAX = 32

    def _cu_cache_get(self, key):
        cache = getattr(self, "_cu_cache", None)
        if cache is None:
            return None
        v = cache.get(key)
        if v is not None:
            cache.move_to_end(key)
        return v

    def _cu_cache_put(self, key, value):
        cache = getattr(self, "_cu_cache", None)
        if cache is None:
            cache = OrderedDict()
            self._cu_cache = cache
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self._CU_CACHE_MAX:
            cache.popitem(last=False)

    def _decompress_cu(self, attr, cu_index: int, cu_size_bytes: int,
                       cu_size_clusters: int) -> bytes:
        """Materialize one compression unit (CU) of a compressed attr as a
        bytes object of length `cu_size_bytes` (typically 64 KB)."""
        # Walk attr.runs in VCN-space, picking out the CU's vcn slice
        cu_vcn_start = cu_index * cu_size_clusters
        cu_vcn_end = cu_vcn_start + cu_size_clusters
        cs = self.cluster_size

        # Slice the runs covering this CU; classify (a) all sparse, (b) full
        # stored, or (c) partial stored + sparse fill (compressed).
        stored_clusters = 0
        sparse_clusters = 0
        cur_vcn = 0
        cu_runs: list = []  # list of (length_in_clusters, lcn_or_None) limited to CU
        for run_len, lcn in attr.runs:
            run_start = cur_vcn
            run_end = cur_vcn + run_len
            cur_vcn = run_end
            if run_end <= cu_vcn_start:
                continue
            if run_start >= cu_vcn_end:
                break
            seg_start = max(run_start, cu_vcn_start)
            seg_end = min(run_end, cu_vcn_end)
            seg_len = seg_end - seg_start
            if seg_len <= 0:
                continue
            if lcn is None:
                cu_runs.append((seg_len, None))
                sparse_clusters += seg_len
            else:
                # Compute the LCN at seg_start within this run
                seg_lcn = lcn + (seg_start - run_start)
                cu_runs.append((seg_len, seg_lcn))
                stored_clusters += seg_len

        if stored_clusters == 0:
            # All-sparse CU
            return b"\x00" * cu_size_bytes

        # Read all stored clusters in their original order to form the raw
        # CU image (for non-compressed CU) or the LZNT1 payload.
        # Stored runs come before sparse fill in a compressed CU; the read
        # below preserves run order so we get the LZNT1 stream contiguously.
        raw = bytearray()
        for seg_len, seg_lcn in cu_runs:
            if seg_lcn is None:
                # In a compressed CU the trailing sparse clusters are NOT part
                # of the LZNT1 stream — they're just padding. Don't include.
                continue
            raw.extend(self._read_clusters(seg_lcn, seg_len))

        if stored_clusters == cu_size_clusters and sparse_clusters == 0:
            # Uncompressed CU, stored verbatim
            return bytes(raw)

        # Compressed CU — run LZNT1 on the stored bytes, pad to CU size
        return lznt1_decompress(bytes(raw), expected_size=cu_size_bytes)

    def _read_clusters(self, lcn: int, n_clusters: int) -> bytes:
        """Read n_clusters starting at `lcn`, applying the same shift logic
        as `_read_via_runs` for non-MFT data."""
        cs = self.cluster_size
        if self._lcn_shift_map:
            out = bytearray()
            for k in range(n_clusters):
                orig = lcn + k
                shift = self._shift_for_lcn(orig)
                reader_lcn = orig + shift
                if reader_lcn < 0:
                    out.extend(b"\x00" * cs)
                else:
                    out.extend(self.disk.read(reader_lcn * cs, cs))
            return bytes(out)
        bpb_mft = getattr(self, '_bpb_mft_lcn', None)
        shift = self.lcn_shift
        if bpb_mft is None or shift == 0:
            return self.disk.read(lcn * cs, n_clusters * cs)
        # Apply the same gap logic as _read_via_runs for non-MFT data
        out = bytearray()
        for k in range(n_clusters):
            orig = lcn + k
            if orig >= bpb_mft:
                reader_lcn = orig + shift
                out.extend(self.disk.read(reader_lcn * cs, cs))
            elif orig >= bpb_mft + shift:
                out.extend(b"\x00" * cs)
            else:
                out.extend(self.disk.read(orig * cs, cs))
        return bytes(out)

    def _read_compressed_attr(self, attr: _ParsedAttr, offset: int, length: int,
                              cache_key_prefix=()) -> bytes:
        """Read `length` bytes from `offset` of an LZNT1-compressed non-resident
        attribute. The attribute's $DATA real_size is the *uncompressed* file
        size; CUs of `2 ** attr.compression_unit_size` clusters each are
        decoded on demand via `lznt1_decompress` and cached LRU."""
        cu_clusters = 1 << attr.compression_unit_size
        cu_bytes = cu_clusters * self.cluster_size
        real_size = attr.real_size
        init_size = attr.init_size
        if length <= 0 or offset >= real_size:
            return b""
        end = min(offset + length, real_size)
        out = bytearray()
        cu_idx = offset // cu_bytes
        cu_off = offset % cu_bytes
        while len(out) < end - offset:
            need = (end - offset) - len(out)
            # Anything past init_size is logically zero
            absolute = offset + len(out)
            if absolute >= init_size:
                out.extend(b"\x00" * need)
                break
            cu_remaining = cu_bytes - cu_off
            take = min(need, cu_remaining)
            # Cache per (id(attr), cu_idx). id is fine — _MftRecord lives in cache.
            ck = cache_key_prefix + (id(attr), cu_idx)
            cu_data = self._cu_cache_get(ck)
            if cu_data is None:
                cu_data = self._decompress_cu(attr, cu_idx, cu_bytes, cu_clusters)
                self._cu_cache_put(ck, cu_data)
            slice_end = cu_off + take
            chunk = cu_data[cu_off:slice_end]
            # Honour init_size cutoff inside this CU
            cu_abs_start = cu_idx * cu_bytes
            if init_size < cu_abs_start + slice_end:
                cutoff = max(0, init_size - (cu_abs_start + cu_off))
                if cutoff < len(chunk):
                    chunk = chunk[:cutoff] + b"\x00" * (len(chunk) - cutoff)
            out.extend(chunk)
            cu_idx += 1
            cu_off = 0
        return bytes(out)

    # ----- WOF (Xpress) attribute read -------------------------------------

    def _read_wof(self, rec: _MftRecord, offset: int, length: int) -> bytes:
        """Read from a WOF-compressed file by decompressing the named
        :WofCompressedData $DATA stream."""
        size = rec.wof_uncompressed_size
        if length < 0:
            length = size - offset
        if offset >= size or length <= 0:
            return b""
        length = min(length, size - offset)

        # Cached decompressed payload? WOF files tend to be read whole; one
        # decompression per file is fine. Re-use the same LRU as CUs.
        ck = ("wof", rec.rec_num)
        plain = self._cu_cache_get(ck)
        if plain is None:
            wof_attr = None
            for a in rec.attrs:
                if a.type == AT_DATA and a.name == "WofCompressedData":
                    wof_attr = a
                    break
            if wof_attr is None:
                # No payload — return zeros (file appears empty)
                return b"\x00" * length
            if wof_attr.non_resident:
                payload = self._read_via_runs(wof_attr.runs, 0, wof_attr.real_size)
            else:
                payload = wof_attr.content
            try:
                plain = _xpress.decompress(payload, size, chunk_size=rec.wof_chunk_size)
            except _xpress.XpressError:
                return b"\x00" * length
            self._cu_cache_put(ck, plain)
        return plain[offset:offset + length]

    def _get_mft_record(self, rec_num: int) -> Optional[_MftRecord]:
        cached = self._mft_cache.get(rec_num)
        if cached is not None:
            return cached
        raw = self._read_mft_record_raw(rec_num)
        if len(raw) < 42 or raw[:4] != b"FILE":
            return None
        rec = self._parse_mft_record(raw, expected_rec_num=rec_num)
        if rec is not None:
            self._mft_cache[rec_num] = rec
        return rec

    # ----- MFT record parsing ----------------------------------------------

    @staticmethod
    def _apply_fixups(buf: bytes) -> Optional[bytes]:
        if len(buf) < 8:
            return None
        usa_off = struct.unpack_from("<H", buf, 4)[0]
        usa_count = struct.unpack_from("<H", buf, 6)[0]
        if usa_count < 1:
            return None
        if usa_off + usa_count * 2 > len(buf):
            return None
        usa = buf[usa_off:usa_off + usa_count * 2]
        fixup_value = usa[:2]
        out = bytearray(buf)
        # Sectors expected: usa_count - 1, each 512 bytes
        for i in range(1, usa_count):
            sec_end = i * 512
            if sec_end > len(out):
                break
            if bytes(out[sec_end - 2:sec_end]) != fixup_value:
                # Corruption; bail but keep what we have
                return bytes(out)
            out[sec_end - 2:sec_end] = usa[i * 2:i * 2 + 2]
        return bytes(out)

    def _parse_mft_record(self, raw: bytes, expected_rec_num: int = -1) -> Optional[_MftRecord]:
        if len(raw) < 42 or raw[:4] != b"FILE":
            return None
        fixed = self._apply_fixups(raw)
        if fixed is None:
            return None
        flags = struct.unpack_from("<H", fixed, 22)[0]
        seq = struct.unpack_from("<H", fixed, 16)[0]
        rec_num = struct.unpack_from("<I", fixed, 44)[0]
        if expected_rec_num >= 0 and rec_num == 0 and expected_rec_num != 0:
            # Some formatters leave rec_num=0; trust caller's record number.
            rec_num = expected_rec_num
        in_use = bool(flags & MFT_FLAG_IN_USE)
        is_dir = bool(flags & MFT_FLAG_DIRECTORY)
        first_attr_off = struct.unpack_from("<H", fixed, 20)[0]

        rec = _MftRecord(rec_num=rec_num, in_use=in_use, is_dir=is_dir, seq=seq)
        pos = first_attr_off
        N = len(fixed)
        while pos + 8 <= N:
            attr_type = struct.unpack_from("<I", fixed, pos)[0]
            if attr_type == AT_END:
                break
            if pos + 16 > N:
                break
            attr_len = struct.unpack_from("<I", fixed, pos + 4)[0]
            if attr_len == 0 or pos + attr_len > N:
                break
            non_resident = fixed[pos + 8] != 0
            name_len = fixed[pos + 9]
            name_off = struct.unpack_from("<H", fixed, pos + 10)[0]
            attr_flags = struct.unpack_from("<H", fixed, pos + 12)[0]

            # Skip encrypted attrs (EFS not supported). Compressed attrs are
            # handled below — they go into rec.attrs and decompression is
            # applied in the read path.
            if attr_flags & ATTR_FLAG_ENCRYPTED:
                pos += attr_len
                continue

            if name_len:
                name_bytes = fixed[pos + name_off:pos + name_off + name_len * 2]
                attr_name = name_bytes.decode("utf-16-le", errors="replace")
            else:
                attr_name = ""

            pa = _ParsedAttr(type=attr_type, name=attr_name, flags=attr_flags, non_resident=non_resident)

            if not non_resident:
                content_size = struct.unpack_from("<I", fixed, pos + 16)[0]
                content_off = struct.unpack_from("<H", fixed, pos + 20)[0]
                if content_off + content_size > attr_len:
                    # Clamp
                    content_size = max(0, attr_len - content_off)
                pa.content = fixed[pos + content_off:pos + content_off + content_size]
            else:
                first_vcn = struct.unpack_from("<Q", fixed, pos + 16)[0]
                last_vcn = struct.unpack_from("<Q", fixed, pos + 24)[0]
                run_off = struct.unpack_from("<H", fixed, pos + 32)[0]
                # Compression unit size (log2 clusters). Only meaningful when
                # ATTR_FLAG_COMPRESSED is set; 0 otherwise.
                comp_unit = struct.unpack_from("<H", fixed, pos + 34)[0]
                alloc_size = struct.unpack_from("<Q", fixed, pos + 40)[0]
                real_size = struct.unpack_from("<Q", fixed, pos + 48)[0]
                init_size = struct.unpack_from("<Q", fixed, pos + 56)[0]
                pa.first_vcn = first_vcn
                pa.last_vcn = last_vcn
                pa.alloc_size = alloc_size
                pa.real_size = real_size
                pa.init_size = init_size
                if attr_flags & ATTR_FLAG_COMPRESSED:
                    pa.compression_unit_size = comp_unit if comp_unit else 4
                if run_off < attr_len:
                    pa.runs = _decode_runs(fixed[pos:pos + attr_len], run_off)

            rec.attrs.append(pa)

            # Extract convenience fields
            if attr_type == AT_STANDARD_INFORMATION and not non_resident and len(pa.content) >= 48:
                c = pa.content
                rec.si_btime = struct.unpack_from("<Q", c, 0)[0]
                rec.si_mtime = struct.unpack_from("<Q", c, 8)[0]
                rec.si_ctime = struct.unpack_from("<Q", c, 16)[0]
                rec.si_atime = struct.unpack_from("<Q", c, 24)[0]
                rec.si_attrs = struct.unpack_from("<I", c, 32)[0]
            elif attr_type == AT_FILE_NAME and not non_resident:
                fn = self._parse_file_name(pa.content)
                if fn is not None:
                    rec.file_names.append(fn)
            elif attr_type == AT_REPARSE_POINT and not non_resident:
                self._maybe_parse_wof(rec, pa.content)

            pos += attr_len

        # If WOF was detected, record the uncompressed size from the unnamed
        # $DATA (which is a sparse placeholder of exactly that length).
        if rec.wof_chunk_size:
            for a in rec.attrs:
                if a.type == AT_DATA and a.name == "":
                    rec.wof_uncompressed_size = a.real_size if a.non_resident else len(a.content)
                    break

        # Pick best name
        if rec.file_names:
            ranked = sorted(rec.file_names, key=lambda x: _NS_PRIORITY.get(x["namespace"], 99))
            best = ranked[0]
            rec.best_name = best["name"]
            rec.parent_ref = best["parent_ref"]
            rec.fn_btime = best["btime"]
            rec.fn_mtime = best["mtime"]
            rec.fn_ctime = best["ctime"]
            rec.fn_atime = best["atime"]
            rec.fn_real_size = best["real_size"]
            rec.fn_attrs = best["attrs"]

        return rec

    @staticmethod
    def _maybe_parse_wof(rec: _MftRecord, content: bytes) -> None:
        """If `content` is a $REPARSE_POINT body for IO_REPARSE_TAG_WOF with
        a supported Xpress provider, populate rec.wof_* fields."""
        if len(content) < 8:
            return
        tag = struct.unpack_from("<I", content, 0)[0]
        if tag != IO_REPARSE_TAG_WOF:
            return
        data_len = struct.unpack_from("<H", content, 4)[0]
        # 8-byte reparse header, then GenericReparseBuffer of `data_len`.
        # WOF body layout:
        #   WOF_EXTERNAL_INFO          { u32 Version=1; u32 Provider=2 }   (8 bytes)
        #   FILE_PROVIDER_EXTERNAL_INFO_V1 {
        #       u32 Version=1; u32 Algorithm; u32 Flags                    (12 bytes)
        #   }
        # Total = 20 bytes (some buffers also include trailing padding).
        if 8 + data_len > len(content) or data_len < 16:
            return
        body = content[8:8 + data_len]
        wof_ver = struct.unpack_from("<I", body, 0)[0]
        provider = struct.unpack_from("<I", body, 4)[0]
        if wof_ver != 1 or provider != 2:  # only FILE_PROVIDER supported
            return
        prov_ver = struct.unpack_from("<I", body, 8)[0]
        algorithm = struct.unpack_from("<I", body, 12)[0]
        if prov_ver != 1:
            return
        chunk = _WOF_XPRESS_CHUNK_SIZE.get(algorithm)
        if chunk is None:
            # LZX (1) or unknown — leave wof_chunk_size = 0 so reads fall back.
            rec.wof_algorithm = algorithm
            return
        rec.wof_algorithm = algorithm
        rec.wof_chunk_size = chunk
        # Uncompressed size is recorded in the unnamed $DATA's real_size
        # (it's a sparse stream of that length). Filled in by the caller from
        # the parsed attrs after the loop completes.

    @staticmethod
    def _parse_file_name(content: bytes) -> Optional[dict]:
        if len(content) < 66:
            return None
        parent_ref = struct.unpack_from("<Q", content, 0)[0] & 0x0000FFFFFFFFFFFF
        btime = struct.unpack_from("<Q", content, 8)[0]
        mtime = struct.unpack_from("<Q", content, 16)[0]
        ctime = struct.unpack_from("<Q", content, 24)[0]
        atime = struct.unpack_from("<Q", content, 32)[0]
        alloc_size = struct.unpack_from("<Q", content, 40)[0]
        real_size = struct.unpack_from("<Q", content, 48)[0]
        attrs = struct.unpack_from("<I", content, 56)[0]
        name_len = content[64]
        namespace = content[65]
        name_off = 66
        if name_off + name_len * 2 > len(content):
            return None
        name = content[name_off:name_off + name_len * 2].decode("utf-16-le", errors="replace")
        return {
            "parent_ref": parent_ref,
            "namespace": namespace,
            "name": name,
            "btime": btime,
            "mtime": mtime,
            "ctime": ctime,
            "atime": atime,
            "alloc_size": alloc_size,
            "real_size": real_size,
            "attrs": attrs,
        }

    # ----- path index build -------------------------------------------------

    def _build_path_index(self):
        """Walk the entire MFT once and build (parent -> {name: child}) map."""
        if self._path_index_built:
            return
        # MFT length in records
        total_records = self._mft_real_size // self.mft_record_size

        for rec_num in range(total_records):
            rec = self._get_mft_record(rec_num)
            if rec is None or not rec.in_use:
                continue
            self._all_recs.add(rec_num)
            if rec_num < 16 and rec_num != ROOT_MFT_RECORD:
                # Skip system metafiles for path traversal (still cached)
                continue
            if not rec.file_names:
                continue
            # Index every namespace-1/3/0 alias under its parent. DOS-only (2) is redundant.
            seen_lower = set()
            ranked = sorted(rec.file_names, key=lambda x: _NS_PRIORITY.get(x["namespace"], 99))
            for fn in ranked:
                if fn["namespace"] == NS_DOS:
                    continue
                lower = fn["name"].lower()
                if lower in seen_lower:
                    continue
                seen_lower.add(lower)
                parent = fn["parent_ref"]
                bucket = self._children.setdefault(parent, {})
                # Don't overwrite a higher-priority entry
                bucket.setdefault(lower, rec_num)

        self._path_index_built = True

    @property
    def total_files(self) -> int:
        if not self._path_index_built:
            self._build_path_index()
        # In-use records minus system reserved (0..15) excluding root
        count = 0
        for r in self._all_recs:
            if r < 16:
                continue
            count += 1
        return count

    # ----- path resolution --------------------------------------------------

    def _split_path(self, path: str) -> list:
        # Accept both / and \ as separators, strip leading sep
        path = path.replace("\\", "/").strip()
        if path in ("", "/"):
            return []
        parts = [p for p in path.split("/") if p]
        return parts

    def _resolve(self, path: str) -> Optional[int]:
        """Resolve a path to an MFT record number. Returns None if not found."""
        if not self._path_index_built:
            self._build_path_index()
        cur = ROOT_MFT_RECORD
        for part in self._split_path(path):
            bucket = self._children.get(cur)
            if not bucket:
                return None
            child = bucket.get(part.lower())
            if child is None:
                return None
            cur = child
        return cur

    # ----- FileEntry construction ------------------------------------------

    def _entry_for(self, rec_num: int, name_override: Optional[str] = None) -> Optional[FileEntry]:
        rec = self._get_mft_record(rec_num)
        if rec is None or not rec.in_use:
            return None
        name = name_override if name_override is not None else (rec.best_name or "")
        # Determine size from unnamed $DATA (files); for dirs size is 0
        size = 0
        if not rec.is_dir:
            for a in rec.attrs:
                if a.type == AT_DATA and a.name == "":
                    if a.non_resident:
                        size = a.real_size
                    else:
                        size = len(a.content)
                    break
            if size == 0 and rec.fn_real_size:
                # Fall back to $FILE_NAME's recorded size
                size = rec.fn_real_size
        return FileEntry(
            name=name,
            size=size,
            is_dir=rec.is_dir,
            mtime=filetime_to_unix(rec.si_mtime or rec.fn_mtime),
            atime=filetime_to_unix(rec.si_atime or rec.fn_atime),
            ctime=filetime_to_unix(rec.si_ctime or rec.fn_ctime),
            btime=filetime_to_unix(rec.si_btime or rec.fn_btime),
            file_attributes=rec.si_attrs or rec.fn_attrs,
            mft_record=rec_num,
        )

    # ----- public: stat -----------------------------------------------------

    def stat(self, path: str) -> FileEntry:
        rec_num = self._resolve(path)
        if rec_num is None:
            raise FileNotFoundError(path)
        # Use the path's last component as the displayed name (preserves case)
        parts = self._split_path(path)
        name = parts[-1] if parts else ""
        entry = self._entry_for(rec_num, name_override=name)
        if entry is None:
            raise FileNotFoundError(path)
        return entry

    # ----- public: list_dir -------------------------------------------------

    def list_dir(self, path: str) -> list:
        rec_num = self._resolve(path)
        if rec_num is None:
            raise FileNotFoundError(path)
        rec = self._get_mft_record(rec_num)
        if rec is None or not rec.is_dir:
            raise NotADirectoryError(path)

        # Use the pre-built children index for completeness (it covers all
        # parents seen in the MFT walk). This avoids needing to walk the
        # B-tree for directories we already indexed.
        entries: list[FileEntry] = []
        bucket = self._children.get(rec_num, {})
        seen = set()
        for lower, child_rec in bucket.items():
            if child_rec in seen:
                continue
            seen.add(child_rec)
            child = self._get_mft_record(child_rec)
            if child is None:
                continue
            # Pick this child's name as it appears under THIS parent
            display_name = None
            ranked = sorted(child.file_names, key=lambda x: _NS_PRIORITY.get(x["namespace"], 99))
            for fn in ranked:
                if fn["parent_ref"] == rec_num and fn["namespace"] != NS_DOS:
                    display_name = fn["name"]
                    break
            if display_name is None:
                display_name = child.best_name or f"<rec-{child_rec}>"
            e = self._entry_for(child_rec, name_override=display_name)
            if e is not None:
                entries.append(e)
        entries.sort(key=lambda x: (not x.is_dir, x.name.lower()))
        return entries

    # ----- public: read_file -----------------------------------------------

    def read_file(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        rec_num = self._resolve(path)
        if rec_num is None:
            raise FileNotFoundError(path)
        rec = self._get_mft_record(rec_num)
        if rec is None:
            raise FileNotFoundError(path)
        if rec.is_dir:
            raise IsADirectoryError(path)

        # WOF / Compact OS Xpress: the unnamed $DATA is a sparse placeholder;
        # the real bytes live in :WofCompressedData. Decompress and slice.
        if rec.wof_chunk_size:
            return self._read_wof(rec, offset, length)

        data_attr = None
        for a in rec.attrs:
            if a.type == AT_DATA and a.name == "":
                data_attr = a
                break
        if data_attr is None:
            return b""

        if not data_attr.non_resident:
            content = data_attr.content
            real_size = len(content)
            if length < 0:
                length = real_size - offset
            length = max(0, min(length, real_size - offset))
            return content[offset:offset + length]

        real_size = data_attr.real_size
        if length < 0:
            length = real_size - offset
        if offset >= real_size or length <= 0:
            return b""
        length = min(length, real_size - offset)

        # NTFS attribute compression (LZNT1)
        if data_attr.flags & ATTR_FLAG_COMPRESSED and data_attr.compression_unit_size:
            return self._read_compressed_attr(data_attr, offset, length)

        # Initialized data ends at init_size; bytes past that read as zero.
        init_size = data_attr.init_size
        result = bytearray(length)
        # Read up to init_size from runs; rest stays zero.
        if offset < init_size:
            read_len = min(length, init_size - offset)
            chunk = self._read_via_runs(data_attr.runs, offset, read_len)
            result[:len(chunk)] = chunk
        return bytes(result)

    # ----- public: open -----------------------------------------------------

    def open(self, path: str):
        return _FileHandle(self, path)


# ---------------------------------------------------------------------------
# Streaming file handle
# ---------------------------------------------------------------------------

class _FileHandle:
    def __init__(self, vol: NtfsVolume, path: str):
        self.vol = vol
        self.path = path
        rec_num = vol._resolve(path)
        if rec_num is None:
            raise FileNotFoundError(path)
        rec = vol._get_mft_record(rec_num)
        if rec is None:
            raise FileNotFoundError(path)
        if rec.is_dir:
            raise IsADirectoryError(path)
        self._rec = rec
        self._data_attr = None
        for a in rec.attrs:
            if a.type == AT_DATA and a.name == "":
                self._data_attr = a
                break
        if self._data_attr is None:
            self._size = 0
        elif self._data_attr.non_resident:
            self._size = self._data_attr.real_size
        else:
            self._size = len(self._data_attr.content)
        self._pos = 0

    @property
    def size(self) -> int:
        return self._size

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = self._size + offset
        else:
            raise ValueError("invalid whence")
        if self._pos < 0:
            self._pos = 0
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self._size - self._pos
        if n <= 0 or self._pos >= self._size:
            return b""
        data = self.vol.read_file(self.path, self._pos, n)
        self._pos += len(data)
        return data

    def close(self):
        # Nothing to release — disk handle is shared with the volume.
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

def _format_listing(entries: list) -> str:
    lines = []
    for e in entries:
        kind = "D" if e.is_dir else "F"
        size = "-" if e.is_dir else f"{e.size:,}"
        lines.append(f"{kind}  {size:>16}  {e.name}")
    return "\n".join(lines)


def _main(argv):
    if len(argv) < 2:
        print("usage: ntfsread.py <disk-image> [path]")
        print("  prints `ls path` (default '/')")
        sys.exit(1)
    image = argv[1]
    path = argv[2] if len(argv) > 2 else "/"
    disk = _FileDisk(image)
    vol = NtfsVolume(disk)
    print(f"BPB: bytes/sec={vol.bytes_per_sector} sec/clu={vol.sectors_per_cluster} "
          f"cluster={vol.cluster_size} mft_lcn={vol.mft_lcn} "
          f"mft_record_size={vol.mft_record_size} total_sectors={vol.total_sectors:,}")
    print(f"in-use records: {len(vol._all_recs):,}  total_files: {vol.total_files:,}")
    print(f"--- ls {path!r} ---")
    try:
        entries = vol.list_dir(path)
    except (FileNotFoundError, NotADirectoryError) as e:
        # Fall back to stat
        try:
            st = vol.stat(path)
            print(_format_listing([st]))
            return
        except FileNotFoundError:
            print(f"path not found: {path}")
            sys.exit(2)
    print(_format_listing(entries))


if __name__ == "__main__":
    _main(sys.argv)
