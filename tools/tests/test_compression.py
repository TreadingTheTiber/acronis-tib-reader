"""Integration tests for NTFS compression read paths.

Synthesises in-memory NTFS-attribute scenarios (no real .tib needed) and
verifies that:

  * LZNT1 compressed CUs decompress correctly through the public attr-read
    path (`NtfsVolume._read_compressed_attr`)
  * Cross-CU reads, partial reads and init_size cutoffs behave correctly
  * WOF / Compact OS Xpress reparse points are detected from a synthetic
    reparse buffer
  * `NtfsVolume._read_wof` decompresses the named :WofCompressedData ADS
    and slices correctly

These complement the canonical-vector self-tests already in
`tibread/lznt1.py` and `tibread/xpress.py` (which validate the bit-exact
decoder).

Run directly:  python3 tools/tests/test_compression.py
"""
from __future__ import annotations

import struct
import sys

sys.path.insert(0, "/home/colin/tibread/dist")

from tibread import xpress
from tibread.ntfs import (
    AT_DATA,
    ATTR_FLAG_COMPRESSED,
    IO_REPARSE_TAG_WOF,
    NtfsVolume,
    _MftRecord,
    _ParsedAttr,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ClusterDisk:
    """In-memory cluster-addressable backing store (4 KB clusters)."""

    def __init__(self, n_clusters: int = 256, cluster_size: int = 4096):
        self.cluster_size = cluster_size
        self.clusters = [b"\x00" * cluster_size for _ in range(n_clusters)]

    def write_cluster(self, lcn: int, data: bytes) -> None:
        cs = self.cluster_size
        if len(data) > cs:
            raise ValueError("data > cluster_size")
        self.clusters[lcn] = data + b"\x00" * (cs - len(data))

    def read(self, offset: int, length: int) -> bytes:
        cs = self.cluster_size
        out = bytearray()
        while length > 0:
            cl, woff = divmod(offset, cs)
            n = min(cs - woff, length)
            if cl >= len(self.clusters):
                out.extend(b"\x00" * n)
            else:
                out.extend(self.clusters[cl][woff : woff + n])
            offset += n
            length -= n
        return bytes(out)


def _make_volume(disk):
    """Build a bare `NtfsVolume` skeleton sufficient for the compressed read
    path. Bypasses `__init__` (no boot sector / no MFT bootstrap)."""
    vol = NtfsVolume.__new__(NtfsVolume)
    vol.disk = disk
    vol.cluster_size = disk.cluster_size
    vol._lcn_shift_map = None
    vol.lcn_shift = 0
    vol._bpb_mft_lcn = None
    vol._cu_cache = None
    return vol


def _build_lznt1_constant_cu(byte_val: int, sub_count: int = 16) -> bytes:
    """Build a 64 KB LZNT1 stream representing `sub_count` 4 KB sub-blocks
    each filled with `byte_val`. Each sub-block is stored *compressed*
    (one literal + a chain of self-overlapping length-N backrefs)."""

    def _compressed_sub(b: int) -> bytes:
        body = bytearray()
        out_pos = 0
        while out_pos < 4096:
            flag_pos = len(body)
            body.append(0)
            flag = 0
            for bit in range(8):
                if out_pos >= 4096:
                    break
                if out_pos < 16:
                    lb = 4
                elif out_pos < 32:
                    lb = 5
                elif out_pos < 64:
                    lb = 6
                elif out_pos < 128:
                    lb = 7
                elif out_pos < 256:
                    lb = 8
                elif out_pos < 512:
                    lb = 9
                elif out_pos < 1024:
                    lb = 10
                elif out_pos < 2048:
                    lb = 11
                else:
                    lb = 12
                max_len = (1 << lb) - 1 + 3
                if out_pos == 0:
                    body.append(b)
                    out_pos += 1
                    continue
                length = min(max_len, 4096 - out_pos)
                bref = ((1 - 1) << lb) | (length - 3)
                body.append(bref & 0xFF)
                body.append((bref >> 8) & 0xFF)
                flag |= 1 << bit
                out_pos += length
            body[flag_pos] = flag
        return bytes(body)

    sub_body = _compressed_sub(byte_val)
    header_val = 0xB000 | (len(sub_body) - 1)
    sub = bytes([header_val & 0xFF, (header_val >> 8) & 0xFF]) + sub_body
    return sub * sub_count + b"\x00\x00"  # end marker


# ---------------------------------------------------------------------------
# LZNT1 tests
# ---------------------------------------------------------------------------


def test_lznt1_full_read():
    cs = 4096
    stream = _build_lznt1_constant_cu(ord("A"))
    stored_clusters = (len(stream) + cs - 1) // cs
    padded = stream + b"\x00" * (stored_clusters * cs - len(stream))

    disk = _ClusterDisk(n_clusters=64)
    for i in range(stored_clusters):
        disk.write_cluster(i, padded[i * cs : (i + 1) * cs])

    vol = _make_volume(disk)
    attr = _ParsedAttr(
        type=AT_DATA, name="", flags=ATTR_FLAG_COMPRESSED, non_resident=True
    )
    attr.real_size = 65536
    attr.init_size = 65536
    attr.alloc_size = 65536
    attr.compression_unit_size = 4
    attr.runs = [(stored_clusters, 0), (16 - stored_clusters, None)]

    data = vol._read_compressed_attr(attr, 0, 65536)
    assert data == b"A" * 65536, "full LZNT1 read mismatch"
    print("  [ok] LZNT1 full-CU read (65536 bytes)")


def test_lznt1_partial_and_cross_cu():
    cs = 4096
    stream = _build_lznt1_constant_cu(ord("A"))
    stored_clusters = (len(stream) + cs - 1) // cs
    padded = stream + b"\x00" * (stored_clusters * cs - len(stream))

    disk = _ClusterDisk(n_clusters=64)
    for i in range(stored_clusters):
        disk.write_cluster(i, padded[i * cs : (i + 1) * cs])
    # Place a 2nd identical CU starting at LCN 16
    for i in range(stored_clusters):
        disk.write_cluster(16 + i, padded[i * cs : (i + 1) * cs])

    vol = _make_volume(disk)
    attr = _ParsedAttr(
        type=AT_DATA, name="", flags=ATTR_FLAG_COMPRESSED, non_resident=True
    )
    attr.real_size = 131072
    attr.init_size = 131072
    attr.alloc_size = 131072
    attr.compression_unit_size = 4
    attr.runs = [
        (stored_clusters, 0),
        (16 - stored_clusters, None),
        (stored_clusters, 16),
        (16 - stored_clusters, None),
    ]

    chunk = vol._read_compressed_attr(attr, 1000, 5000)
    assert chunk == b"A" * 5000, "partial LZNT1 read mismatch"
    print("  [ok] LZNT1 partial read within CU")

    chunk = vol._read_compressed_attr(attr, 60000, 10000)
    assert chunk == b"A" * 10000, "cross-CU LZNT1 read mismatch"
    print("  [ok] LZNT1 cross-CU read")


def test_lznt1_init_size_cutoff():
    cs = 4096
    stream = _build_lznt1_constant_cu(ord("Z"))
    stored_clusters = (len(stream) + cs - 1) // cs
    padded = stream + b"\x00" * (stored_clusters * cs - len(stream))

    disk = _ClusterDisk(n_clusters=64)
    for i in range(stored_clusters):
        disk.write_cluster(i, padded[i * cs : (i + 1) * cs])

    vol = _make_volume(disk)
    attr = _ParsedAttr(
        type=AT_DATA, name="", flags=ATTR_FLAG_COMPRESSED, non_resident=True
    )
    # init_size cuts off at 1000 bytes
    attr.real_size = 65536
    attr.init_size = 1000
    attr.alloc_size = 65536
    attr.compression_unit_size = 4
    attr.runs = [(stored_clusters, 0), (16 - stored_clusters, None)]

    data = vol._read_compressed_attr(attr, 0, 65536)
    assert data[:1000] == b"Z" * 1000, "pre-init data wrong"
    assert data[1000:] == b"\x00" * (65536 - 1000), "post-init not zeroed"
    print("  [ok] LZNT1 honours init_size cutoff")


def test_lznt1_all_sparse_cu():
    """A CU with all-sparse runs decompresses to 64 KB of zeros."""
    disk = _ClusterDisk(n_clusters=16)
    vol = _make_volume(disk)
    attr = _ParsedAttr(
        type=AT_DATA, name="", flags=ATTR_FLAG_COMPRESSED, non_resident=True
    )
    attr.real_size = 65536
    attr.init_size = 65536
    attr.alloc_size = 65536
    attr.compression_unit_size = 4
    attr.runs = [(16, None)]
    data = vol._read_compressed_attr(attr, 0, 65536)
    assert data == b"\x00" * 65536
    print("  [ok] LZNT1 all-sparse CU")


def test_lznt1_uncompressed_cu():
    """A CU whose stored portion fills the full 16 clusters is treated as
    uncompressed (no LZNT1 decode)."""
    cs = 4096
    raw_cu = bytes(((i * 31337) & 0xFF) for i in range(65536))
    disk = _ClusterDisk(n_clusters=16)
    for i in range(16):
        disk.write_cluster(i, raw_cu[i * cs : (i + 1) * cs])
    vol = _make_volume(disk)
    attr = _ParsedAttr(
        type=AT_DATA, name="", flags=ATTR_FLAG_COMPRESSED, non_resident=True
    )
    attr.real_size = 65536
    attr.init_size = 65536
    attr.alloc_size = 65536
    attr.compression_unit_size = 4
    attr.runs = [(16, 0)]
    data = vol._read_compressed_attr(attr, 0, 65536)
    assert data == raw_cu, "uncompressed-CU passthrough wrong"
    print("  [ok] LZNT1 uncompressed-CU passthrough")


# ---------------------------------------------------------------------------
# WOF / Xpress tests
# ---------------------------------------------------------------------------


def test_wof_reparse_parser():
    # 20-byte WOF body: WOF_EXTERNAL_INFO (Ver=1, Provider=2) + FILE_PROVIDER_V1
    # (Ver=1, Algorithm=2 [Xpress8K], Flags=0)
    body = struct.pack("<IIIII", 1, 2, 1, 2, 0)
    content = struct.pack("<IHH", IO_REPARSE_TAG_WOF, len(body), 0) + body
    rec = _MftRecord(rec_num=1, in_use=True, is_dir=False, seq=1)
    NtfsVolume._maybe_parse_wof(rec, content)
    assert rec.wof_chunk_size == 8192
    assert rec.wof_algorithm == 2
    print("  [ok] WOF parser detects Xpress8K")

    # LZX (algorithm=1) — we record the algo but don't enable decompression
    body = struct.pack("<IIIII", 1, 2, 1, 1, 0)
    content = struct.pack("<IHH", IO_REPARSE_TAG_WOF, len(body), 0) + body
    rec = _MftRecord(rec_num=2, in_use=True, is_dir=False, seq=1)
    NtfsVolume._maybe_parse_wof(rec, content)
    assert rec.wof_chunk_size == 0
    assert rec.wof_algorithm == 1
    print("  [ok] WOF parser ignores LZX provider")

    # Non-WOF reparse tag → ignored
    content = struct.pack("<IHH", 0xA0000003, 0, 0)
    rec = _MftRecord(rec_num=3, in_use=True, is_dir=False, seq=1)
    NtfsVolume._maybe_parse_wof(rec, content)
    assert rec.wof_chunk_size == 0
    assert rec.wof_algorithm == -1
    print("  [ok] WOF parser ignores non-WOF reparse tags")


def test_wof_read_xpress4k_uncompressed_chunks():
    """Build a WOF payload with chunks stored uncompressed (the WOF spec
    allows this when comp_len == uc_len) and verify the read path slices."""
    plain = b"A" * 8192  # 2 chunks of 4 KB
    table = struct.pack("<I", 4096)  # offset of chunk[1] = 4096
    payload = table + plain

    # Sanity-check the standalone xpress decompressor first
    out = xpress.decompress(payload, len(plain), chunk_size=4096)
    assert out == plain

    class _Disk:
        cluster_size = 4096

        def read(self, off, n):
            return b"\x00" * n

    vol = _make_volume(_Disk())
    sparse_data = _ParsedAttr(type=AT_DATA, name="", flags=0, non_resident=True)
    sparse_data.real_size = 8192
    sparse_data.init_size = 8192
    sparse_data.alloc_size = 8192
    sparse_data.runs = [(2, None)]

    wof_ads = _ParsedAttr(
        type=AT_DATA, name="WofCompressedData", flags=0, non_resident=False
    )
    wof_ads.content = payload

    rec = _MftRecord(rec_num=42, in_use=True, is_dir=False, seq=1)
    rec.attrs = [sparse_data, wof_ads]
    rec.wof_chunk_size = 4096
    rec.wof_uncompressed_size = 8192
    rec.wof_algorithm = 0

    assert vol._read_wof(rec, 0, -1) == plain
    assert vol._read_wof(rec, 100, 500) == plain[100:600]
    assert vol._read_wof(rec, 8000, 1000) == plain[8000:8192]
    print("  [ok] WOF read with Xpress4K (uncompressed chunks)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("LZNT1 attribute-read integration:")
    test_lznt1_full_read()
    test_lznt1_partial_and_cross_cu()
    test_lznt1_init_size_cutoff()
    test_lznt1_all_sparse_cu()
    test_lznt1_uncompressed_cu()
    print("WOF / Xpress integration:")
    test_wof_reparse_parser()
    test_wof_read_xpress4k_uncompressed_chunks()
    print("All compression-integration tests passed.")


if __name__ == "__main__":
    main()
