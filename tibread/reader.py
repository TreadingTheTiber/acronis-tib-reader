#!/usr/bin/env python3
"""
tibreader - random-access partition reader for sector-by-sector TIB files.

Format model (verified):
- Each block covers 128 fixed clusters (LCNs N*128 .. N*128+127) of 4096 bytes
- 16-byte preamble = 128-bit bitmap; bit i set iff LCN (N*128 + i) is stored
- Decompressed block contains exactly the present clusters in LCN order
- Sparse (bit-clear) clusters return zeros at runtime

Reader exposes read(offset, length) over the FULL original partition layout
(including sparse zeros). Backed by a precomputed block index from tibindex.py.
"""
import os
import struct
import zlib
import threading
from collections import OrderedDict

VOLUME_HEADER_LEN = 32
PREAMBLE_LEN = 16
CLUSTER_SIZE = 4096
CLUSTERS_PER_BLOCK = 128
BLOCK_SIZE = CLUSTER_SIZE * CLUSTERS_PER_BLOCK  # 524288
INDEX_MAGIC = b"TIBIDX02"
INDEX_REC_SIZE = 28  # u64 file_offset, 16 bytes preamble, u32 comp_len


class LRUCache:
    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self.data = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            if key in self.data:
                self.data.move_to_end(key)
                return self.data[key]
        return None

    def put(self, key, value):
        with self.lock:
            self.data[key] = value
            self.data.move_to_end(key)
            while len(self.data) > self.maxsize:
                self.data.popitem(last=False)


class TibReader:
    """Random-access reader exposing the original partition image."""

    def __init__(self, tib_path: str, index_path: str, cache_blocks: int = 128):
        self.tib_path = tib_path
        # Memory-map the index for cheap access
        with open(index_path, "rb") as f:
            magic = f.read(8)
            if magic != INDEX_MAGIC:
                raise ValueError(f"bad index magic: {magic.hex()}")
            self.tib_size, self.data_start, self.data_end, self.block_count = \
                struct.unpack("<QQQQ", f.read(32))
            self.records_blob = f.read(self.block_count * INDEX_REC_SIZE)
        if len(self.records_blob) != self.block_count * INDEX_REC_SIZE:
            raise ValueError("truncated index")
        # Each block covers 128 LCNs starting at (block_idx * 128). Total partition
        # size in clusters = block_count * 128.
        self.partition_size = self.block_count * BLOCK_SIZE
        # Open file handle per thread (for FUSE multi-threaded reads)
        self._tls = threading.local()
        self.cache = LRUCache(cache_blocks)

    def _file(self):
        if not hasattr(self._tls, "f"):
            self._tls.f = open(self.tib_path, "rb")
        return self._tls.f

    def _get_record(self, block_idx: int):
        """Returns (file_offset, preamble_bytes, comp_len) for block block_idx."""
        if block_idx < 0 or block_idx >= self.block_count:
            raise IndexError(f"block {block_idx} out of range [0, {self.block_count})")
        off = block_idx * INDEX_REC_SIZE
        return struct.unpack_from("<Q16sI", self.records_blob, off)

    def _decompress_block(self, block_idx: int) -> bytes:
        """Returns the full decompressed block (only present clusters concatenated)."""
        cached = self.cache.get(block_idx)
        if cached is not None:
            return cached
        file_off, preamble, comp_len = self._get_record(block_idx)
        f = self._file()
        f.seek(file_off + PREAMBLE_LEN)
        comp_data = f.read(comp_len - PREAMBLE_LEN)
        decomp = zlib.decompressobj()
        out = decomp.decompress(comp_data)
        # Trust trail-bytes; nothing more to do
        self.cache.put(block_idx, out)
        return out

    def _block_preamble(self, block_idx: int) -> bytes:
        _, preamble, _ = self._get_record(block_idx)
        return preamble

    @staticmethod
    def _bit_set(preamble: bytes, lcn_in_block: int) -> bool:
        return bool(preamble[lcn_in_block >> 3] & (1 << (lcn_in_block & 7)))

    @staticmethod
    def _popcount_before(preamble: bytes, lcn_in_block: int) -> int:
        """Count set bits in preamble for positions 0..lcn_in_block-1."""
        if lcn_in_block <= 0:
            return 0
        full_bytes = lcn_in_block >> 3
        partial_bits = lcn_in_block & 7
        c = 0
        for i in range(full_bytes):
            c += bin(preamble[i]).count("1")
        if partial_bits:
            mask = (1 << partial_bits) - 1
            c += bin(preamble[full_bytes] & mask).count("1")
        return c

    def read_cluster(self, lcn: int) -> bytes:
        """Read one cluster (4096 bytes) at LCN. Returns zeros if sparse or out of range."""
        block_idx = lcn // CLUSTERS_PER_BLOCK
        if block_idx >= self.block_count:
            return b"\x00" * CLUSTER_SIZE
        local = lcn % CLUSTERS_PER_BLOCK
        preamble = self._block_preamble(block_idx)
        if not self._bit_set(preamble, local):
            return b"\x00" * CLUSTER_SIZE
        position = self._popcount_before(preamble, local)
        block = self._decompress_block(block_idx)
        return block[position * CLUSTER_SIZE : (position + 1) * CLUSTER_SIZE]

    def read(self, offset: int, length: int) -> bytes:
        """Read `length` bytes starting at `offset` of the original partition image.
        Sparse regions return zeros. Reads past partition end are clipped."""
        if offset < 0:
            raise ValueError("negative offset")
        if length <= 0:
            return b""
        end = min(offset + length, self.partition_size)
        if end <= offset:
            return b""

        out = bytearray(end - offset)
        out_pos = 0
        cur = offset
        while cur < end:
            cluster = cur // CLUSTER_SIZE
            in_cluster = cur % CLUSTER_SIZE
            block_idx = cluster // CLUSTERS_PER_BLOCK
            local = cluster % CLUSTERS_PER_BLOCK

            if block_idx >= self.block_count:
                # Beyond indexed area = sparse zeros
                take = end - cur
                cur += take
                out_pos += take
                continue

            preamble = self._block_preamble(block_idx)
            if not self._bit_set(preamble, local):
                # Sparse cluster: zeros
                take = min(CLUSTER_SIZE - in_cluster, end - cur)
                # out is already zero-init, just advance
                cur += take
                out_pos += take
                continue

            # Present cluster. Decompress block (cached) and copy required slice.
            position = self._popcount_before(preamble, local)
            block = self._decompress_block(block_idx)
            cluster_data = block[position * CLUSTER_SIZE : (position + 1) * CLUSTER_SIZE]
            take = min(CLUSTER_SIZE - in_cluster, end - cur)
            out[out_pos : out_pos + take] = cluster_data[in_cluster : in_cluster + take]
            cur += take
            out_pos += take
        return bytes(out)


def cmd_info(idx_path: str):
    with open(idx_path, "rb") as f:
        magic = f.read(8)
        tib_size, data_start, data_end, block_count = struct.unpack("<QQQQ", f.read(32))
    print(f"Index: {idx_path}")
    print(f"  magic: {magic}")
    print(f"  tib_file_size: {tib_size:,}")
    print(f"  data range: [{data_start:,} .. {data_end:,})")
    print(f"  block count: {block_count:,}")
    print(f"  partition size (clusters * 4096): {block_count * BLOCK_SIZE:,} (~{block_count * BLOCK_SIZE / 1024**4:.2f} TiB)")


def cmd_dump(tib: str, idx: str, offset: int, length: int, out: str):
    r = TibReader(tib, idx)
    print(f"partition_size: {r.partition_size:,}")
    data = r.read(offset, length)
    with open(out, "wb") as f:
        f.write(data)
    print(f"wrote {len(data):,} bytes to {out}")


def cmd_stat(tib: str, idx: str):
    """Print stats: how many clusters are stored vs sparse, etc."""
    r = TibReader(tib, idx)
    total_present = 0
    for i in range(r.block_count):
        _, preamble, _ = r._get_record(i)
        total_present += sum(bin(b).count("1") for b in preamble)
    total_clusters = r.block_count * CLUSTERS_PER_BLOCK
    print(f"blocks: {r.block_count:,}")
    print(f"clusters total: {total_clusters:,}")
    print(f"clusters present: {total_present:,}")
    print(f"clusters sparse:  {total_clusters - total_present:,}")
    print(f"present fraction: {total_present / total_clusters * 100:.2f}%")
    print(f"stored bytes: {total_present * CLUSTER_SIZE:,}")
    print(f"partition size (full): {total_clusters * CLUSTER_SIZE:,}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: tibreader.py info <idx>")
        print("       tibreader.py stat <tib> <idx>")
        print("       tibreader.py dump <tib> <idx> <offset> <length> <out>")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "info":
        cmd_info(sys.argv[2])
    elif cmd == "stat":
        cmd_stat(sys.argv[2], sys.argv[3])
    elif cmd == "dump":
        cmd_dump(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6])
    else:
        print(f"unknown: {cmd}")
        sys.exit(1)
