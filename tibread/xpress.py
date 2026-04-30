"""
Pure-Python Xpress Huffman decompressor (MS-XCA spec) for WOF support.

This is the variant used by Windows Overlay Filter (WOF) / "Compact OS" to
transparently compress files in WinSxS, Program Files, etc. on Windows 10/11.

Three WOF compression formats use Xpress Huffman:
    Xpress4K   (chunk size 4096)
    Xpress8K   (chunk size 8192)
    Xpress16K  (chunk size 16384)
The fourth WOF format, LZX (chunk 32768), is a different algorithm.

Format reference:
    [MS-XCA] "Xpress Compression Algorithm" — section 2.2 "Xpress Compression
    with Huffman Encoding" (LZ77 + Canonical Prefix Code).

Cross-checked against Acronis True Image's xpress_decompressor.cpp (decompiled
from product.bin, functions FUN_0839e500..FUN_0839e940). Acronis's symbols:
    ReadSymbols, BuildHuffmanTable, HuffmanDecoder, PopBytes, PopBits,
    DecompressImpl, CheckTree.

Per-chunk wire format
---------------------
1. 256 bytes: code-length table. 512 symbols (0..511); each symbol's length
   stored as 4 bits little-endian-nibble-packed (low nibble = even-index
   symbol, high nibble = odd-index symbol). Length 0 = symbol unused.
2. Bitstream: a sequence of 16-bit little-endian words. Bits within the
   current 32-bit "window" are consumed MSB-first; the window is refilled
   16 bits at a time from the next u16-LE word.
3. Symbols decoded one-by-one until output buffer is filled:
     symbol < 256        -> literal byte
     256 <= symbol < 512 -> match
        len_nibble  =  symbol        & 0x0F
        offset_bits = (symbol >> 4)  & 0x0F   (in 0..15)
        if len_nibble == 15:
            extra = read_byte()
            if extra == 255:
                len_nibble = read_u16_le() - 15  # may go negative? see spec
            else:
                len_nibble = extra + 15
        match_length = len_nibble + 3
        match_offset = (1 << offset_bits) + read_bits(offset_bits)
        # copy match_length bytes from output[pos-offset:] (overlap allowed)

The chunk completes when the output reaches its expected size (4K / 8K / 16K
typically; the last chunk of a file may be shorter).

Bit endianness gotcha
---------------------
The "PopBits" routine in Acronis's code uses a 32-bit shift register where
high bits are the next-to-be-consumed bits, and the register is refilled
from the *next* u16-LE word into the *low* 16 bits when fewer than 16 bits
remain. This matches the MS-XCA spec.

Bytes consumed by `read_byte()` / `read_u16_le()` are pulled from a
*separate* byte cursor that is independent of the bit cursor. The byte
cursor advances through the input in order; bit reads have already
pre-loaded their words. (The Acronis code keeps a `byte_pos` and a
`buffered_word` separately.)
"""

from __future__ import annotations

from typing import Tuple


class XpressError(Exception):
    pass


# ---------------------------------------------------------------------------
# Canonical prefix-code table builder
# ---------------------------------------------------------------------------

# We build a fast decode table indexed by the next 15 bits of the bitstream
# (max code length is 15). Each entry stores (symbol, code_length).
_LOOKUP_BITS = 15
_LOOKUP_SIZE = 1 << _LOOKUP_BITS


def _build_decode_table(code_lengths: list[int]) -> list[Tuple[int, int]]:
    """Build a flat lookup table for canonical Huffman decoding.

    Returns a list of length 2**15. Each entry is (symbol, code_length).
    Lookup: peek 15 bits MSB-first, index, consume `code_length` bits.

    Canonical-prefix construction (per MS-XCA / DEFLATE-style):
      - Codes are assigned in order of (length, symbol).
      - The shortest codes get the smallest numeric values.
    """
    n = len(code_lengths)
    # Bucket symbols by length.
    by_len: list[list[int]] = [[] for _ in range(16)]
    for sym, ln in enumerate(code_lengths):
        if ln:
            if ln > 15:
                raise XpressError(f"invalid code length {ln} for symbol {sym}")
            by_len[ln].append(sym)

    # Verify Kraft's inequality (allows incomplete codes; MS-XCA permits this
    # in valid streams - but a code overrun would produce nonsense. We just
    # check it doesn't *exceed* 1.)
    total = sum(len(by_len[L]) * (1 << (15 - L)) for L in range(1, 16))
    if total > _LOOKUP_SIZE:
        raise XpressError("Huffman code lengths over-subscribed")

    table = [(0, 0)] * _LOOKUP_SIZE
    code = 0
    for length in range(1, 16):
        syms = by_len[length]
        # Number of lookup entries each code of this length covers:
        span = 1 << (15 - length)
        for sym in syms:
            # The actual `length`-bit code, MSB-aligned to 15 bits:
            base = code << (15 - length)
            for i in range(span):
                table[base + i] = (sym, length)
            code += 1
        code <<= 1  # shift for next length level
    return table


def _read_code_lengths(src: bytes, off: int) -> list[int]:
    """Read 256 bytes of nibble-packed code lengths -> list[512] of int."""
    if off + 256 > len(src):
        raise XpressError("input too short for Huffman code-length table")
    lengths = [0] * 512
    for i in range(256):
        b = src[off + i]
        lengths[2 * i + 0] = b & 0x0F
        lengths[2 * i + 1] = (b >> 4) & 0x0F
    return lengths


# ---------------------------------------------------------------------------
# Bitstream reader
# ---------------------------------------------------------------------------


class _BitStream:
    """Xpress Huffman bitstream reader.

    Holds the input buffer, a bit cursor (16-bit-word aligned) for `pop_bits`,
    and a separate byte cursor for `pop_bytes` (used to read extended match
    lengths). The two cursors share the input buffer but advance separately;
    the spec orders bit-word reads ahead of byte reads via the way the
    encoder lays them out (extended-length bytes are interleaved between
    bit words at well-defined points). In practice, a single cursor
    suffices because PopBytes is only called after the symbol triggering
    the extended-length path was decoded, and the encoder placed those
    raw bytes immediately after the most recent fully-consumed 16-bit word
    boundary.

    The Acronis decompile shows ONE input cursor (`param_1[2]`) used by
    BOTH PopBytes (reads 1 or 2 bytes) and the bit-refill (reads 2 bytes).
    The bit register holds up to 32 bits; when bits-buffered drops below 16
    a u16 is pulled from the cursor. PopBytes simply pulls 1 or 2 bytes
    from the same cursor without aligning.

    That means: extended-length bytes are encoded by the writer EXACTLY at
    the point in the byte stream where the decoder will be when it asks
    for them - i.e., just after the writer flushed its pending bit-word.
    The encoder cooperates by flushing on extended-length emission.
    """

    __slots__ = ("buf", "buf_end", "cursor", "reg", "nbits")

    def __init__(self, buf: bytes, start: int, end: int):
        self.buf = buf
        self.buf_end = end
        self.cursor = start
        self.reg = 0      # right-aligned bit register; bits are consumed from the high end
        self.nbits = 0    # number of valid bits currently in `reg`
        # Prime the register with two u16-LE words (32 bits total).
        self._refill_word()
        self._refill_word()

    def _refill_word(self) -> None:
        """Pull one u16-LE word into the LOW 16 bits of the next free slot."""
        if self.cursor + 2 > self.buf_end:
            # Out of data — pad with zeros (matches Acronis: it tolerates an
            # output-driven loop and only errors via OOB-output checks).
            w = 0
            self.cursor = self.buf_end  # don't read past end
        else:
            w = self.buf[self.cursor] | (self.buf[self.cursor + 1] << 8)
            self.cursor += 2
        # Place w into reg at position (32 - nbits - 16) so bits stack from MSB.
        # I.e., we shift the existing bits left to make room? No — easier:
        # treat reg as MSB-first stream of nbits bits already, then OR in
        # the new word at bit positions (16 - nbits ... 31 - nbits).
        # Since we maintain `reg` left-aligned (bits used live in the HIGH
        # portion of a 32-bit value), we insert a new word into the low
        # 16-bit slot just below the current high portion.
        #
        # Concretely: reg stores `nbits` valid bits, MSB-first, in bits
        # [31 .. 32-nbits]. A refill places a new word in bits
        # [31-nbits .. 16-nbits], leaving the bottom (16-nbits) bits unused.
        self.reg |= (w & 0xFFFF) << (16 - self.nbits)
        self.reg &= 0xFFFFFFFF
        self.nbits += 16

    def peek15(self) -> int:
        """Return the next 15 bits, MSB-aligned (right-justified in the
        return value)."""
        if self.nbits < 15:
            self._refill_word()
        return (self.reg >> 17) & 0x7FFF

    def consume(self, n: int) -> None:
        if n > self.nbits:
            self._refill_word()
            if n > self.nbits:
                # extreme tail case
                self._refill_word()
        self.reg = (self.reg << n) & 0xFFFFFFFF
        self.nbits -= n
        if self.nbits < 16:
            self._refill_word()

    def pop_bits(self, n: int) -> int:
        """Consume and return n bits (0 <= n <= 16), MSB-first."""
        if n == 0:
            return 0
        if self.nbits < n:
            self._refill_word()
        v = (self.reg >> (32 - n)) & ((1 << n) - 1)
        self.reg = (self.reg << n) & 0xFFFFFFFF
        self.nbits -= n
        if self.nbits < 16:
            self._refill_word()
        return v

    def pop_byte(self) -> int:
        if self.cursor >= self.buf_end:
            raise XpressError("unexpected end of input in pop_byte")
        b = self.buf[self.cursor]
        self.cursor += 1
        return b

    def pop_u16_le(self) -> int:
        if self.cursor + 2 > self.buf_end:
            raise XpressError("unexpected end of input in pop_u16_le")
        v = self.buf[self.cursor] | (self.buf[self.cursor + 1] << 8)
        self.cursor += 2
        return v


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decompress_chunk(src: bytes, src_off: int, src_len: int,
                     uncompressed_size: int) -> bytes:
    """Decompress a single Xpress-Huffman chunk.

    `src[src_off : src_off+src_len]` is the compressed chunk (includes
    the 256-byte code-length table at the start). `uncompressed_size`
    is the expected output size for this chunk.

    Returns a `bytes` of length `uncompressed_size`.
    """
    if src_off + src_len > len(src):
        raise XpressError("chunk extent out of bounds")
    if src_len < 256:
        raise XpressError("chunk too small to hold Huffman table")

    code_lengths = _read_code_lengths(src, src_off)
    table = _build_decode_table(code_lengths)
    bs = _BitStream(src, src_off + 256, src_off + src_len)

    out = bytearray(uncompressed_size)
    pos = 0

    while pos < uncompressed_size:
        sym, ln = table[bs.peek15()]
        if ln == 0:
            raise XpressError(f"undefined Huffman code at out pos {pos}")
        bs.consume(ln)

        if sym < 256:
            out[pos] = sym
            pos += 1
            continue

        # Match.
        sym -= 256
        len_nibble = sym & 0x0F
        offset_bits = (sym >> 4) & 0x0F

        # Match length encoding (per Acronis xpress_decompressor.cpp /
        # FUN_0839e940 and MS-XCA spec):
        #   nibble != 15            -> len = nibble + 3
        #   nibble == 15, byte<255  -> len = byte + 15 + 3
        #   nibble == 15, byte==255 -> len = u16_le + 3   (the 0xff byte
        #                              is the escape; the actual length
        #                              is the *next* u16-LE in the byte
        #                              stream)
        if len_nibble == 15:
            extra = bs.pop_byte()
            if extra < 255:
                match_len = extra + 15 + 3
            else:
                match_len = bs.pop_u16_le() + 3
        else:
            match_len = len_nibble + 3

        if offset_bits:
            offset = (1 << offset_bits) + bs.pop_bits(offset_bits)
        else:
            offset = 1  # offset_bits==0 means offset = 1<<0 = 1 (literal "rep prev byte")

        if offset > pos:
            raise XpressError(
                f"match offset {offset} exceeds current output position {pos}")
        if pos + match_len > uncompressed_size:
            raise XpressError(
                f"match length {match_len} overruns output (pos={pos}, "
                f"size={uncompressed_size})")

        # Byte-by-byte copy (overlap allowed - LZ77 RLE behaviour).
        src_pos = pos - offset
        for i in range(match_len):
            out[pos + i] = out[src_pos + i]
        pos += match_len

    return bytes(out)


def decompress(src: bytes, uncompressed_size: int,
               chunk_size: int | None = None) -> bytes:
    """Decompress a multi-chunk Xpress Huffman stream as used by WOF.

    Args:
        src: the contents of the :WofCompressedData ADS *AFTER* the WOF
            file-info header (i.e., raw compressed payload starting with
            the chunk offset table).
        uncompressed_size: the original file size from the FILE_PROVIDER
            reparse-point header.
        chunk_size: 4096 / 8192 / 16384 (Xpress flavour). Required.

    Wire layout of `src`:
        chunk_offset_table:  array of (nchunks - 1) entries; each entry is
                             a u32 (when uncompressed_size <= 4 GiB) or u64
                             (otherwise) giving the *byte offset* of the
                             start of that chunk's compressed data, relative
                             to the start of the *first* chunk's data
                             (i.e., relative to the byte just after this
                             chunk-offset table).
        chunk[0] data:       starts at offset `chunk_table_size` from src[0]
        chunk[i] data:       starts at chunk_table_size + offsets[i-1]

        Each chunk's data is the 256-byte Huffman table + bitstream.

        Special case: if a chunk's compressed size equals the chunk's
        uncompressed size (chunk_size, or last-chunk leftover), the chunk
        is stored UNCOMPRESSED (no Huffman table).
    """
    if chunk_size not in (4096, 8192, 16384):
        raise XpressError(f"invalid chunk size {chunk_size!r}")

    nchunks = (uncompressed_size + chunk_size - 1) // chunk_size
    if nchunks == 0:
        return b""

    entry_size = 8 if uncompressed_size > 0xFFFF_FFFF else 4
    chunk_table_size = (nchunks - 1) * entry_size

    if len(src) < chunk_table_size:
        raise XpressError("input too short for chunk offset table")

    # Parse offsets relative to `chunk_data_base`.
    offsets = [0]
    if entry_size == 4:
        for i in range(nchunks - 1):
            o = int.from_bytes(src[i * 4:(i + 1) * 4], "little")
            offsets.append(o)
    else:
        for i in range(nchunks - 1):
            o = int.from_bytes(src[i * 8:(i + 1) * 8], "little")
            offsets.append(o)
    chunk_data_base = chunk_table_size

    out = bytearray(uncompressed_size)

    for ci in range(nchunks):
        start = chunk_data_base + offsets[ci]
        if ci + 1 < nchunks:
            end = chunk_data_base + offsets[ci + 1]
        else:
            end = len(src)

        if ci + 1 < nchunks:
            uc_this = chunk_size
        else:
            uc_this = uncompressed_size - ci * chunk_size

        comp_len = end - start
        if comp_len == uc_this:
            # Stored uncompressed.
            out[ci * chunk_size:ci * chunk_size + uc_this] = src[start:end]
        else:
            chunk_plain = decompress_chunk(src, start, comp_len, uc_this)
            out[ci * chunk_size:ci * chunk_size + uc_this] = chunk_plain

    return bytes(out)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _ms_xca_vec1() -> tuple[bytes, bytes]:
    """[MS-XCA] sample 1: literals-only 'abcdefghijklmnopqrstuvwxyz'.

    From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca
    section "LZ77+Huffman" — example 1 (all literals).
    """
    hex_bytes = (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "50 55 55 55 55 55 55 55 55 55 55 45 44 04 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 "
        "00 00 00 00"
    )
    compressed = bytes.fromhex(hex_bytes.replace(" ", ""))
    plaintext = b"abcdefghijklmnopqrstuvwxyz"
    return compressed, plaintext


def _ms_xca_vec2() -> tuple[bytes, bytes]:
    """[MS-XCA] sample 2: 'abc' x 100 = 300-byte plaintext, exercises long match path.

    Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca,
    section 'LZ77+Huffman'. Nonzero code-length-table positions (one nibble
    each per symbol, low-nibble-first packing into bytes):
        byte 48  = 0x30 -> sym  97 ('a') length 3
        byte 49  = 0x23 -> sym  98 ('b') length 3, sym  99 ('c') length 2
        byte 128 = 0x02 -> sym 256 (EOF) length 2
        byte 143 = 0x20 -> sym 287 (match escape) length 2
    Tail bitstream: a8 dc 00 00 ff 26 01
        First u16 LE  = 0xdca8 = 0b1101110010101000
            bits decode as: 110 (a) 111 (b) 00 (c) 10 (sym 287) 1 (offset bit)
            (offset_bits=1, raw=1 -> offset = 2 + 1 = 3)
            length escape: nibble=15 -> read byte 0xff -> read u16 0x0126 = 294
            -> length = 294 + 3 = 297 (matches spec note '0x126 = 294 = 297-3')
        Then EOF (sym 256) symbol decoded but loop already terminated.
    """
    table = bytearray(256)
    table[48] = 0x30   # 'a' length 3
    table[49] = 0x23   # 'b' length 3, 'c' length 2
    table[128] = 0x02  # EOF (sym 256) length 2
    table[143] = 0x20  # match-escape sym 287 length 2
    tail = bytes.fromhex("a8dc0000ff2601")
    return bytes(table) + tail, b"abc" * 100


def _selftest() -> None:
    """Quick sanity tests:

    1. Decode-table builder round-trip on a hand-built canonical code.
    2. End-to-end round-trip via the simplest possible encoder we
       implement inline (literals only, all-length-8 codes).
    """
    import sys

    # Test 1: code-length table parser.
    raw = bytes([0x12, 0x34])  # nibbles: low=2 high=1, low=4 high=3
    parsed = _read_code_lengths(raw + b"\x00" * 254, 0)
    assert parsed[0] == 2 and parsed[1] == 1
    assert parsed[2] == 4 and parsed[3] == 3
    assert all(p == 0 for p in parsed[4:])
    print("  [ok] code-length table parser")

    # Test 2: literal-only round trip.
    # Build a chunk where every byte 0..255 has 8-bit code (length 8 for
    # symbols 0..255; length 0 for everything else 256..511). Then encode
    # the canonical 8-bit codes (which for an 8-bit complete code over 256
    # symbols is just symbol == code value).
    #
    # Canonical lengths-of-8 over 256 symbols: codes 0..255 in numeric
    # order. So symbol `s` has code value `s` represented in 8 bits MSB-first.
    #
    # Code-length table: every symbol 0..255 -> 8; every symbol 256..511 -> 0.
    code_lengths = [8] * 256 + [0] * 256
    nibbles = bytearray(256)
    for sym, ln in enumerate(code_lengths):
        byte_idx = sym // 2
        if sym % 2 == 0:
            nibbles[byte_idx] |= ln & 0x0F
        else:
            nibbles[byte_idx] |= (ln & 0x0F) << 4

    # Plaintext to encode:
    plain = b"Hello, Xpress Huffman!" * 16  # 352 bytes
    # Bitstream: each byte b emits 8 bits = b itself (canonical assignment).
    # Pack as u16-LE words, MSB-first within each word.
    bits: list[int] = []
    for b in plain:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    # Pad to multiple of 16.
    while len(bits) % 16:
        bits.append(0)
    words = []
    for i in range(0, len(bits), 16):
        w = 0
        for j in range(16):
            w = (w << 1) | bits[i + j]
        # MSB-first within the word means the FIRST bit emitted lives in
        # bit 15 of `w`. Now emit as little-endian u16: low byte first.
        words.append(w & 0xFF)
        words.append((w >> 8) & 0xFF)
    chunk = bytes(nibbles) + bytes(words)

    out = decompress_chunk(chunk, 0, len(chunk), len(plain))
    assert out == plain, f"literal round-trip failed: {out[:40]!r} vs {plain[:40]!r}"
    print(f"  [ok] literal-only round trip ({len(plain)} bytes)")

    # Test 3: official Microsoft MS-XCA test vector 1 (literals only).
    comp, plain = _ms_xca_vec1()
    out = decompress_chunk(comp, 0, len(comp), len(plain))
    assert out == plain, f"MS vec1 mismatch: {out!r} vs {plain!r}"
    print(f"  [ok] MS-XCA vector 1 (literals, {len(plain)} bytes)")

    # Test 4: official Microsoft MS-XCA test vector 2 (long-match escape path).
    comp, plain = _ms_xca_vec2()
    out = decompress_chunk(comp, 0, len(comp), len(plain))
    assert out == plain, (
        f"MS vec2 mismatch:\n got: {out[:60]!r}...\n exp: {plain[:60]!r}...")
    print(f"  [ok] MS-XCA vector 2 (long match, {len(plain)} bytes)")

    print("xpress.py self-tests passed")


if __name__ == "__main__":
    _selftest()
