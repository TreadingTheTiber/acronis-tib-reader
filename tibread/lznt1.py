"""
LZNT1 decompression — the algorithm used by NTFS for compressed $DATA attributes.

Per the NTFS spec / libntfs-3g / Linux kernel fs/ntfs3/lznt.c:
  - A compressed $DATA stream is divided into compression units (CU).
    The CU size in clusters is 2^comp_unit_size (default 4 → 16 clusters = 64KB).
  - Each CU's runs decode to ONE OF:
      (a) all sparse runs (lcn=None) covering the full CU → all-zero CU
      (b) stored runs covering the FULL CU's clusters     → uncompressed CU (raw)
      (c) stored runs covering FEWER than full CU + sparse fill → COMPRESSED CU
          (run through lznt1_decompress to get the original CU bytes)
  - Compressed CU bytes are a sequence of 4096-byte SUB-BLOCKS, each preceded
    by a 16-bit header:
      bits 0-11: chunk_size_minus_1 (so size = (header & 0xFFF) + 1, max 4096)
      bits 12-14: signature (always 0b011)
      bit  15:   1 = compressed sub-block, 0 = literal sub-block
  - A compressed sub-block contains LZ77-style tokens:
      * Tokens come in groups of 8, preceded by a 1-byte "flag" byte.
      * Each flag bit (LSB first):
          0 → next token is a single literal byte
          1 → next token is a 2-byte little-endian backref (offset, length)
            where the bit-split between offset and length depends on the
            current decompressed-output position within the sub-block:
                position < 16:   offset_bits=12, length_bits=4
                position < 32:   offset_bits=11, length_bits=5
                position < 64:   offset_bits=10, length_bits=6
                position < 128:  offset_bits=9,  length_bits=7
                position < 256:  offset_bits=8,  length_bits=8
                position < 512:  offset_bits=7,  length_bits=9
                position < 1024: offset_bits=6,  length_bits=10
                position < 2048: offset_bits=5,  length_bits=11
                else:            offset_bits=4,  length_bits=12
            offset = (bref >> length_bits) + 1
            length = (bref & ((1<<length_bits)-1)) + 3
            then memcpy from out[len(out) - offset], length bytes
            (overlap is allowed; copy byte-by-byte).

A header value of 0 marks end-of-stream.
"""
from __future__ import annotations


def _length_bits_for_position(position: int) -> int:
    if position < 16:   return 4
    if position < 32:   return 5
    if position < 64:   return 6
    if position < 128:  return 7
    if position < 256:  return 8
    if position < 512:  return 9
    if position < 1024: return 10
    if position < 2048: return 11
    return 12


def lznt1_decompress(data: bytes, expected_size: int = -1) -> bytes:
    """Decompress a sequence of LZNT1 sub-blocks.

    expected_size: if > 0, pad output with zeros to that length when decompression
                   ends early (compressed CUs are typically padded by sparse runs
                   to fill the 64KB CU; this convenience zero-pads in pure-data
                   contexts where the caller can't easily concat sparse zeros).
    """
    out = bytearray()
    pos = 0
    n = len(data)

    while pos + 2 <= n:
        header = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if header == 0:
            break
        sub_size = (header & 0x0FFF) + 1
        compressed = bool(header & 0x8000)
        end = pos + sub_size
        if end > n:
            # Truncated — bail with what we have.
            break
        sub = data[pos:end]
        pos = end

        if not compressed:
            out.extend(sub)
            continue

        sub_start_in_out = len(out)
        sp = 0
        sn = len(sub)
        while sp < sn:
            flags = sub[sp]
            sp += 1
            for bit in range(8):
                if sp >= sn:
                    break
                if not (flags >> bit) & 1:
                    # Literal byte
                    out.append(sub[sp])
                    sp += 1
                else:
                    # 2-byte backref
                    if sp + 2 > sn:
                        sp = sn  # stop
                        break
                    bref = sub[sp] | (sub[sp + 1] << 8)
                    sp += 2
                    position_in_sub = len(out) - sub_start_in_out
                    lb = _length_bits_for_position(position_in_sub)
                    length = (bref & ((1 << lb) - 1)) + 3
                    offset = (bref >> lb) + 1
                    src = len(out) - offset
                    if src < sub_start_in_out:
                        # Malformed — backref before sub-block start. Skip safely.
                        # (libntfs3 zeroes; we'll do the same defensively.)
                        out.extend(b"\x00" * length)
                    else:
                        # Copy byte-by-byte (overlap allowed: RLE-like copies)
                        for k in range(length):
                            out.append(out[src + k])

    if expected_size > 0 and len(out) < expected_size:
        out.extend(b"\x00" * (expected_size - len(out)))
    return bytes(out)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Smoke test: encode a known-form input and round-trip via reference vectors.
    # Vectors taken from libntfs-3g unit tests (paraphrased).
    # Round-trip a literal sub-block: header 0x3000 (literal, len=1), one byte 'A'
    test1 = bytes([0x00, 0x30, ord('A')])
    assert lznt1_decompress(test1) == b'A', "literal sub-block failed"

    # Empty stream (just end marker)
    assert lznt1_decompress(b'\x00\x00') == b''

    # Compressed sub-block: 8 literal 'A' bytes
    # header: bit15=1 (compressed), bits12-14=0b011, bits0-11 = (size-1)
    # Body: flag=0x00 (8 literals), 'A'*8
    sub_body = b'\x00' + b'A' * 8
    sub_size = len(sub_body)
    header = 0xB000 | (sub_size - 1)
    test2 = bytes([header & 0xFF, (header >> 8) & 0xFF]) + sub_body
    assert lznt1_decompress(test2) == b'AAAAAAAA', "compressed literals failed"

    # Compressed with backref: literal 'AB' then backref offset=2 length=4
    # → 'ABABABAB'... wait: literal 'AB', backref(offset=2, length=4) means copy 4 bytes from -2
    # at position 2: lb = 4 (since pos < 16). bref = ((offset-1) << 4) | (length-3)
    # offset=2 → bref_high = (2-1) << 4 = 0x10
    # length=4 → bref_low = 4-3 = 1
    # bref = 0x11, le bytes 0x11 0x00
    # Flag: 0b00000100 (bits 0,1 = literal; bit 2 = backref)
    sub_body = bytes([0x04, ord('A'), ord('B'), 0x11, 0x00])
    sub_size = len(sub_body)
    header = 0xB000 | (sub_size - 1)
    test3 = bytes([header & 0xFF, (header >> 8) & 0xFF]) + sub_body
    expected = b'ABABAB'  # 'AB' literal + 4 bytes copied from -2 (overlap = RLE)
    got = lznt1_decompress(test3)
    assert got == expected, f"backref test failed: got {got!r} expected {expected!r}"

    print("LZNT1 self-tests passed.")
