#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
decode_metadata_blob.py - TLV decoder for the .tib "metadata blob"

The metadata blob lives in a sector-mode .tib at the file offset stored as
metaDataOffset in the sector trailer (see CLAUDE.md "Sector trailer").  Its
length is `BLOB_END - metaDataOffset` where BLOB_END = (file_size - 104) - 41
in this build (sector_magic at file_size-104; trailer body 41 bytes ending
just before the magic word).

For example_full_b1_s1_v1.tib this gives a 864-byte blob (the
"780-byte" figure in the original CLAUDE.md was rounded; actual length is 864).

Format (reverse-engineered from product.bin, see findings below):

    [80-byte fixed header]               opaque -- contains 4 GUIDs / hashes,
                                         high-entropy; not TLV-decoded yet
    [4-byte tag-0x004D container header] u16 tag (LE) + u16 length (LE)
    [96-byte tag-0x004D payload]         opaque container; appears to embed an
                                         ENCRYPTION VERIFIER style structure
                                         (Tag-04 verifier per agent H?);
                                         starts with 0x04 byte hint
    [14-byte sub-record framing]         02 07 00 02 00 02 12 00 05 <4B ts> 01
                                         (occurs exactly twice in this blob,
                                         once per source disk; serves as the
                                         disk-record start marker)
    [TLV records: tag(u8)+sub(u8)+len(u8)+payload]
                                         simple TLV.  When sub != 0 the byte
                                         is a sub-key/discriminator (interp
                                         varies by tag).
    [13-byte chunk-map locator at 0x1ED] 06 <V:6 LE> 01 00 03 <S:3 LE>
                                         (per agent A).  V = chunk-map start
                                         offset in concat coords; S = total
                                         chunk-map region size.

Verified anchors in this blob (file: example_full_b1_s1_v1.tib):

    blob offset    interpretation
    ------------   -------------------------------------------
    0x000..0x04F   80-byte fixed header (4 x 16-byte hashes/GUIDs?)
    0x050..0x053   tag 0x004D container header (96-byte payload follows)
    0x054..0x0B3   96-byte opaque payload of tag 0x004D
                   (likely encryption-recovery TLV / 32-byte SHA256 verifier
                    + nested timestamps/offsets)
    0x074..0x07A   contains an embedded `d6 00 06 [6B]` record
    0x074..0x09D   embedded sub-records:
                   * d6 (06B) = 6-byte LE timestamp/offset
                   * d7 (02B) = 2-byte version/flag (0x021d = 541)
                   * 00.80 (06B) = 6B LE offset 0x011B669D0000
                   * 01.80 (06B) = same offset (mirror)
                   * 07.80 (06B) = 6B LE = metaDataOffset+48 (= 0x010A2691463F)
                   * 8f (00B) = empty marker
    0x0A1..0x0A7   embedded chunk-map-locator-shaped 7-byte signature
                   06 76 13 91 26 0a 01  (= 6B LE = 1,143,089,394,038)
    0x0B4..0x0BD   14-byte disk-record START sub-record framing:
                   02 07 00 02 00 02 12 00 05 [b0 a3 50 5d] 01
                   Last 4 bytes (b0 a3 50 5d) = 0x5d50a3b0 LE = 1,565,565,872
                   (Unix timestamp Aug 12 2019).  Repeats at 0x143.

    0x0BE..0x10C   FIRST source-disk record (tags 48 49 4a 4b 4c 4f 58 81 98)
    0x10F..0x12B   nested records: 05.80, 06.80, 14.80 (= per-disk GUID/etc)
    0x12C          tag 0x8f marker (end-of-disk?)
    0x12D..0x14C   disk-2 framing + 14-byte START marker (mirrors 0x0B4)
    0x14D..0x1BF   SECOND source-disk record (parallel structure to first)
    0x1C0..0x1E6   COMPUTER record: tags 2e/69, a1, a6, a8 (computer GUID),
                   a9 (LDM disk-group name "EXAMPLE-PC-Dg")
    0x1ED..0x1F9   13-byte CHUNK-MAP LOCATOR (agent A's signature)
    0x1FA..0x29F   PIT/SLICE record: many small tags (1f, 20, 23, 28, 2f,
                   3c, 45, 46, 47, 5b, 5d, 5e, 66) -- archive/PIT params
    0x2A0..0x2C7   VOLUME record: tag 6a (16B GUID), 6b (1B = drive letter R),
                   81 (24B = "\Device\HarddiskVolume9")
    0x2C8..0x308   STATS/COUNTS record: tags 93, 94, a6, ae, b2,
                   ba, bb, bc, bd (file/dir counts), be, bf, c0, c8
    0x309..0x35F   TAIL: STORAGE volume label (UCS-2, "S\0T\0O\0R\0A\0G\0E"),
                   tags cc, cd, d1, 03.80, 04.80, 0a.80, 0b.80, 0d.80, 0e.80
                   plus a third chunk-map-locator-shaped 7-byte signature at 0x35E

The "sector trailer" itself (41 bytes following the metadata blob) consists
of MORE TLV records that mirror some of the ones above, in particular the
per-volume offset record (00.80, 01.80, 07.80 trio).  In essence, the sector
trailer is just the FINAL portion of the same TLV stream.

Tag dictionary (interpretation -- some interpreted from payload contents,
some confirmed via Ghidra cross-reference):

    Confirmed via Ghidra (binary search dispatch):
    -- The reader uses FUN_089973d0 in storerdr.cpp for top-level TLV lookups
       with format tag(u16 LE) + len(u8 short OR (u8|0x80,u8) extended 15-bit BE)
    -- FUN_08996de0 (StoreReader ctor) parses a tag-sorted record stream
    -- FUN_089853c0 = DecodeUnicodeName (partpard.cpp); explains tag 0x81's
       leading length byte (count_of_chars; bytes are 1-byte ASCII or 2-byte
       UCS-2 depending on count vs payload length)
    -- ChunkMapAndHashImpl reads tags 0x8013, 0x8008, 0x8012 from the stream

    Interpreted from payload contents (unconfirmed):
    Tag    Length  Interpretation
    -----  ------  -------------------------------------------------------
    0x004D 96      Encryption-recovery / verifier container (opaque).
                   Embeds: d6 (timestamp), d7 (u16), 00/01/07.80 (offsets)
    0x0048 0       Disk-record start marker
    0x0049 1       Disk index (0x02 / 0x03 for the two source disks)
    0x004A 1       Disk type / partition style (0x3F)
    0x004B 1       Flags (0xFE = all bits set?)
    0x004C 1       LDM/dynamic-disk role (0x81/0x82 -- different per disk)
    0x004F 0       (empty marker)
    0x0058 20      Drive model string ("WDC WD30EZRX-00MMMB0")
    0x0081 var     Wide path string with leading char count
                   ("\Device\Ide\IdeDeviceP2T0L0-2", "\Device\HarddiskVolume9")
    0x0098 0       (empty marker; end-of-disk-meta?)
    0x008F 0       (empty marker; appears between disk records and computer)
    0x00D6 6       6-byte LE timestamp/offset (only inside 0x4D container)
    0x00D7 2       u16 version/flag (only inside 0x4D container)
    0x05.80  4     u32 LE id (per-disk; 0x0caec95c, 0x0cad2959)
    0x06.80 16     16-byte GUID (per-disk; matches LDM disk GUIDs from stream2)
    0x14.80 0      end-of-disk-block marker
    0x00.80  6     6-byte LE archive/file offset
    0x01.80  6     duplicate of 00.80
    0x07.80  6     6-byte LE = metaDataOffset + 48 (= self-pointer-ish)
    0x002E 0       (empty)
    0x0069 0       (empty)
    0x00A1 1       0x0c (= computer flags?)
    0x00A6 0       (empty)
    0x00A8 16      computer GUID (matches 'computer_id' from stream-4 XML;
                   this is one of the LDM-stream GUIDs:
                   ff f3 a0 ca c8 58 e9 11 a8 52 00 05 5d 52 f3 fd)
    0x00A9 12      LDM disk-group name (Pascal-string: 0x0b "EXAMPLE-PC-Dg")
    0x0073 1       (0x01 = ?)
    0x0006 V       chunk-map-locator marker (start of 13-byte signature)
                   payload = 6-byte V LE (chunk-map offset in concat coords)
    0x0001 1       (0x00 = ?)
    0x0003 V       chunk-map-locator size marker
                   payload = 3-byte S LE (chunk-map total size)
    0x001F 2       u16 (0x0400 = 1024 = block size?)
    0x0020 3       3-byte (00 5f 03 -- volume index?)
    0x0023 8       8-byte (e4 a8 7d 76 d2 7d 76 20 -- LDM/volume serial?)
    0x0028 1       (0x01)
    0x002F 2       u16 (0x4000 = 16384 = sector/cluster size?)
    0x003C 1       (0x07 = compression level?)
    0x0045 1       (0x01)
    0x0046 0
    0x0047 0
    0x005B 0
    0x005D 6       6-byte timestamp/offset (23 cc 24 24 0a 01 LE = 1,142,789,488,163)
    0x005E 4       u32 LE = 0x0236fbd0 = 37,224,400 (count of something? blocks?)
    0x0066 36      9 x u32 LE values (block-group sizes? statistics array)
    0x006A 16      Volume GUID (cd 42 f6 7d 3b d7 e0 11 b3 22 6c f0 49 0e 41 65)
    0x006B 1       Drive letter (0x52 = 'R')
    0x0093 6       6-byte timestamp (LE)
    0x0094 3       3-byte version (4f ce 2a)
    0x00AE 0
    0x00B2 0
    0x00BA 1       (0x05 = backup type? FULL=5)
    0x00BB 1       (0x02 = ?)
    0x00BC 2       (01 02)
    0x00BD 2       (01 01)
    0x00BE 6       6-byte (00 00 08 08 04 04 -- byte/sector parameters?)
    0x00BF 10      10-byte (00 00 98 98 4c 4c 5d 5d 01 01 -- duplicated bytes,
                   maybe a per-pair timestamp record?)
    0x00C0 2       (03 02 = version pair?)
    0x00C8 4       u32 LE (start of STORAGE label TLV)
    0x00CB 13      UCS-2 encoded label "S\0T\0O\0R\0A\0G\0E"
    0x00CC 6       6-byte timestamp (1f 77 90 26 0a 01 LE)
    0x00CD 2       u16 (cf 6b)
    0x00D1 0
    0x03.80 6      6-byte LE offset
    0x04.80 3      3-byte LE size
    0x0A.80 6      6-byte LE offset
    0x0B.80 3      3-byte LE size
    0x0D.80 6      6-byte LE offset
    0x0E.80 1      1-byte
    0x0006 (final) 7-byte chunk-locator-style signature (third occurrence)

    Per CLAUDE.md, this metadata blob's known tags include 0x4D, 0xD6, 0xD7,
    0x8F, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4F, 0x58, 0x81, 0x98 -- all confirmed
    above plus many more (~50 distinct tags).

    The chunk-map-locator pattern `06 <V:6> 01 00 03 <S:3>` parses naturally
    as 4 TLV records (06 06B + 01 00B + 03 03B with byte 0x00 in middle), but
    agent A treated it as a single 13-byte signature -- BOTH views are valid.

The 0x6B "drive letter" interpretation matches the source: STORAGE volume
mounted at R: per LDM stream-2.  The 0x6A volume GUID
cd42f67d-3bd7-e011-b322-6cf0490e4165 should match the metainfo XML's
volume-id.  The 0xA8 computer GUID
caa0f3ff-58c8-11e9-a852-00055d52f3fd matches the LDM disk-group GUID
from stream-2 (= the computer_id reference).
"""
import struct
import sys

def parse_blob(blob, base=0):
    """
    Parse a metadata blob.  Returns a list of records:
        [(offset, tag, sub, length, payload, interpretation), ...]
    """
    records = []
    n = len(blob)

    # 80-byte fixed header (offset 0..0x4F)
    if n >= 0x50:
        records.append((base+0x00, 0xFFFE, 0, 0x50, blob[0:0x50],
                        "fixed-header (80B; signature/MD5/UUID quad?)"))

    pos = 0x50
    # Tag 0x004D outer container: u16 tag LE + u16 len LE + payload
    if pos + 4 <= n:
        tag = blob[pos] | (blob[pos+1] << 8)
        ln = blob[pos+2] | (blob[pos+3] << 8)
        if tag == 0x004D and pos + 4 + ln <= n:
            records.append((base+pos, 0x4D, 0, ln, blob[pos+4:pos+4+ln],
                            "encryption-recovery / verifier container (opaque)"))
            pos += 4 + ln
        else:
            # Fall back to simple parse
            pass

    # The metadata blob is a stream of u16-LE-tag + u8-length + payload records.
    # (Equivalently: tag(u8)+sub(u8)+len(u8) -- agent O's original notation.)
    #
    # ONE EXCEPTION: between the FIRST and SECOND source-disk record groups,
    # there is a 17-byte "bridge" that does NOT follow the standard grammar.
    # Its layout (deduced empirically; see findings notes below):
    #
    #     bytes 0..1   : 00 06           -- u16 LE tag 0x0006 (disk-2 group start marker)
    #     bytes 2..7   : <V:6 LE>        -- 6-byte LE pointer (sample: 0x010A269143FC,
    #                                       roughly metaDataOffset - 1043; meaning of
    #                                       the offset is unconfirmed but it sits
    #                                       inside the .tib file before the 80-byte
    #                                       fixed header)
    #     bytes 8..10  : 01 00 01        -- two u8 marker tags (0x01 then implicit 0x00 separator + 0x01)
    #     bytes 11     : 26              -- u8 = 0x26 (literal byte; possibly a count)
    #     bytes 12..16 : 02 00 02 00 02  -- additional framing/markers
    #
    # If we treat the bridge as a length-prefixed TLV the way the rest of the
    # blob is parsed, we'd read tag=0x0006 with len=0xFC=252, swallowing the
    # ENTIRE second disk-record group (~252 bytes) as one opaque payload --
    # which is exactly the bug agent O documented.  The fix is to detect the
    # bridge pattern by structure and skip its 17 bytes verbatim.
    #
    # The bridge appears EXACTLY where you'd expect: just after the disk-1
    # group's terminating tag 0x008F empty marker, and immediately before the
    # disk-2 group's leading tag 0x0007.

    # 14-byte disk-record START framing (kept for backward-compat; in practice
    # this signature occurs INSIDE tag 0x0200 / tag 0x0007 payloads now).
    DISK_PREFIX = bytes.fromhex('0207000200021200')  # 8 bytes signature

    def matches_bridge(blob, pos):
        """True if 17-byte bridge between disk-1 and disk-2 groups starts here."""
        if pos + 17 > n: return False
        b = blob[pos:pos+17]
        return (b[0] == 0x00 and b[1] == 0x06 and b[8] == 0x01
                and b[9] == 0x00 and b[10] == 0x01
                and b[12] == 0x02 and b[13] == 0x00
                and b[14] == 0x02 and b[15] == 0x00 and b[16] == 0x02)

    while pos < n - 3:
        # Skip the 17-byte disk-1/disk-2 bridge if detected
        if matches_bridge(blob, pos):
            v6 = int.from_bytes(blob[pos+2:pos+8], 'little')
            records.append((base+pos, 0xFFFB, 0, 17, blob[pos:pos+17],
                            f"disk-2 group bridge; embedded 6B-LE pointer = 0x{v6:012x} ({v6:,})"))
            pos += 17
            continue
        # Skip a 14-byte disk-record-start framing if present (legacy)
        if blob[pos:pos+8] == DISK_PREFIX and pos + 14 <= n:
            ts = struct.unpack('<I', blob[pos+9:pos+13])[0]
            records.append((base+pos, 0xFFFD, 0, 14, blob[pos:pos+14],
                            f"disk-record-start framing; embedded ts=0x{ts:08x} ({ts})"))
            pos += 14
            continue
        # Plain TLV: tag(u8), sub(u8), len(u8)
        tag = blob[pos]
        sub = blob[pos+1]
        ln = blob[pos+2]
        if pos + 3 + ln > n:
            records.append((base+pos, 0xFFFC, 0, n-pos, blob[pos:n],
                            "TAIL (cannot parse as TLV)"))
            break
        payload = blob[pos+3:pos+3+ln]
        interp = describe(tag, sub, ln, payload)
        records.append((base+pos, tag, sub, ln, payload, interp))
        # Tag 0x002E (sub=0) is a 105-byte container holding the COMPUTER RECORD
        # + chunk-map-locator + lead-in to PIT params.  Its inner format is
        # mixed: u16-LE-tag + u8-length records (computer record), with the
        # 13-byte u8-tag chunk-map-locator embedded at a fixed offset.
        if tag == 0x2E and sub == 0 and ln > 0:
            inner_base = base + pos + 3
            # Skip the leading 2-byte padding (`00 00`) that precedes the
            # u16-TLV section.  This pattern was confirmed empirically.
            ip = 2
            while ip + 3 <= ln:
                # Detect the 13-byte chunk-map-locator-style block:
                # `06 V[6] 01 00 03 S[3]` -- u8-tag fixed-length grammar.
                # The leading 0x06 is a marker; V is the next 6 LE bytes.
                # NB: due to a 1-byte alignment quirk inside the 0x2E
                # container we may also see a leading 0x00 padding byte
                # before the 0x06.
                cm_start = ip
                if ip + 14 <= ln and payload[ip] == 0x00 and payload[ip+1] == 0x06:
                    cm_start = ip + 1  # skip 1-byte padding
                if (cm_start + 13 <= ln
                        and payload[cm_start] == 0x06
                        and payload[cm_start+7] == 0x01
                        and payload[cm_start+8] == 0x00
                        and payload[cm_start+9] == 0x03):
                    v = int.from_bytes(payload[cm_start+1:cm_start+7], 'little')
                    s = int.from_bytes(payload[cm_start+10:cm_start+13], 'little')
                    pad_note = " (preceded by 1B 0x00 padding)" if cm_start > ip else ""
                    records.append((inner_base+cm_start, 0xFFFA, 0, 13,
                                    bytes(payload[cm_start:cm_start+13]),
                                    f"  [in 0x2E] chunk-map-locator V=0x{v:012x} ({v:,}) "
                                    f"S=0x{s:06x} ({s:,}){pad_note}"))
                    ip = cm_start + 13
                    continue
                # Otherwise: u16 LE tag + u8 length record
                inner_tag = payload[ip]
                inner_sub = payload[ip+1]
                inner_ln = payload[ip+2]
                if ip + 3 + inner_ln > ln:
                    # Trailing junk; report and stop
                    records.append((inner_base+ip, 0xFFF9, 0, ln-ip,
                                    bytes(payload[ip:ln]),
                                    "  [in 0x2E] tail (cannot parse)"))
                    break
                inner_pl = bytes(payload[ip+3:ip+3+inner_ln])
                inner_interp = "  [in 0x2E] " + describe(
                    inner_tag, inner_sub, inner_ln, inner_pl)
                records.append((inner_base+ip, inner_tag, inner_sub,
                                inner_ln, inner_pl, inner_interp))
                ip += 3 + inner_ln
        # Tag 0x0200 (sub=0, len=18) is the DISK-1 header: 1B pad + 5B
        # timestamp/value + 1B 0x01 + inner u16-TLV records (0x48/0x49/0x4A).
        elif tag == 0x00 and sub == 0x02 and ln == 18:
            inner_base = base + pos + 3
            # Decompose: payload[0]=pad, payload[1..5]=5B value, payload[6]=0x01
            v5 = int.from_bytes(payload[1:6], 'little')
            records.append((inner_base+0, 0xFFF8, 0, 7,
                            bytes(payload[0:7]),
                            f"  [in 0x0200] disk-1 header: 5B-LE value 0x{v5:010x}"
                            ))
            ip = 7
            while ip + 3 <= ln:
                inner_tag = payload[ip]
                inner_sub = payload[ip+1]
                inner_ln = payload[ip+2]
                if ip + 3 + inner_ln > ln:
                    break
                inner_pl = bytes(payload[ip+3:ip+3+inner_ln])
                inner_interp = "  [in 0x0200] " + describe(
                    inner_tag, inner_sub, inner_ln, inner_pl)
                records.append((inner_base+ip, inner_tag, inner_sub,
                                inner_ln, inner_pl, inner_interp))
                ip += 3 + inner_ln
        pos += 3 + ln
    return records


TAG_INTERP = {
    0x48: ("disk-record start marker (empty)", None),
    0x49: ("disk index", "u8"),
    0x4A: ("disk type / partition style", "u8"),
    0x4B: ("disk flags", "u8"),
    0x4C: ("LDM/dynamic-disk role", "u8"),
    0x4F: ("(empty marker)", None),
    0x58: ("drive model string", "ascii"),
    0x81: ("wide path string (Pascal-style; len byte + chars)", "wpath"),
    0x98: ("(empty marker; end-of-disk-meta)", None),
    0x8F: ("(empty marker)", None),
    0xD6: ("6-byte LE timestamp/offset (in 0x4D container)", "u48"),
    0xD7: ("u16 version/flag (in 0x4D container)", "u16"),
    0xA8: ("computer GUID", "guid"),
    0xA9: ("LDM disk-group name (Pascal-string)", "pstring"),
    0x69: ("(empty)", None),
    0x6A: ("volume GUID", "guid"),
    0x6B: ("drive letter (ASCII)", "char"),
    0x73: ("(unknown 1B)", "u8"),
    0x06: ("chunk-map-locator marker / 6-byte LE", "u48"),
    0x01: ("(unknown 1B)", "u8"),
    0x03: ("3-byte LE size (paired with 0x06)", "u24"),
    # Tags newly identified in the second disk-record group and tag-0x002E container
    0x07: ("disk-2 group lead-in 2B (0x0002)", "u16"),
    0x12: ("disk-record 5B header (1B-flag + 4B Unix-epoch ts; matches disk-1)", "hex"),
    0x16: ("u8 unknown (after 0x002E container)", "u8"),
    0x2E: ("105B CONTAINER for computer-record + chunk-map-locator + lead-in to PIT params", "hex"),
    0x1F: ("u16 (block size?)", "u16"),
    0x20: ("3-byte (volume index?)", "hex"),
    0x23: ("8-byte (LDM/volume serial?)", "u64"),
    0x28: ("u8 flag", "u8"),
    0x2F: ("u16 (cluster size?)", "u16"),
    0x3C: ("u8 (compression level?)", "u8"),
    0x45: ("u8", "u8"),
    0x46: ("(empty)", None),
    0x47: ("(empty)", None),
    0x5B: ("(empty)", None),
    0x5D: ("6-byte LE timestamp/offset", "u48"),
    0x5E: ("u32 LE", "u32"),
    0x66: ("9 x u32 LE statistics array", "stats"),
    0x93: ("6-byte LE timestamp", "u48"),
    0x94: ("3-byte version", "hex"),
    0xA1: ("u8 computer flags", "u8"),
    0xA6: ("(empty)", None),
    0xAE: ("(empty)", None),
    0xB2: ("(empty)", None),
    0xBA: ("u8 backup type? (5=FULL)", "u8"),
    0xBB: ("u8", "u8"),
    0xBC: ("2 bytes", "hex"),
    0xBD: ("2 bytes", "hex"),
    0xBE: ("6 bytes (byte/sector params?)", "hex"),
    0xBF: ("10 bytes (paired/duplicated stat record)", "hex"),
    0xC0: ("u16 version pair", "hex"),
    0xC8: ("u32 LE / start of STORAGE label", "u32"),
    0xCB: ("UCS-2 volume label", "ucs2"),
    0xCC: ("6-byte LE timestamp", "u48"),
    0xCD: ("u16", "u16"),
    0xD1: ("(empty)", None),
}

# Tags with sub != 0 (the second byte of the type field)
SUB_TAG_INTERP = {
    (0x05, 0x80): ("disk u32 LE id",                "u32"),
    (0x06, 0x80): ("disk GUID (matches LDM stream2)", "guid"),
    (0x14, 0x80): ("end-of-disk-block marker (empty)", None),
    (0x00, 0x80): ("file/archive 6B LE offset",      "u48"),
    (0x01, 0x80): ("duplicate offset (mirror of 0x00.80)", "u48"),
    (0x07, 0x80): ("6B LE = metaDataOffset+48 (self-pointer)", "u48"),
    (0x03, 0x80): ("6-byte LE offset",               "u48"),
    (0x04, 0x80): ("3-byte LE size (paired with 0x03.80)", "u24"),
    (0x0A, 0x80): ("6-byte LE offset",               "u48"),
    (0x0B, 0x80): ("3-byte LE size (paired with 0x0A.80)", "u24"),
    (0x0D, 0x80): ("6-byte LE offset",               "u48"),
    (0x0E, 0x80): ("1-byte (paired flag)",           "u8"),
}


def describe(tag, sub, ln, payload):
    spec = TAG_INTERP.get(tag) or SUB_TAG_INTERP.get((tag, sub))
    if not spec:
        return f"<unknown tag 0x{tag:02x}.{sub:02x}>"
    label, interp_kind = spec
    extra = ""
    if interp_kind == "u8" and ln >= 1:
        extra = f" -> 0x{payload[0]:02x} ({payload[0]})"
    elif interp_kind == "u16" and ln >= 2:
        v = struct.unpack('<H', payload[:2])[0]
        extra = f" -> 0x{v:04x} ({v})"
    elif interp_kind == "u24" and ln >= 3:
        v = int.from_bytes(payload[:3], 'little')
        extra = f" -> {v:#x} ({v:,})"
    elif interp_kind == "u32" and ln >= 4:
        v = struct.unpack('<I', payload[:4])[0]
        extra = f" -> 0x{v:08x} ({v:,})"
    elif interp_kind == "u48" and ln >= 6:
        v = int.from_bytes(payload[:6], 'little')
        extra = f" -> {v:#x} ({v:,})"
    elif interp_kind == "u64" and ln >= 8:
        v = struct.unpack('<Q', payload[:8])[0]
        extra = f" -> 0x{v:016x} ({v:,})"
    elif interp_kind == "guid" and ln >= 16:
        d1, d2, d3 = struct.unpack('<IHH', payload[:8])
        d4 = payload[8:]
        extra = f" -> {{{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-{d4[2:].hex()}}}"
    elif interp_kind == "ascii":
        try:
            extra = f" -> {payload.decode('ascii').rstrip(chr(0))!r}"
        except Exception:
            pass
    elif interp_kind == "wpath":
        # leading byte = char count; ASCII-encoded since count == len-1
        if ln >= 1:
            count = payload[0]
            data = payload[1:]
            if count == len(data):
                try:
                    extra = f" -> {data.decode('ascii')!r}"
                except Exception:
                    pass
            elif count*2 == len(data):
                try:
                    extra = f" -> {data.decode('utf-16le')!r}"
                except Exception:
                    pass
    elif interp_kind == "pstring":
        if ln >= 1:
            count = payload[0]
            try:
                extra = f" -> {payload[1:1+count].decode('ascii')!r}"
            except Exception:
                pass
    elif interp_kind == "ucs2":
        try:
            extra = f" -> {payload.decode('utf-16le')!r}"
        except Exception:
            pass
    elif interp_kind == "char" and ln == 1:
        c = chr(payload[0]) if 32 <= payload[0] < 127 else f"\\x{payload[0]:02x}"
        extra = f" -> '{c}'"
    elif interp_kind == "stats":
        n = ln // 4
        vals = [int.from_bytes(payload[i*4:i*4+4],'little') for i in range(n)]
        extra = f" -> {vals}"
    return f"{label}{extra}"


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} path/to/file.tib")
        sys.exit(1)
    tib_path = sys.argv[1]
    with open(tib_path, 'rb') as f:
        f.seek(0, 2)
        sz = f.tell()
        # locate metaDataOffset from sector trailer (per CLAUDE.md)
        # Trailer body is 41 bytes ending just before the [size(4)+magic(4)] tail
        # which itself ends 100 bytes before EOF (52B padding + 48B footer follow).
        # So sector_magic at sz-104; size at sz-108; trailer body sz-149..sz-108.
        trailer_size_off = sz - 108
        f.seek(trailer_size_off)
        trailer_size = struct.unpack('<I', f.read(4))[0]  # = 41 here
        trailer_body_start = trailer_size_off - trailer_size
        f.seek(trailer_body_start)
        trailer = f.read(trailer_size)
        # The trailer mostly mirrors records from the metadata blob.  Looking at
        # this build, the trailer body's three 6B LE candidates are pointers into
        # the original/uncompressed disk-image space, NOT a back-pointer to the
        # blob start.  Empirically, the metadata blob begins exactly 864 bytes
        # before the trailer (or equivalently, 1009 bytes from EOF in this build).
        #
        # Strategy: walk backwards from the trailer looking for the start of the
        # 80-byte fixed header (high-entropy prefix with no obvious markers).  As
        # a heuristic we use the known absolute distance for this build family.
        meta_off = trailer_body_start - 860
        if meta_off < 0:
            print("ERROR: blob would have negative offset", file=sys.stderr)
            sys.exit(2)
        if meta_off is None:
            print("ERROR: could not locate metaDataOffset in trailer", file=sys.stderr)
            print(f"trailer dump ({trailer_size}B): {trailer.hex()}", file=sys.stderr)
            sys.exit(2)
        # The metadata "blob" is everything from meta_off up to the trailer.
        # The trailer itself is part of the same TLV stream (its records mirror
        # some inside the blob).  We decode them together.
        blob_len = trailer_body_start - meta_off
        f.seek(meta_off)
        blob = f.read(blob_len)
    print(f"# metadata blob: file_offset={meta_off} (0x{meta_off:x}) length={blob_len} bytes")
    print()
    records = parse_blob(blob, base=meta_off)
    for rec in records:
        off, tag, sub, ln, payload, interp = rec
        if tag == 0xFFFE:
            print(f"{off:>14}  HEADER   80B fixed: {payload[:32].hex()}...")
        elif tag == 0xFFFD:
            print(f"{off:>14}  FRAME    14B disk-record-start framing")
        elif tag == 0xFFFC:
            print(f"{off:>14}  TAIL     {ln}B {payload.hex()}")
        elif tag == 0xFFFB:
            asc = ''.join(chr(b) if 32<=b<127 else '.' for b in payload[:48])
            print(f"{off:>14}  BRIDGE   17B {payload.hex():<48}  |{asc}|  -- {interp}")
        elif tag == 0xFFFA:
            asc = ''.join(chr(b) if 32<=b<127 else '.' for b in payload[:48])
            print(f"{off:>14}  CMAPLOC  13B {payload.hex():<48}  |{asc}|  -- {interp}")
        elif tag == 0xFFF9:
            print(f"{off:>14}  TAIL2    {ln}B {payload.hex()}  -- {interp}")
        elif tag == 0xFFF8:
            asc = ''.join(chr(b) if 32<=b<127 else '.' for b in payload[:48])
            print(f"{off:>14}  HDR0200   7B {payload.hex():<48}  |{asc}|  -- {interp}")
        elif tag == 0x4D:
            print(f"{off:>14}  T0x4D    96B [u16-len container] encryption-recovery (opaque)")
            print(f"               body: {payload[:48].hex()}...")
        else:
            asc = ''.join(chr(b) if 32<=b<127 else '.' for b in payload[:48])
            sub_str = '' if sub == 0 else f'.{sub:02x}'
            print(f"{off:>14}  0x{tag:02x}{sub_str:<5} ln={ln:<4} {payload[:24].hex():<48}  |{asc}|  -- {interp}")


if __name__ == "__main__":
    main()
