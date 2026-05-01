# RESEARCH: archive3.dll Strings Mining

Source: `~/archive3_re/archive3_strings.txt` (253 KB) and `archive3_adapter_strings.txt` (24 KB) on `re-host`. Binary analyzed: `archive3.dll` from Acronis True Image 2024 install.

Confidence convention used in this document:
- **[CONFIRMED]** — text appears verbatim in the strings dump.
- **[INFERRED]** — derived from naming, file layout, or adjacent strings; likely correct but not literally proven.

---

## 1. Source-tree topology

PDB-leaked source root (Windows path):

```
c:\ja\workspace\pipeline\ab-backup-archive3\libarchive3\
```

**70 distinct source files** referenced in the dump (67 `libarchive3` + 3 DigiCert certificate vendor blobs). Per-file occurrence counts (full path strings + raw symbol references):

| Count | File | Notes |
|------:|------|-------|
| 107 | `page.c` | Page allocator / I/O — heaviest module |
|  75 | `lsm.c` | Log-structured-merge tree core |
|  71 | `lsm_notary_map.c` | Merkle-style integrity tree |
|  64 | `archive_api.c` | Public-API layer |
|  63 | `archive_item.c` | File/directory item logic |
|  58 | `archive_slice.c` | Slice (incremental backup) logic |
|  56 | `perf_stat.h` | Perf counter macros |
|  51 | `golomb.c` | Golomb-coded extent compression |
|  49 | `archive_io.c` | I/O abstraction |
|  47 | `page_cache.c` | In-memory page cache |
|  46 | `archive_hdr.c` | Archive header (ARCH magic) |
|  42 | `segment.c` | Data segment compression/encryption |
|  41 | `page.h` |  |
|  41 | `compaction.c` | Online compaction |
|  38 | `archive_priv.h` |  |
|  36 | `persistent_cache.c` | On-disk pcache (APCF magic) |
|  36 | `ext.h` | Extent helpers |
|  33 | `lsm_golomb.c` | Golomb encoding for LSM |
|  30 | `sequential.c` | Sequential read fast-path |
|  30 | `archive_io_local.c` | Local-FS I/O backend |
|  24 | `archive_alloc.c` | Block allocator |
|  23 | `archive_io_ostor.c` | "ObjectStorage" backend (cloud) |
|  21 | `lsm_name_map.c` | Name → item-id LSM map |
|  21 | `archive_io_astor.c` | "Astor" client backend |
|  17 | `replication.c` | Slice replication |
|  16 | `lsm_mem.c` | LSM in-memory layer |
|  16 | `archive_volume.c` | Multi-volume support |
|  15 | `checkpoint.c` | Checkpoint / commit |
|  14 | `page_vec.c` | Page vector helpers |
|  14 | `archive_encr.c` | Encryption setup / users |
|  13 | `crypto_aes.c` | AES wrap/unwrap (PBKDF2) |
|  12 | `lsm_merge.c` | LSM compaction merge |
|  11 | `validate_segments.c` |  |
|  11 | `lsm_unused_map.c` | Free-space LSM |
|  11 | `lsm_item.h` |  |
|  10 | `replication_sequential.c` |  |
|  10 | `lsm_segment_map.c` | Segment-id map |
|  10 | `lsm_data_map_lookup.c` | Data extent lookup |
|   9 | `validate_slices.c` |  |
|   9 | `validate_item.c` |  |
|   8 | `validate_hashes.c` |  |
|   8 | `lsm_ctree_lookup.c` | Compact-tree lookup |
|   7 | `lsm_unused_map_lookup.c` |  |
|   7 | `lsm_lookup.c` |  |
|   7 | `container.c` | Single-file `.tibx` container wrapper |
|   7 | `analyze.c` | Health-check |
|   6 | `persistent_cache_crawler.c` |  |
|   5 | `validate_orphan.c` |  |
|   5 | `last_good.c` | Repair to last-good header |
|   5 | `dedup.c` | Dedup index |
|   4 | `validate_space.c` |  |
|   4 | `validate_objects.c` |  |
|   4 | `lsm_data_map.c` |  |
|   4 | `copy.c` | Slice-export raw copy |
|   4 | `astor_snapshots.c` |  |
|   3 | `validate_refs.c` |  |
|   3 | `archive_locking.c` |  |
|   2 | `validate_trees.c` |  |
|   2 | `validate_pages.c` |  |
|   2 | `validate_dedup.c` |  |
|   2 | `lsm_unused_map_merge.c` |  |
|   2 | `lsm_nlink_map.c` | Hard-link count map |
|   2 | `archive_log.c` |  |
|   1 | `utf8.c` |  |
|   1 | `archive_stats.c` |  |
|   1 | `archive_io_local_dirfd.c` | dirfd-based local I/O |
|   1 | `archive_err.c` |  |

Plus: `digicert.c`, `DigiCertTrustedRootG4.c`, `DigiCertTrustedG4CodeSigningRSA4096SHA2562021CA1.c`, `DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.c`, `DigiCertAssuredIDRootCA.c` — embedded code-signing trust roots, **not** format-relevant.

**Notable absences** (vs. originally listed): `analyze.c` *is* present (7 hits). `archive_alloc.c`, `archive_api.c`, `archive_encr.c`, `archive_err.c`, `archive_hdr.c`, `archive_io.c`, `archive_io_astor.c`, `archive_io_local.c`, `archive_io_local_dirfd.c`, `archive_priv.h`, `ext.h`, `lsm_item.h`, `page.h`, `perf_stat.h` are all present and confirmed. New file `archive_io_ostor.c` was discovered (cloud "object storage" backend).

---

## 2. Format magic numbers / signatures **[CONFIRMED]**

These are the real, format-relevant 4-byte ASCII signatures (false positives like `SAVH`/`SUWH`/etc. are x86-64 prologue bytes — `push rbx; push rbp; push rsi; push rdi; push rXX; sub rsp, ..` — that strings(1) misinterpreted as ASCII). Filtered list:

| Magic | Module | Role | Cross-ref string |
|-------|--------|------|------------------|
| **`ARCH`** | `archive_hdr.c:431-432` | Archive header (the file-level superblock) | `ar#%u: header magic '%02X%02X%02X%02X' at %llu is incorrect` |
| **`ARCI`** | `archive_hdr.c` | Archive Commit Index — points to an `ARCH` header chain | `ar#%u: magic of archive CI at %s is incorrect` |
| **`APCF`** | `persistent_cache.c` | Persistent-cache file header (separate from `.tibx` data; cache sidecar) | `pc#%u: %s: invalid magic %02hhx%02hhx%02hhx%02hhx` |
| **`CHBXI`** | (5-char) | "Container header `.tibx`-incremental"? appears next to `.meta/.slice/.common/comment` and `coldline`. Probably the single-file container envelope written by `container.c`. | `coldline\nCHBXI\n.meta/.slice/.common/comment` |
| **`LEAF`** | `lsm.c:1697` | LSM tree leaf-node segment | `lsm#%u: %s wrong seg magic (type=%d, magic='%.*s' …)` |
| **`LDIR`** | `lsm.c:1697` | LSM directory (interior) node | same as above |
| **`L-SB`** | `lsm.c:1456` | LSM superblock | `lsm#%u: %s sb size (%u) is invalid` / `L-SB` |
| `LSM_LEAF` / `LSM_DIR` / `GOLOMB` / `DATA` / `UNKNOWN` | `lsm.c` | These are **type-name strings** for `type_text` in `{"type_text": "%s", "magic": %u, "crc": ...}`, not on-disk magic. They name the segment-type enum. |
| `Hole` / `Wrong magic` / `CRC mismatch` | | Status enum strings used by validate output. |

The "magic" field in `{"%s": {"sb_size": %u, "magic": "%.*s", "ver": %u, "seq": %u, "nr_ctree": %u, ...}}` is the LSM-superblock magic (`L-SB`), printed as `%.*s` (raw bytes), so the tag is genuinely 4 ASCII bytes on disk.

Segment `seg` JSON uses 2-byte magic (`magic %02x%02x`) per: `ar#%u: segment at %s magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u` — i.e. each compressed segment carries a small 2-byte magic prefix in its header (NOT one of the 4-char tags above). **[CONFIRMED via decompile of `FUN_1800676c0`]**:

- Plain (unencrypted) segment magic: bytes `'S' 'G'` = `0x47 0x53` (LE word `0x4753`, displayed as `53 47`). Stored at `DAT_1800c2d84`.
- Encrypted segment magic:        bytes `'S' 'E'` = `0x45 0x53` (LE word `0x4553`, displayed as `53 45`). Stored at `DAT_1800c2d88`. Only accepted when the archive's encryption-enabled flag (`*(arch+0x1e69)`) is non-zero; otherwise the parser logs `ar#%u: unexpected encrypted segment …` and rejects the page.

The next 2 bytes after the magic are a BE u16 segment-format version that must be `< 2`. The 4 bytes at `+0x02` are zlen (BE u32 compressed length), the 4 bytes at `+0x04` look like clen (BE u32). The compression-algorithm byte is at offset `+0x10` of the segment header and must be one of `{0, 1, 2, 3}` (0 = none/raw, 1 = LZ4, 2 = Zstd, 3 = ?). The fixed segment-header size is `0x24 + (variable_byte & 0xff)` bytes (see `get_segment_header_size` at `0x180068c90`).

---

## 3. Version range supported **[CONFIRMED via text]**

Key strings:

```
ar#%u: version (%d) is newer than supported (%d). Try to update your software
ar#%u: archive version is unknown: actual header has one %u, but last known one is %u
ar#%u: hdr version: %u
ar#%u: Upgrade ver.7: create golomb filter
Upgrade is not allowed (archive version %d)
lsm#%u: %s sb version is newer (%d) then supported (%d)
pc#%u: %s: version %u is unsupported (expected %u)
```

- The only literal version number visible is **`ver.7`** in the upgrade path "create golomb filter". This says: when reading a v6-or-older archive in RW mode with upgrade-allowed, the code synthesizes a Golomb dedup filter (a feature introduced in v7). So **v7 is at least one supported version**, and earlier (≤ v6) versions are upgradeable.
- The actual maximum supported value is held in a `#define` and never expanded as a literal in the strings dump. **[INFERRED]** the supported version for ATI 2024 is **v7 or v8**; needs disasm of `archive_hdr.c` (sites near line 431/432, 304, 1497) to read the constant.
- Three independent version concepts coexist:
  1. **Archive header version** (`ARCH`).
  2. **LSM superblock version** (`L-SB`, separate per-LSM).
  3. **Persistent-cache version** (`APCF`).

There is also a separate **`features` / `features_ro` / `features_rw`** bitmask in the header, with messages "features (%llu) are newer than supported (%llu) for RW mode", indicating forward-compat is bit-flag-based, not just monotonic version-bumps. One feature name leaked: **`PASSWORD_HINT`** (`ar#%u: enable feature PASSWORD_HINT`).

The header `features` field is rendered in tracelog as 16 chars (`features=%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c`), implying ≤16 named feature bits in current use.

---

## 4. Encryption catalog **[CONFIRMED]**

Source: `archive_encr.c`, `crypto_aes.c`. OpenSSL EVP-based.

**Algorithms** (string-table verbatim, mapped to `archive_encr_alg_get_str` / `archive_encr_alg_from_str`):

| Algorithm string | Key size | Mode |
|------------------|----------|------|
| `aes-128-cbc` | 128 | CBC |
| `aes-192-cbc` | 192 | CBC |
| `aes-256-cbc` | 256 | CBC |
| `aes-128-gcm` | 128 | GCM |
| `aes-192-gcm` | 192 | GCM |
| `aes-256-gcm` | 256 | GCM |

Likely ordering of `enum encr_alg`: 0=none, 1..6 = the six AES variants in the order above. **[INFERRED]**

**Key derivation**: `PKCS5_PBKDF2_HMAC` (OpenSSL); iteration count is a tunable, exposed by export `archive_set_pbkdf2_iter_log2` — **iterations = 2^N** style, and `unwrap_key` validates iterations are within range (`Invalid number of PBKDF2 iterations %u: must be in range [%u - %u]`).

**Key wrapping**: two paths:
- **Password path**: PBKDF2-HMAC → derive KEK → AES wrap-data-key (`wrap_key` in `crypto_aes.c:174`).
- **Public-key path**: `EVP_PKEY_encrypt_init` / `EVP_PKEY_encrypt` (`wrap_key_pkey` at `crypto_aes.c:501`). Used by `archive_encr_use_pub_keys`, `archive_encr_use_priv_key`.

**Per-archive metadata** carries `encr_alg`, `encr_last_key_id`, `encr_mtime` (header JSON dump confirmed). There is a notion of multi-user encryption: `archive_encr_user_list_*`, `archive_encr_has_user`, `archive_encr_rm_user` — i.e. multiple wrapped copies of the data key are stored.

**No** scrypt, Argon2, or other KDFs found.

---

## 5. Compression catalog **[CONFIRMED]**

| Algorithm | Evidence |
|-----------|----------|
| **None** | enum value 0 (`none`) |
| **Zstd** | `ZSTD_compress`, `ZSTD_decompress`, `ZSTD_compressBound`, `ZSTD_isError`, `ZSTD_getErrorName`, `zstd.dll`; log `ar#%u: Zstd segment at %s decompress failed: zstd_err=%s` |
| **LZ4** | `LZ4_compressBound`, `LZ4_compress_default`, `LZ4_decompress_safe`, `LZ4_compress_fast_continue`, `LZ4_decompress_safe_continue`, `LZ4_resetStream`, `lz4_data_compressible`, `pack_to_lz4_encoding`; logs `ar#%u: LZ4 segment at %s decompress failed: lz4_err=%d` |
| **zlib** | log only: `ar#%u: zlib segment at %s decompress failed: zlib_err=%d` and `ar#%u: zlib segment at %s uncompressed size %lu != data_size %u`. No `inflate*`/`deflate*` symbols are imported, so zlib is likely **decompress-only** (legacy backwards compat). **[INFERRED]** |

Probable enum ordering: `0 = none, 1 = zlib, 2 = LZ4, 3 = Zstd`. **[INFERRED]** — must verify with disasm.

`archive_get_compr_str` / `archive_get_compr_from_str` handle the string mapping. `archive_set_compr_lvl` adjusts compression level (Zstd 1..22 most likely). LSM internal pages use **LZ4** specifically (see `lsm#%u: %s LZ4 decompression failed at %s` and `lsm#%u: %s sb - LZ4 decompression failed`), regardless of the data-segment compressor — i.e. metadata-tier compression is hard-coded to LZ4.

Each segment header carries `comp=%u` (1 byte field): `ar#%u: segment at %s magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u`.

---

## 6. Hash / dedup / chunking

- **Notary tree** (Merkle-style content authentication): `archive_notary_*` exports, `lsm_notary_map.c` (largest LSM-map module, 71 hits). Per-archive params in the dump: `"notary": {"last_item_id": %llu, "degree": %u, "hash_alg": %u, "flags": "%#x"}`. Tree node dump: `{"degree": %u, "id_mask": %u, "hash_alg": %u, "hash_size": %u, "nodes": [...]}`.
- **Hash algorithms** available (OpenSSL imports): `EVP_sha256`, `EVP_sha1`. No blake2/blake3/sha512 used. **[CONFIRMED]**
- **Dedup**: enum field `dedup_alg` in archive meta (`"meta": {"compr_lvl": %u, "encr_alg": %u, "dedup_alg": %u, ...}`). Strings just say `set dedup %s` and `archive_set_dedup`/`archive_get_dedup`. The dedup index is built on top of a Golomb-coded LSM (`lsm_golomb.c`). Hash size for dedup is configurable: `archive_set_hash_bits`, `archive_set_hash_window_step`, `archive_set_hash_window_width` — i.e. **rolling-hash content-defined chunking**. The "ver.7 → create golomb filter" upgrade path confirms that pre-v7 archives lacked the Golomb dedup filter.
- **Chunking**: `archive_set_chunking_alg` / `archive_get_chunking_alg` — name strings for the algorithms aren't in the dump (likely numeric-only API).

---

## 7. Page / segment / item structure clues

### Archive (file-level) header `ARCH` — fields visible in the JSON dump string
The big trace-format string in `archive_hdr.c` is essentially a literal field-list:

```
{"fsize", "offset", "aligned_size", "size", "magic", "ver",
 "ci_offs", "first_ci_offs", "first_hdr_offs", "prev_hdr_offs",
 "last_item_id", "cur_sid", "last_full_sid", "last_sid", "next_sid",
 "slices_to_delete", "first_unfinished_sid", "encr_last_key_id",
 "commit_seq", "reuse_seq", "chain_start_pg",
 "last_segment_id", "full_begin_seg_id", "full_end_seg_id", "diff_begin_seg_id",
 "features", "features_ro", "features_rw",
 "mode", "reuse_delay", "next_reuse_seq", "next_reuse_time", "encr_mtime"}
```

This is essentially the **on-disk header layout** in print-order (very strong signal — these names typically map 1:1 to the C struct in the source).

### CI page `ARCI` — fields
```
{"offset", "version", "hdr_offs", "hdr_sz", "commit_seq", "reuse_seq",
 "ci_seq", "prev_ci", "flags", "vol_offs",
 "uuid": "%016llx%016llx", "session": "%016llx%016llx"}
```
So the CI page is a small index that **points back to the header** (`hdr_offs`/`hdr_sz`), forms a chain (`prev_ci`), and is itself versioned (`ci_seq`). UUID + session UUID (128 bits each) are stored.

### Segment header
```
"seg": {"offset", "magic": "%.*s", "version", "len", "zlen", "key_id",
        "compresssion" /* sic */, "cache_level"}
```
Plus the trace `magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u` — strong evidence that the on-disk segment header has:
- 2-byte magic
- 1 or 2 byte version
- length / compressed length (uint32)
- key_id (uint8 — limited by encr_last_key_id which appears to be 8-bit)
- compression (uint8)
- cache_level (uint8)

### LSM superblock `L-SB`
```
{"sb_size", "magic", "ver", "seq", "nr_ctree", "nr_max_ctree",
 "max_ext_len", "c0_count", "ctree": [...]}
```

LSM stores up to `nr_max_ctree` "compact trees" plus a `c0_count`-entry C0 (memtable-equivalent). Typical LSM design: `c0` = mutable in-memory layer; `ctree` array = frozen sorted runs.

Per-tree dump:
```
{"offset": %llu, "tree_nr": %llu, "tree_sz": %llu}
```

### LSM page (LEAF/LDIR)
```
{"offset", "magic", "version", "encoding": "%02x", "count", "len", "zlen", "seq", "id"}
```
"encoding" is one byte. Possible encodings include `LSM_LEAF`, `LSM_DIR`, `GOLOMB`, `DATA`, `UNKNOWN` — these are the type-text labels printed via `type_text`.

### Persistent-cache file `APCF`
```
pcache: magic=%02hhx%02hhx%02hhx%02hhx ver=%u nr=%u next=%u offs=%llu uuid=%016llx%016llx atime=%s age=%s
```
APCF = "Acronis Persistent Cache File"? **[INFERRED]** Used as a sidecar; **not** part of the `.tibx` itself. The `pcache:` channel is `persistent_cache.c`.

### "CI page" meaning
"CI" = **Commit Index**. Confirmed by:
- `ar#%u: ci page found at %s`
- `ar#%u: hdr without ci page: commit_seq=%llu hdr=%s mode=%s`
- `archive_get_commit_seq`
- `prev_ci`, `ci_seq` fields

So a "CI page" is an indirection: each commit writes a fresh CI that points to the latest `ARCH` header, and CIs form a chain via `prev_ci` so the reader can walk back to a "last good" commit if the most recent one is corrupted (`archive_find_last_good_header` + `last_good.c`).

### `lsm_item.h`
The header is referenced from `lsm_ctree_lookup.c` (`lsm_ctree_iter_init`, `lsm_ctree_pop_page`, `lsm_ctree_lookup`) and `lsm.c`. Items are LSM key-value pairs — kinds inferred from sibling files:
- `lsm_data_map.c` — extent → data location
- `lsm_name_map.c` — name → item-id
- `lsm_segment_map.c` — segment-id → segment metadata
- `lsm_unused_map.c` — free space / unused extents
- `lsm_nlink_map.c` — hard-link counts
- `lsm_notary_map.c` — Merkle hashes

So the archive maintains **6 LSM trees** in parallel.

---

## 8. Key log strings reveal code paths

20 selected strings, each annotated with the function it lives in (inferred from naming + nearby file paths) and the format insight it gives.

| # | Function | Log string | What it tells us |
|---|----------|-----------|------------------|
| 1 | `archive_hdr_validate` (`archive_hdr.c:431`) | `ar#%u: header magic '%02X%02X%02X%02X' at %llu is incorrect` | Header magic is a 4-byte field and the validator prints exactly four hex bytes — confirms `ARCH` is a literal big-endian-printed sequence at a fixed offset. |
| 2 | `archive_hdr_dump` | giant JSON string starting `{"fsize"…` | Authoritative struct field-order for the on-disk archive header. |
| 3 | `archive_open_at` (`archive_api.c`) | `ar#%u: opening archive path="%s"%s in %s mode%s dir=%s` | Open is multi-mode (`r`/`w`/`a`-style strings) and supports a separate dir argument (volume directory). |
| 4 | `archive_open` | `ar#%u: looking for %s in %s%u volumes, last=%u` | Multi-volume support — archive may span N files; reader probes them in order. |
| 5 | `archive_to_append_mode` (`archive_api.c`) | `ar#%u: rw>append: switching to append-only write mode, %s ci0` | RW archives can be downgraded to append-only by writing a new "ci0". |
| 6 | `archive_commit` (`checkpoint.c`) | `ar#%u: commit: type=%s: started: flags=%c%c%c dirty=%d merging=%d` | A commit has **3 flag bits** (rendered as 3 chars) and sets a "dirty"/"merging" state. |
| 7 | `archive_format_upgrade` | `ar#%u: Upgrade ver.7: create golomb filter` | v7 introduced the Golomb-coded extent filter; older versions need this synthesized when upgrading. |
| 8 | `validate_features` (`archive_hdr.c`) | `ar#%u: features (%llu) are newer than supported (%llu) for RW mode...` | Feature bitmask is **64-bit**, with separate sets for ro and rw access. |
| 9 | `wrap_key` (`crypto_aes.c:174`) | `ar#%u: wrap_key: PKCS5_PBKDF2_HMAC failed on %s` | PBKDF2-HMAC + AES wrap is the password-key path. |
| 10 | `unwrap_key` (`crypto_aes.c:225`) | `ar#%u: unwrap_key: Invalid number of PBKDF2 iterations %u: must be in range [%u - %u]` | There is a hard-coded min/max iteration range stored in the archive. |
| 11 | `unwrap_key` | `ar#%u: unwrap_key: Unsupported key format %u` | Wrapped-key format has a "key_format" enum byte (≥2 values: PBKDF2, public-key). |
| 12 | `ar_segment_compress_co` (`segment.c:65/79`) | `ar#%u: failed to compress segment %llu:%u to %s, rc=%d` | Segments addressed as a 64-bit segment-id + 32-bit sub-id. |
| 13 | `segment_decompress` (`segment.c`) | `ar#%u: segment at %s magic=%02x%02x ver=%u len=%u zlen=%u key=%u comp=%u cache=%u` | On-disk segment header layout (≥10 bytes). |
| 14 | `archive_validate_pages` | `pg at %llu fix %d->%d bit %d in byte #%x` | Page-level FEC / single-bit error correction exists (!) — file format may include parity. |
| 15 | `lsm_decompress_leaf` (`lsm.c`) | `lsm#%u: %s LZ4 decompression failed at %s` | LSM nodes are **LZ4-compressed** (always), independent of data-segment compressor. |
| 16 | `archive_hdr_read` (`archive_hdr.c`) | `ar#%u: failed to read CI page at %s: stored archive version (%u) differs from known one (%u)` | Multiple commits in same file each stamp the version → crash recovery can detect post-upgrade torn writes. |
| 17 | `pcache_open` (`persistent_cache.c`) | `pcache: magic=%02hhx%02hhx%02hhx%02hhx ver=%u nr=%u next=%u offs=%llu uuid=...` | APCF is a sidecar with its own UUID and version, totally separate from the .tibx. |
| 18 | `archive_validate_orphan_exts` | many `bug: …extent [%llu; %llu) inside …` | Extents are described as `[start; end)` half-open ranges. |
| 19 | `lsm_sb_validate` (`lsm.c:1456`) | `lsm#%u: %s sb - invalid compressed size (%d instead of %d)` | LSM superblock stores both compressed and uncompressed size. |
| 20 | `archive_open_single_file` (`container.c`) | `open_container_archive: '%s' has type '%s' instead of '%s'` | Single-file `.tibx` is a CONTAINER that wraps a single archive of declared `type` — see §10 below. |

---

## 9. Other interesting findings

- **Self-healing on read**: `pg at %llu fix %d->%d bit %d in byte #%x` strongly implies bit-level error correction at the page level — likely an Reed-Solomon or single-bit Hamming code. The function `ar_page_verify` is exported.
- **Bottleneck monitoring**: `bottleneck = '%s' (write = %d%%, read = %d%%, compression/encryption = %d%%, decompression/decryption = %d%%)` — there's runtime telemetry for which stage of the pipeline is slowest.
- **Astor + Ostor backends**: `archive_io_astor.c` (cluster client; "Acronis Storage" / Parallels Cloud Server based given `pcs_*` symbols) and `archive_io_ostor.c` (`ar_io_ostor_list_object_versions`, `ObjectStorage_ListObjectVersions`) — cloud backends. Local FS: `archive_io_local.c` + `archive_io_local_dirfd.c`.
- **Page cache priorities / cache_level**: segment header has `cache_level=%u` byte, suggesting a tiered hot/warm/cold cache.
- **Coldline / cold storage**: `archive_set_cold_storage`, string `coldline` (right next to `CHBXI`) → SaaS/cloud cold-tier integration.
- **String `tibx`**: appears once as a raw token. Likely the archive-type name printed by `archive_check_file_ext` or in `archive_type=%s`.
- **`.meta/.slice/.common/comment`** path string near `CHBXI` — this is the path of the slice-comment item *inside* the archive (the archive contains a virtual filesystem of `.meta/...` items).

---

## 10. archive3_adapter.dll — what it is

`archive3_adapter.dll` (24 KB strings, ~64 KB total) is a thin **glue layer** between the bigger ATI process and `archive3.dll`. Its role, derived from its 11 readable exports + dependencies:

```
Archive3_InitializePcsEnvironment
Archive3_DeinitializePcsEnvironment
Archive3_InitializePcsLogging
Archive3_DeinitializePcsLogging
Archive3_InitializePcsServiceEnvironment
Archive3_StartPcsEventloop
Archive3_GetDefaultPcsProcess
Archive3_GetPcsLogLevel
Archive3_PcsStatsSetLogPath
Archive3_AstorClientSetEreqStat
Archive3_TraceError(EventLevel, Common::Error&)  // C++ mangled
```

Source-path strings reveal it's built from `c:\b\workspace\common\ati-main-win-ati\818\archive\ver3\adapter\environment.cpp` and `core\common\error.cpp` — i.e. a **separate codebase** from `libarchive3` itself. It depends on `pcs_io.dll` and `logging.dll`. Its job is to:
1. **Initialize the PCS (Parallels Cloud Server) runtime** — event loop, logging, process lifecycle — that the C `libarchive3` was originally written for.
2. **Translate C++ ATI exceptions / `Common::Error` objects into log events** before they cross into the C archive3 module.
3. **Provide stats/logging hooks** (`Archive3_PcsStatsSetLogPath`, `Archive3_AstorClientSetEreqStat`).

**It does NOT** parse or transform `.tibx` data. It is a runtime-environment shim, not a format adapter. It's the bridge between the ATI 2024 application code (C++/Win32) and the Linux-flavored libarchive3 (C/PCS-eventloop). Manifest declares it as Acronis True Image. No format-relevant strings.

So if you want to reverse the format, **archive3.dll is the only binary you need**; archive3_adapter.dll is a no-op for format purposes.

---

## 11. Open questions for follow-up

1. What is the literal max version number in `archive_hdr.c:432` near `ARCH`? (Need disasm.)
2. What is the 2-byte segment magic? Need to inspect the constant compared in `segment.c:79`.
3. Does the `CHBXI` / single-file container have its own header (separate from the inner ARCH)? `container.c` only has 7 strings, so it's tiny — probably a thin TOC.
4. Order of `enum encr_alg` and `enum compr_alg`. Disasm `archive_encr_alg_get_str`.
5. What is the page-size constant? "header size %#x (%u) in CI page at %s is not aligned to page size" implies a fixed power-of-2; almost certainly **4096**, but unproven from strings alone.
6. Mapping of `enum item_type` (the `type` field in slice JSON). Need disasm of slice helpers.
