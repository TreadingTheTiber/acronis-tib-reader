# RESEARCH: archive3.dll Exports — Annotated

Source: `~/archive3_re/archive3_exports_full.txt` (raw `objdump -p` output, 25 521 lines).

Total **641 named exports**, organized by namespace. Numbers in parentheses are export counts in that namespace.

| Prefix | Count | Module / Role |
|--------|------:|---------------|
| `archive_*` | ~205 | Public C API |
| `ar_*` | ~145 | Lower-level helpers (also public) |
| `lsm_*` | ~80 | LSM tree primitives |
| `remote_*` | 108 | RPC-stubs (mirror of archive_/ar_io_/dir_ for out-of-process server) |
| `dir_*`, `file_*`, `cancel_*`, `event_*`, `temp_file_*` | ~30 | Common I/O building blocks |
| `pcs_*` | ~20 | re-exported from PCS runtime (event loop, BIO, log) |
| Crypto / X509 (`X509_*`, `EVP_*`, `BIO_*`, `RSA_*`) | ~50 | Statically-linked OpenSSL |
| LZ4 / Zstd | ~12 | Compression libs |
| `bg_*`, `sl_*`, `tx_*`, misc | ~30 | Background-task / slot / transaction helpers |

This document focuses on the **format-relevant** subset.

---

## 1. Lifecycle / open / close — entry points

```
archive_open                         // primary entry; opens a multi-volume .tibx
archive_open_at                      // opens at a specific volume + offset (recovery)
archive_open_single_file             // opens a single-file container (CHBXI envelope)
__archive_open                       // internal common path (also exported, oddly)
archive_close
archive_alloc / archive_free         // raw allocators around the archive_t object
archive_cancel                       // abort in-flight operations
archive_is_opened
archive_check_file_ext               // validates "*.tibx" suffix
archive_set_open_params              // min/max read-ahead in pages
ar_container_file_open               // single-file CHBXI container open
ar_container_get_archive
ar_container_get_info
```

The `_at` form taking volume index suggests the format places the **header at a known offset within a known volume**, not the start of the file (because archives can be append-only and grow).

---

## 2. Header / commit / version

```
archive_get_uuid                     // 128-bit archive UUID
archive_get_commit_seq               // monotonic commit counter (uint64)
archive_get_ctime / get_mtime
archive_get_size / get_volume_offset
archive_get_dir_features
archive_library_version              // returns hard-coded build version
archive_format_upgrade               // explicit ver-N → ver-(N+1) upgrade
archive_set_allow_upgrade
archive_set_compatibility            // emit older-format archives
archive_set_meta / get_meta
ar_meta_keys                         // string-table of meta-key names
archive_recover_last_good            // walk CI chain backward
archive_find_last_good_header        // direct `last_good.c` entry
archive_hdr_slice_print              // pretty-print to log (uses big JSON fmt string)
```

---

## 3. Encryption (most important for unsealing data)

```
// Setup
archive_encr_set_alg(alg)            // alg ∈ {none, aes-128/192/256-cbc/gcm}
archive_encr_alg_from_str / _get_str // string ↔ enum
archive_encr_get_alg / get_mtime
archive_encr_is_initialized
archive_set_pbkdf2_iter_log2(N)      // PBKDF2 iterations = 2^N
archive_copy_encr_setup              // clone setup from another archive

// Per-user keys (multi-recipient):
archive_encr_set_passwd / use_passwd
archive_encr_set_pub_keys / use_pub_keys / use_priv_key
archive_encr_has_user / rm_user
archive_encr_user_list_start / next / release

// Engine selection (OpenSSL provider):
archive_encr_set_engine
```

Internally (not exported but visible from strings):
```
wrap_key(password, ...)              // PBKDF2-HMAC-SHA? + AES-wrap
unwrap_key(...)
wrap_key_pkey(...) / unwrap_key_pkey // public-key path (RSA via EVP_PKEY)
```

The wrapped-key blob has fields: format-byte, key-size, PBKDF2-iter-count (with hard min/max range), algo-id. See `crypto_aes.c:174` and `crypto_aes.c:225`.

---

## 4. Page layer (low level)

```
ar_page_alloc / ar_page_free
ar_page_get / ar_page_put            // refcount
ar_page_read / read_async / read_wait
ar_page_write
ar_page_fill_header                  // build on-disk page header
ar_page_parse_header                 // decode it
ar_page_prepare_header               // populate before write
ar_page_verify                       // CRC + (likely) FEC bit-fixing
ar_page_set_error
ar_page_cache_init / free / dump
ar_page_cache_invalidate_page_range
ar_get_global_page_cache
```

`fill_header` and `parse_header` exported separately is **a strong signal** that the on-disk page header is a self-contained sub-record that's read/written by these two functions specifically — high-priority targets for Ghidra.

---

## 5. Segment layer

```
ar_segment_read                      // read+decompress+decrypt one segment
ar_segment_read_payload              // raw bytes only
get_segment_header_size              // returns sizeof(seg_hdr) — disasm gives the literal
lsm_key2segment_id                   // segment-id is the LSM key-encoding for segment_map
lsm_val2segment_info                 // decode segment-map LSM value
lsm_segment_find
archive_get_segment_map
archive_validate_segments / _ex
archive_validate_segment_refs
archive_remove_segments
archive_clean_orphan_segments
archive_fix_segment_refs
```

`get_segment_header_size` is the **single most useful export** for confirming the segment-header layout — call it (or read its constant return) and we have the exact byte-count.

---

## 6. Items / streams

```
archive_item_open / close / exists / undo
archive_item_add / del / del_batch / del_stream / link / rename
archive_item_complete                // finalize
archive_item_query / query_info / query_name_by_item_id / query_slice_range
archive_item_get_info / get_name / get_size / get_type / get_holes_size
archive_item_get_read_stream / get_write_stream
archive_item_get_stream_info / has_stream / has_links / is_dirty
archive_item_set_user_value
archive_item_batch_*                 // batched insert: capacity, item, size, add_init, add, cleanup
archive_stream_read / write / read_simple / write_shbuf
archive_stream_close / flush / truncate / punch_hole
archive_stream_get_size / get_changes / get_info / get_write_queue_size
ar_item_info_init / copy / free
ar_item_list_start / next / release  // directory enumeration
ar_item_list_versions_*              // multi-version enumeration
ar_item_link_list_*
```

Streams + items match a POSIX-like FS abstraction. `item_query_slice_range` confirms items are visible across multiple slices (incremental backup chain).

---

## 7. Slices (incremental-backup units)

```
archive_slice_create / create_ex / start_chain / finish / unfinished
archive_slice_export / export_ex     // standalone-export a slice
archive_slice_get_export_params
archive_slice_query / query_by_uuid / query_prev_or_eq
archive_slice_rm / rm_first / rm_range / cleanup
archive_slice_set_comment / set_ctime / set_ctime_now
archive_slice_get_base_uuid / get_comment / get_data_size / get_current
ar_slice_current_id / last / last_id / from_disk / to_disk
ar_slice_list_start / next / release
ar_slice_type_from_str
slice_features2str                   // (string) per-slice feature bitmask
```

`ar_slice_from_disk` / `_to_disk` is the slice-(de)serializer; the JSON dump confirms:
```
{"last_sid", "last_full_sid", "base_full_sid", "type", "features", "deleted",
 "user_size", "compr_size", "data_size", "ctime", "ftime", "uuid",
 "last_segment_id", "items": {"added", "changed", "removed"}}
```

---

## 8. LSM tree

```
lsm_init / fini / create / free
lsm_add / del
lsm_lookup_eq / ge / gt / le / lt / next
lsm_iter_init / release
lsm_flush / merge / merge_all / merge_wait_all / need_merge
lsm_set_merge_thresholds
lsm_automerge_resume / suspend
lsm_sb_create / sb_read              // L-SB superblock io
lsm_page_read
lsm_get_tree_nr / tree_sz
lsm_get_rd_stats / wr_stats / stats_dump / rd_stats_dump
lsm_dump_ctrees                      // dumps every ctree to log
lsm_visit_pgs / visit_golomb
```

Per-map specializations:

```
// data map (extent → location)
lsm_dmap_init / add / del / lookup / lookup_next / lookup_raw / iter_init / iter_release
lsm_dmap_end_offs
lsm_key2dmap_ext / val2dmap_ext_info

// unused-space map (free list)
lsm_umap_init / add / del / merge
lsm_umap_iter_init / iter_init_ex / iter_release / iter_reset
lsm_umap_lookup_ge / ge_in_range / lookup_next / lookup_next_in_range
lsm_alloc_umap_key
lsm_key2umap_ext

// segment map
lsm_segment_find
lsm_key2segment_id / val2segment_info

// nlink map
lsm_nlink_map_lookup

// notary (Merkle) map
lsm_notary_dump
lsm_notary_map_hash_alg / hash_size

// internal mem-tree (skiplist-like)
lsm_mem_tree_init / free / add / del / move / empty
lsm_mem_tree_lookup_ge / gt / le / lt
lsm_mem_node_first / last / next / prev
```

So **6 LSM maps** total, all running on a single LSM core. The "ctree" terminology indicates **compact tree** (a frozen, read-only sorted run; classic LSM nomenclature).

---

## 9. Compaction / commit / checkpoint

```
archive_commit                       // top-level commit
archive_compact / compact_async / compact_wait
archive_set_compact_thresholds
archive_set_autocommit / autocommit_params / set_flush_on_commit
archive_set_snapshot_on_commit
archive_set_reuse_delay              // grace before block-reuse
archive_set_punch_hole_thresholds
archive_punch_holes
archive_resparse
archive_transaction_start / finish
archive_set_temp_dir
archive_dont_flush_temp_lsm          // tuning knob for big imports
archive_pcache_open / disable / add_range / stat
```

---

## 10. Validation / repair

```
// Read-only verifiers (probably what the tibx_mounter uses to verify integrity)
archive_validate_hashes
archive_validate_holes_size
archive_validate_objects
archive_validate_orphan_exts
archive_validate_pages
archive_validate_segment_refs
archive_validate_segments / _ex
archive_validate_slices / _ex
archive_validate_space_usage
archive_validate_trees
archive_validate_user_size

// Repair (in-place fix)
archive_fix_dedup
archive_fix_holes_size
archive_fix_missing_objects
archive_fix_segment_refs
archive_fix_space_usage
archive_fix_user_size

archive_enum_corrupted_items
archive_recover_last_good
archive_dump_all_pages
archive_dump_ctree
archive_dump_headers                 // dumps ARCH header JSON to log
archive_io_set_ignore_crc_errors     // emergency-read mode
archive_io_set_reopen_timeout
archive_set_bottleneck_log_level
archive_get_io_error
archive_get_perf_stats
archive_stat_dump / stats_dump
archive_cache_dump
archive_io_get_disk_usage
```

`archive_dump_headers` is the **single best diagnostic export** — calling it on a target file logs the entire `ARCH` JSON via the format string in §2 of RESEARCH_TIBX_STRINGS.md.

---

## 11. I/O backends (multi-storage)

```
// Local FS
ar_io_open_local_dir / open_local_dir_dirfd / open_local_file
ar_io_local_dir_get_fd / local_path_is_network
ar_io_make_local_abs_path / append_local_path
ar_io_file_local_get_file / get_mode

// Astor (cluster client; pcs_io-based)
ar_io_open_astor_dir_cl / open_astor_file_cl
ar_io_astor_get_dir_client / get_file_client / get_file_stat
ar_io_astor_set_dir_timeout / set_file_timeout / set_*_ops_timeout
ar_io_wrap_astor_file
ar_io_is_astor_dir
ar_astor_is_deleted
astor_snapshot_*  // (visible in strings)

// Object Storage (cloud — S3/Azure-style)
ar_io_open_ostor_dir
ar_io_ostor_set_auth_cb / set_lock_server_auth_cb
ar_io_ostor_log_memory_stats
ar_io_ostor_list_object_versions     // versioned-object listing → cloud cold-tier
ar_io_is_ostor_dir
archive_set_ostor_compact_ratio

// I/O common
ar_io_init / fini
ar_io_set_dir / set_file / set_temp_file
ar_io_dir_create / destroy / get / put / get_path / is_local
ar_io_punch_hole / trunc / write_barrier / write_sync
ar_io_get_archive_size / bytes_read / bytes_written / stats / impersonate_token
```

---

## 12. Notary / Merkle proofs

```
archive_notary_item_add / query / status_query
archive_notary_proof_alloc / free / query
archive_notary_tree_complete / tree_root
archive_notary_hash_alg / hash_size
```

The "notary" is a Merkle tree built **per archive** that allows third-party verification that a file existed at a given snapshot without revealing other contents (proof generation: `archive_notary_proof_query`).

---

## 13. Container (single-file `.tibx`)

```
ar_container_file_open
ar_container_get_archive
ar_container_get_info
ar_is_container
archive_open_single_file
```

`open_container_archive: '%s' has %u slices instead of 1` confirms the container holds **exactly one slice + a single archive** inside a single `.tibx` file. Most likely the `CHBXI` magic is the container envelope, which is a thin wrapper before the inner `ARCH` blob.

---

## 14. `remote_*` namespace (108 exports)

Mirror of the local API for cross-process use. Every `remote_archive_X` and `remote_ar_io_X` invocation is presumably an RPC marshall around the matching local function. Not relevant to format reversing — they don't change the on-disk structure, just allow `archive3.dll` to be loaded in one process and called from another.

---

## 15. Top 10 exports to disassemble first

In priority order for advancing format understanding:

1. `archive_open` — read entry point: confirms initial offset, header size, version constant.
2. `ar_page_parse_header` — decodes the page header (universal across pages: archive, CI, segment, LSM).
3. `archive_hdr_slice_print` / `archive_dump_headers` — the function that uses the giant JSON format string; reading it backwards gives every field-offset of `struct archive_hdr`.
4. `get_segment_header_size` — returns a literal constant; compare with `ar_segment_read` to derive segment-header layout.
5. `archive_encr_alg_from_str` — has a string-table of all encryption algorithm enum values.
6. `unwrap_key` (in `crypto_aes.c`) — mapping from on-disk wrapped-key bytes → plaintext data key.
7. `lsm_sb_read` — parses `L-SB`, gives LSM superblock layout.
8. `ar_container_get_info` — parses `CHBXI` envelope.
9. `ar_page_verify` — likely contains the CRC algorithm (CRC32C? CRC32?) and the bit-fixup logic.
10. `archive_format_upgrade` — branch table by source-version reveals every prior format's structural differences (especially the v6 → v7 Golomb addition).
