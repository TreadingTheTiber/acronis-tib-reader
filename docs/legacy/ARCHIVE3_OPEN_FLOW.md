# archive3.dll — `archive_open` end-to-end flow

This document traces the full open path of a `.tibx` archive from
`archive_open(path, mode, ...)` down through every called function that
participates in opening. The intent is to enumerate (a) every operation an
external reader **must** perform to open a `.tibx` correctly, (b) every check
the official code applies, and (c) what error codes get returned at each step.

Confidence is annotated:

| Tag | Meaning |
|---|---|
| **C** | Confirmed via Ghidra decompilation in this study |
| **I** | Inferred from logging strings / naming conventions only |

Address conventions: addresses below are RVA-style `0x180009900` etc. as they
appear in the archive3.dll image base. Where a function has been given a
"Ghidra `FUN_…` placeholder name" we map it to a proposed legible name.

The error-code constants (always negative) returned along the way:

| Constant | Hex value (uint32) | Meaning |
|---|---|---|
| `EAR_INVALIDARG` | `0xffffec74` (-5004) | argument mismatch |
| `EAR_NOTFOUND`   | `0xffffec75` (-5003) | structural validation failure / not found |
| `EAR_NEWVER`     | `0xffffec64` (-5020) | "newer than expected" feature/version |
| `EAR_NOMEM`      | `0xffffec14` (-5100) | urandom / alloc failed |
| `EAR_BAD_VOL`    | `0xffffec15` (-5099) | bad volume reference |
| `EAR_NO_HEADER`  | `0xffffec77` (-5001) | last-good header search failed |
| `EAR_AUTOCOMMIT` | `0xffffec6b` (-5013) | autocommit retry exhausted |
| `EAR_REWRITE_NS` | `-0x138c`    (-5004) | rewrite mode unsupported |
| `EAR_NO_VOL_HDR` | `-0x139e`    (-5022) | no header in volume |

(Names are inferred from log strings; values are confirmed.)

---

## 1. Public entry: `archive_open` @ `0x180009900` (C)

```c
void archive_open(ctx_pp, dir, name, mode, errp) {
    archive_open_at(ctx_pp, dir, name, mode,
                    /*vol=*/0xffffffff,
                    /*cutoff=*/0xffffffffffffffff,
                    errp);
}
```

`archive_open` is a thin wrapper over `archive_open_at` with `vol=-1` and
`cutoff=-1` (i.e. open the very latest commit across all volumes). All real
work lives in `archive_open_at`.

## 2. The workhorse: `archive_open_at` @ `0x180009930` (C)

Signature reconstructed from decompiled body and surrounding callers:

```c
int archive_open_at(
    archive_t **ctx_pp,        // out: allocated context (already alloc'd)
    ar_io_dir_t *dir,           // io directory handle (local/astor/ostor)
    const char *name,           // archive base name
    uint32_t mode,              // 0=RO, 1=RW, 2=ANALYSIS (etc.)
    uint32_t vol,               // 0xffffffff = all/last
    uint64_t cutoff_us,         // 0xffffffffffffffff = newest
    int *err_out                // out: ar_error_t pointer
);
```

The caller is required to have already allocated `*ctx_pp` via `archive_alloc`
(see §3) before calling `archive_open*`. The signature above is preserved on
the public ABI — the parent `archive_open` simply delegates and discards the
return code.

### 2.1 Pre-flight argument checks (C)

```text
if (dir->flags & 0x8a0) and mode == REWRITE     -> log "rewrite mode is not
                                                    supported by ostor", -EAR_REWRITE_NS
if (dir->flags & 0x1000) and mode == REWRITE    -> log "rewrite mode is not
                                                    supported on astor",  -EAR_REWRITE_NS
```

Both rejections call `FUN_1800086e0(ctx, errp)` to clean up the ctx skeleton.

### 2.2 Build a "where am I opening from" log tag (C)

A small fixed-size buffer (`local_b8`, 64 bytes) is filled with one of:

| Cutoff | Vol | Format string |
|---|---|---|
| -1 | -1 | `""` |
| -1 | k  | `at vol %u` |
| t  | -1 | `at vol last, offs %llu` |
| t  | k  | `at vol %u, offs %llu` |
| t  | -1, ostor | `at cutoff %llu (%s)` (timestamp formatted) |

Used purely for human-readable logs; not part of validation.

### 2.3 IO directory bind: `FUN_18000d0b0` → `ar_io_set_dir` (C)

`FUN_18000d0b0(ctx + 0xd, dir, name, mode, &cutoff)` chooses between two
paths depending on whether the dir handle is an "ostor" object-store dir:

* ostor + cutoff != -1 → `FUN_1800225e0` (snapshot dir at cutoff) →
  `ar_io_set_dir(...)` → `ar_io_dir_put(...)` (releases the temp).
* otherwise → `ar_io_set_dir(io_block, dir, name, mode)` directly.

After this returns, `ctx->io_block` is wired up but no file has been opened;
`ar_io_set_dir` only stages dir/name/mode.

The proposed name is **`archive_attach_dir`**.

### 2.4 Mode-derived flag fix-ups (C)

```c
if (ctx->iflags & 0x400 && ctx->cache_size < 0x100000)   // 1 MiB minimum
    ctx->cache_size = 0x100000;
if (mode == 0)  // RO
    ctx->oflags &= ~0x40;   // clear "expect-write" bit
```

### 2.5 Coroutine context binding (C)

* `pcs_thread_tls()` → grabs the TLS block.
* `pcs_context_get(...)` saves the previous coroutine ctx into `local_140`.
* `pcs_co_set_ctx(ctx[0x91])` swaps to this archive's coroutine context.

The previous ctx is restored at the end via `FUN_18000a0e0` (§5).

### 2.6 Banner log (C)

```
ar %u: opening archive path '%s'   (mode '%s', cap_flags 0x%x)
```

### 2.7 Sanity assertion (C)

```c
if (*((char *)ctx + 0x13cc) != 0)   // "already open" marker
    pcs_bug_at(...)
```

This is a hard fail — the alloc'd ctx must not have been used to open
anything before.

### 2.8 Locate a viable header — call into `archive_load_header` (C)

```c
local_184 = 0x10;  /* cap on number of volumes in array */
res = archive_load_header(
    ctx,
    /*vol_array_out=*/local_f8,        // up to 16 volume IDs
    /*want_recovery=*/(mode & 0x100) != 0,
    /*vol_count_inout=*/&local_184,
    /*requested_vol=*/vol,
    /*cutoff=*/cutoff_us,
    /*errp=*/&ctx->err);
if (res < 0) goto fail;
```

Detailed in §6 below. The 0x100 mode bit selects "use the recovery scanner
(`archive_scan_for_last_good`) for choosing the CI page". On a fresh open of
a clean archive this is normally false; we only enable it when rebuilding
after a torn write.

### 2.9 Astor capability fallbacks: `FUN_1800161f0` (C)

After header is loaded, the code checks if dir is an Astor (Acronis storage)
directory and adjusts cache budgets based on declared features. This only
fires when:

* `ctx->mode_state == 0` (still in initial open phase)
* dir is astor (`ar_io_is_astor_dir` = true)
* astor advertises feature bit 1 (`astor_client_get_features` & 1)

When triggered it disables flag bit 0x4 of `ctx[0x38]`, sets cache to
5/16/32 MiB based on physical RAM, and calls `FUN_18001bee0` to apply.

This is **optional** / capability-driven — failures here don't fail open.

### 2.10 Object-history table allocation: `FUN_180015eb0` (C)

If `dir->capabilities & 0x80` (object history supported) is set, the code
allocates `ctx[0x658]` = an object-history table sized
`(volume_size / 0xc000)` slots × 0x28 bytes, pre-initialising every slot to
the current EOF offset. This corresponds to the "Object history not
supported" / "invalid object history size" errors referenced later in
`FUN_1800155d0`.

### 2.11 Header record validation chain (C)

```c
if (load_header_res == 0) {
    res = FUN_180014140(ctx);              // archive_validate_header_record
    if (res != 0) goto fail;

    res = FUN_18000c740(ctx);              // ostor flag consistency check
    if (res != 0) goto fail;

    FUN_180010c90(ctx);                    // wire up encryption codecs

    if (ctx->mode_state != 2 /*ANALYSIS*/) {
        // walk all volumes whose ID > the current "primary" vol
        // and run FUN_1800367c0 (delete leftover-volume) on each.
        // Different code path if vol == -1 (use rb-tree of vols)
        // vs. vol set explicitly (use range from FUN_1800359c0).
        // Errors propagate via ar_error_move into ctx->err.

        // If primary slot is empty, recreate via FUN_180035c30 +
        // FUN_180035f20.

        if (vol != -1 || cutoff != -1)
            ctx[0x13cd] = 1;  // mark "we have stale state to clean"

        FUN_180003980(ctx);  // schedule async alloc-cache populate (RW)
    }

    res = FUN_180009fb0(ctx);  // archive_validate_slices_and_version
    if (res != 0) goto fail;

    sub_res = FUN_180006d20(ctx);   // mark-RO-if-no-write checkpoint
    res = FUN_18000d690(sub_res, ctx);  // demote-to-RO autocommit cycle
    if (res < 0) goto fail;

    if (res == 0 && FUN_18001a600(ctx + 0xd) /* needs checkpoint */) {
        log "ar %u (R/O): writing checkpoint to ..."
        sub_res = FUN_18000e050(ctx);
        res = FUN_18000d690(sub_res, ctx);
        if (res < 0) goto fail;
    }
}
```

`FUN_180014140` is the "fully read & verify the header record from the
loaded CI page" routine — see §7.

`FUN_18000c740` rejects an archive whose stored object-storage flag does not
match the IO dir's class. Specifically:

```c
hdr_obj_storage = ctx->iflags & 0x80;
ctx_obj_storage = ctx->stored_flags & 4;
if (hdr_obj_storage != ctx_obj_storage)
    log "object storage flag does not match", return -EAR_NOTFOUND;
```

`FUN_180010c90` plugs page-encryption codec hooks into all 8 LSM tree control
blocks (offsets 0x1078, 0x1088, 0x1090, 0x10e8, 0x10a8, 0x10b8, 0x10f8,
0x12b0). It only fires if `ctx[0x1e69]` (the on-disk "encryption alg" byte
at hdr offset 0xd) is non-zero. The codec functions installed are
`FUN_1800122d0` (decode) and `FUN_180012350` (lookup). Two of the trees
(0x1078 = chunkmap-by-hash and 0x10a8 = chunkmap-by-id) get an additional
"is page encrypted?" bit toggled from `ctx->encrypted_flags >> 4`.

### 2.12 Recovery branch (load_header_res > 0) (C)

If `archive_load_header` returns a positive value, that means "a partial
header exists but we deferred recovery to the caller"; this is the
torn-write / corrupt-tail recovery path. The code then:

1. Sets `ctx->iflags |= 0x20` ("opened with recovery").
2. Schedules a recovery deadline `ctx[0x3c9] = now_ms + ctx[0xcd]`.
3. Calls `pcs_get_urandom(ctx[0x3cb], 16)` → 16 random bytes used as a
   recovery "session" identifier (and as a per-open object-storage GUID).
   Returns `-EAR_NOMEM` if urandom fails.
4. Calls `FUN_1800181d0` to push the volume size back to the IO layer.
5. Calls `FUN_180057ba0(...)` to allocate the recovery work unit.
6. Calls `FUN_1800189d0` to set the IO seed.
7. Calls `FUN_1800094a0(ctx)` (post-header init) followed by
   `FUN_180006d20`/`FUN_18000d690` cycle.

### 2.13 Final wiring (C)

```c
lsm_automerge_resume(ctx[0x21f]);
FUN_18000a3c0(ctx, &local_138);  // archive_register_open
```

`FUN_18000a3c0` calls `archive_get_space_usage(ctx, &usage_info)`,
`FUN_18000c790`, `FUN_180006dc0`, then links the ctx into one of two global
linked lists:

* If `ctx->mode_state == 2` (analysis): `PTR_LOOP_180095a18` chain
* Else: `PTR_LOOP_180095a08` chain

and increments the corresponding global counter (`DAT_1800c99c8` or
`DAT_1800c99d8`). It also sets `ctx[0x13cc] = 1` ("now open").

### 2.14 Epilogue: `FUN_18000a0e0` (C)

```c
int archive_open_finish(int rv, archive_t *ctx, uint mode, ulonglong *usage,
                       pcs_ctx prev, int *errp);
```

* Restores the saved coroutine context: `pcs_co_set_ctx(prev)` /
  `pcs_context_put(prev)`.
* On success (rv == 0): logs "opened archive path '%s'", calls
  `FUN_180007d20` to format a multi-line `ar_dump_state` summary at debug
  log level 2, and exposes "stored" and "current" slice info via
  `FUN_18002d880`.
* On failure: logs `failed to open archive path '%s'` with the textual
  `ar_strerror(rv)`, the archive UUID, and the requested mode, then calls
  `FUN_1800086e0(ctx, errp)` to free the ctx skeleton.

Returns `rv` to the caller.

---

## 3. `archive_alloc` @ `0x180007230` (C)

This is the **prerequisite** to `archive_open`. It allocates a 0x1f98-byte
zeroed `archive_t`, calls `ar_io_init(&ctx->io_block)` to bring up the IO
layer, and pre-fills sane defaults:

| Offset | Default | Field |
|---|---|---|
| 0x10  | 8        | expected version (latest = 8) |
| 0x14  | `\| 6`   | flags: allow upgrade + ??? |
| 0x18  | 50       | log channel id |
| 0x20  | 1 GiB    | max archive size |
| 0x28  | 4096     | page size |
| 0x30  | 500      | flush threshold |
| 0x34  | 256 KiB  | chunk threshold |
| 0x38  | 4 MiB    | dedup window |
| 0x12f8/0x1300 | -1 | uninit volume / commit ids |
| 0x4b0/0x4b8/0x4c0 | -1 | first/last/current CI offsets |
| 0x1e68 | 2       | hash alg = SHA-256 |
| 0x654  | 2       | mode = ?? |
| 0x824  | 2       | another default |
| 0x13b0 | 1       | "fresh" flag |
| 0x13b8 | 16 MiB  | LSM page-cache budget |
| 0x13c0 | 5 min   | autocommit interval (300000 ms) |

The caller wires hashing/encryption/options via `archive_set_*` setters
**before** calling `archive_open*`.

---

## 4. Where `archive_open_at` reads & validates the on-disk header

This is the most critical chain. Everything below is part of step 2.8/2.11.

### 4.1 `archive_load_header` @ `0x180004ab0` — function body summary (C)

Pseudo-flow (showing only error-relevant control flow):

```text
archive_load_header(ctx, vols_out[16], want_recovery, &nvols, vol, cutoff, errp):
    if (*nvols == 0)                                  pcs_bug
    if (vol == -1):
        rc = FUN_180035850(ctx->io, vols_out, &nvols, errp)
        if (rc) -> log "failed to find archive files: %s (rc)"; return rc
        if (*nvols == 0) { vols_out[0] = 0; *nvols = 1; }
    else:
        vols_out[0] = vol; *nvols = 1;
    if (cutoff != -1 && *nvols > 1):
        log "archive volume for open at point in time must be a single one"
        return -EAR_BAD_VOL  # 0xffffec15
    single_vol_mode  = (*nvols == 1 && vols_out[0] == 0)
    is_object_store  = (ctx->iflags >> 7) & 1
    want_recovery_   = want_recovery && single_vol_mode &&
                       (ctx->mode_state != 2) && (vol == -1)

    if (is_object_store):
        rc = FUN_1800173a0(ctx->io, want_recovery_, errp);  // open io for read
        if (rc) return rc;
        rc = FUN_1800172a0(ctx->io, FUN_1800193a0(ctx->mode_state), errp);
                                                              // acquire dir lock
        if (rc) return rc;
        full_scan_via_object_store = false
    else:
        full_scan_via_object_store = ((ctx->iflags & 0x800)==0 &&
                                      cutoff==-1 && vol==-1)

    if (full_scan_via_object_store):
        log "ar %u: looking for ANY in single-volume archive"
    else:
        log "ar %u: looking for last_CI in %s%u volumes"

    if (full_scan_via_object_store):
        rc = FUN_1800388b0(ctx, want_recovery_, errp)  // archive_scan_for_last_good
        if (rc == -EAR_NO_VOL_HDR) {
            if (mode != ANALYSIS) return rc;
        } else if (rc < 1) return rc;

    for i in 0 .. *nvols-1:
        cur_vol = vols_out[i]
        cached  = FUN_180035560(ctx->io, cur_vol)  // existing volume entry?
        if (cached && cached->raw_hdr_buf):
            // Already have the buffer, take it from the dir cache.
            local_buf = cached->raw_hdr_buf;
            cached->raw_hdr_buf = NULL;
        else:
            rc = FUN_180035f20(ctx->io, &local_buf, want_recovery_locked, errp);
                                              // archive_open_volume_for_header
            if (rc == 0) goto have_buf;
            if (rc != -EAR_NO_VOL_HDR) return rc;
            if (vol != -1) {
                log "archive volume %u is not found"
                goto fail_no_header_recover_check
            }
            if (single_vol_mode) goto fail_no_header_recover_check
            ar_error_fini(errp)
            continue

        have_buf:
            cutoff_for_this_vol = (cur_vol == vol ? cutoff : -1);
            rc = FUN_180038770(ctx, &local_buf, cutoff_for_this_vol, errp)
                                              // archive_load_volume_ci_page
            // see §4.2
            if (rc == 0) { *nvols = i; return 0 }
            if (rc > 0 && want_recovery && !ctx->stored_flags) {
                if (!is_object_store) { *nvols = i; return rc }
                // else fall through to torn-write fallback
            }
            if (rc == -EAR_NO_VOL_HDR) {
                fail_no_header_recover_check:
                if (!want_recovery_locked || !is_object_store) return rc
                // Torn-write recovery branch:
                ctx->stored_flags |= 4
                FUN_1800354b0(ctx->io, 0)
                FUN_1800181d0(ctx->io, ctx->volume_size)
                ctx->volume_size  = ...
                ctx->ci_offsets   = (volume_size - mod) - X
                ar_error_fini(errp)
                return 1   // signals "use FUN_18000d690 recovery branch"
            }
            if (rc < 0) return rc

    log "ar %u: can't find header in %u volume(s)"
    return -EAR_NOTFOUND  # 0xffffec75
```

#### Key called functions (summary):

| Addr | Proposed name | What | Confidence |
|---|---|---|---|
| `0x180035850` | `archive_io_list_volumes` | Walk dir for archive name pattern, populate vols_out array (RB-tree of volume IDs sorted descending) | C |
| `0x1800359c0` | `archive_io_collect_volumes` | RB-tree builder used by both list_volumes and the post-header janitor pass | C |
| `0x180035560` | `archive_io_lookup_volume` | Find cached volume entry | I (only seen as call) |
| `0x180035f20` | `archive_open_volume_for_header` | Open volume file at `(name).<vol>.tibx`, acquire shared/excl. lock per `ctx->mode_state`, store handle into vol_entry+0x28 | C |
| `0x1800173a0` | `ar_io_open_dir_for_read` | astor/ostor open op | I (call only) |
| `0x1800172a0` | `ar_io_acquire_lock` | mode→lock-class → call dir_op[0x60] | I |
| `0x1800193a0` | `ar_mode_to_lock_class` | mode → 0/1/2 lock kind | I |
| `0x1800388b0` | `archive_scan_for_last_good` | object-store: scan stream for last good CI page, returning its file location into local buf. Returns 1 on success, -EAR_NO_VOL_HDR on miss, <0 on hard error. Wraps `FUN_180039df0` (CI iter init) + `FUN_180039340` (search). | C |
| `0x180038770` | `archive_load_volume_ci_page` | Given a volume's open file, walk the CI chain (newest→oldest) until one validates, then call `FUN_1800398c0` (apply selected CI to ctx). Internally uses `FUN_180039df0` (CI iter init) + `FUN_180039f10` (next) + `FUN_180038990` (validate). | C |
| `0x1800180d0` | `ar_io_postprocess_dir_handle` | sets up legacy non-objstore name |  I |

#### Returned values from `archive_load_header`:

* `0`  — header successfully loaded into `ctx[0x4a8]` (raw page buffer)
* `1`  — recovery requested (object-store, torn write detected); caller must
  run the demote-to-RO + recovery commit cycle
* `-EAR_NOTFOUND` (0xffffec75) — no valid header anywhere
* `-EAR_NO_VOL_HDR` (-0x139e) — specific volume missing
* `-EAR_BAD_VOL`   (0xffffec15) — caller mis-specified vol with cutoff
* IO errors from the dir layer pass through unchanged.

### 4.2 `archive_load_volume_ci_page` @ `0x180038770` (C)

The CI walker. Takes a buffer descriptor for one volume:

1. `FUN_180039df0(ctx, &iter, vol_buf, cutoff)` → initialise iterator
   pointing at the **last** CI offset `ctx->stored_last_ci`. The iterator
   captures: iterator state, dir-op vtable, page size = 0x2800 (10 KiB),
   read budget = 4 MiB (`0x400000`), and applies the encryption flag from
   `ctx->iflags & 0x100`. Returns 0 / IO error.
2. Loop: `FUN_180039f10(&iter)` (read+CRC validate next CI page) → if returns
   `>0` (page is good) call `FUN_180038990(&iter)` (validate against ctx
   constraints — sequence ordering, version, etc). Continue while validate
   says "go further back".
3. When walk terminates with an authoritative page, call
   `FUN_1800398c0(&iter, vol_buf, off, gen)` to copy the chosen page into
   `ctx[0x4a8]` (the canonical "we picked this header" buffer).
4. `FUN_1800180d0` is invoked when the volume is **not** object-store and
   `ctx->raw_dir_handle != 0`: reattaches the dir handle for legacy paths.
5. `ar_error_move(errp, iter.err)` propagates IO error.
6. `__pcs_free(iter.scratch)`.

Return values:

* `0`  — chosen page applied to ctx; open continues with this header.
* `1`  — no commit info found in volume (logged as "no commit info found in
  volume %u (last_CI %llu)"). Caller may treat as "use this volume but
  recovery needed" depending on flags.
* `-EAR_NO_VOL_HDR` — first CI page itself failed CRC.
* `<0` — IO error.

### 4.3 `FUN_180014140` @ `0x180014140` — header record loader (C)

Proposed name: **`archive_validate_header_record`**.

Body:

1. Sanity: `ctx->ci_page_size & 0xfff == 0` (must be page-aligned; bug if
   not).
2. `block_payload_cap = (ctx->ci_pages_per_record >> 12) * 0xff8`.
   If < 1024, bug.
3. Take ownership of the picked CI page buffer: `pi = ctx[0x4a8]; ctx[0x4a8] = 0`.
4. `if (pi[0] != ARCI_MAGIC)` → log "ar %u: header magic 0x%02X..." and
   return `-EAR_NOTFOUND`.
5. Big-endian read `payload_size = pi[1]` (u32 BE). If `block_payload_cap < payload_size`
   → log "stored header offs..." and return `-EAR_NOTFOUND`.
6. Big-endian read `version = pi[2:4]` (u16 BE).
7. **Version gate:** `if (version >= 9)` → log "version (%d) is newer than
   max_supported (8)" and return `-EAR_NEWVER` (0xffffec64).
8. `FUN_180014fe0(ctx, pi)` — apply the **fixed-layout fields** of the
   header record to the ctx (UUID, version, commit/CI seqs, slice list
   offsets, hash alg, dedup alg, feature bitmap…). Returns
   `0`/`-EAR_NOTFOUND`/`-EAR_NEWVER`. See §7.
9. `FUN_1800094a0(ctx)` — post-header init (allocates LSM trees with sizes
   from header).
10. `FUN_1800155d0(ctx, pi)` — parses the **TLV-extended directory** appended
    after the fixed header, reads each LSM tree's superblock, optionally
    parses the object-history dump. Calls `FUN_180015a30` (TLV walker), then
    `FUN_180036170` (hdr-size check vs. archive size?), then 8 calls to
    `lsm_sb_read` (one per LSM tree control block at the offsets we recorded
    earlier), then either `FUN_180051dd0` for the post-v6 extra tree
    (chunkmap_v2) or skips. Returns errors directly — first failed
    `lsm_sb_read` aborts. See §8.
11. RW open with mode==1 + iflags&0x100: pre-allocate space at
    `ctx->stored_eof` via `FUN_180037d00` and force-sync via
    `ar_io_write_sync`. (mandatory for RW upgrade; failure aborts open).
12. `FUN_180014820(ctx, pi, &trim_bytes)` — slice-list / EOF reconciliation.
    See §9. Returns 0 / -EAR_NOTFOUND / IO err.
13. RW only: bump `ctx->commit_count`, push `ctx->next_commit_seq` into the
    primary LSM at offset 0x550/0x558, run `FUN_180012b70` for upgrade
    bookkeeping if mode==1.
14. If FUN_180014820 reported a tail to free (`trim_bytes != 0`), call
    `ar_space_free(ctx, off>>12, len_pages)` and
    `FUN_18005af50(ctx->io, off, off+len)` to release the unused tail
    region (logged as "archive_file_unused_tail freed (...)").
15. `__pcs_free(pi)` always.

### 4.4 `FUN_180014fe0` — fixed-field header parser (C)

Proposed name: **`archive_apply_header_fields`**.

In strict order, with byte-swap from BE to host:

| Source (offset) | Destination (ctx offset) | Check |
|---|---|---|
| 0x20..0x2f | 0x1e58..0x1e67 (UUID) | *if* already set, must match (else `-EAR_NOTFOUND`) |
| 0x08 (u16 BE) | 0x10 (version) | must equal `ctx->expected_version` (default 8) |
| 0x178 (commit seq) | 0x12c0..0x12c8 | must be ≤ ctx->known_commit_seq |
| 0x180 (commit ts) | 0x12b8 | bug if exceeds known commit seq |
| 0x190 (1st CI offs)  | 0x4d0/0x4d8 | mirror of commit seq/ts |
| 0x178 then again | 0x4b0 / mirror, must equal stored "first_CI_offset" |
| 0x188 (CI seq) | 0x4b8 | must be ≤ ctx->known_ci_seq |
| 0x198 (last CI seq) | 0x4b8 (overwrite) | — |
| 0x38 (max archive size) | 0x500 | — |
| 0x16c | 0x514 | (chunking-related u32) |
| 0x48 | 0x64c | (page-cache hint?) |
| 0x4c | 0x650 | (chunk size?) |
| 0x50 | 0x10e0 | (block-size?) |
| 0x174 (mode) | 0x654 (via FUN_180038720 normalize) | warn if changed since last open |
| 0xe8..0xf7 | 0x508..0x517 (slice 1) | via `ar_slice_from_disk` |
| 0xdc | 0x57c (u32 BE) | (slice flags?) |
| 0xe0..0xe7 | 0x5d8 (u64 BE) | (slice ts?) |
| 0x58..0x67 | 0x570..0x57f (slice 2 / "current") | via `ar_slice_from_disk` |
| | 0x511 / 0x579 | bool flags from `FUN_180034620` (slice validity) |
| 0x40 | 0x670 | — |
| 0x1f8/0x200/0x208/0x210 | 0x678/0x680/0x688/0x690 | counters |
| 0x54 | 0x648 | — |
| 0x10 (volume_size) | 0x1e48 | — |
| 0x18 (chunk_size) | 0x1e50 | — |
| 0x170 (mtime) | 0x1ee8 | — |
| 0x247 (atime?) | 0x1e70 | — |
| 0x0d (encr_alg) | 0x1eee | must be < 2 (only known alg) else `-EAR_NOTFOUND` |
| 0x0c (dedup_alg) | 0x1eed | must be < 2 else `-EAR_NOTFOUND` |
| 0x1c8 | (passed to `FUN_1800181d0`)  | volume-size hint to IO |
| 0x1b0 | 0x12e0 | bytes_read_total |
| 0x1d0 | 0x12e8 | bytes_written_total |
| 0x1d8 | 0x12f0 | dedup_saved_total |
| 0x1b8 | 0x11b8 | counters |
| 0x1c0 | 0x11c0 | counters |
| 0x223 | 0x90  | (ID counter) |
| 0x22b | 0x98  | (ID counter) |
| 0x233 | 0x12c8 (u32) | — |
| 0x237 | 0x12d0 | — |
| 0x23f | 0x12d8 | — |
| 0x1e0 (flags qword) | 0x40 | — |
| 0x1e8 (feature_used)| 0x50 | features-mask |
| 0x1f0 (feature_required) | 0x48 | features-mask |

**Feature bit gate (the version-too-new path):**

```c
known_features = ctx->supported_features;       // ctx[0x58]
if ((feature_used >> 9) != 0) -> "features 0x%llx are newer than 0x1ff (...)"; return -EAR_NEWVER;
if (mode != 2 /*ANALYSIS*/ && (feature_required >> 9) != 0) -> same, return -EAR_NEWVER;
extra_used     = feature_used     & ~known_features
extra_required = feature_required & ~known_features
if (extra_used)     -> "features 0x%llx are newer than 0x%llx (...)" (with codec name); return -EAR_NEWVER;
if (extra_required && mode != ANALYSIS) -> same; return -EAR_NEWVER;
```

Mask `0x1ff` = 9 known feature bits. The codec name comes from
`FUN_18000d010(supported_features_idx)`.

If version < 2, the v2-only fields at 0x1d0..0x3ff are zeroed before being
applied (legacy compat).

### 4.5 `FUN_1800155d0` — TLV / superblock loader (C)

Proposed name: **`archive_parse_header_tlv_directory`**.

Calls in order:

1. `FUN_180015a30(ctx_log_id, &local_directory, header_buf)` — invokes the
   TLV walker (per the TLV agent's notes) and produces a `directory[20]` of
   pointer/length pairs. Return 0/error.
2. `FUN_180036170(ctx->io, name_table_off, name_table_len)` — pre-loads the
   archive base-name string table referenced by the TLV directory.
3. Pulls 20 NUL-terminated strings from the name buffer into
   `ctx[0x1da8 .. 0x1da8 + 8*20]` via `__pcs_strdup`. (These are the
   per-tree symbolic names: `chunkmap_idx`, `chunkmap_data`, `umap`,
   `dmap`, etc.)
4. Dedup re-arm: if `dedup_alg != 0` and not analysis:
    * `local_c0 == 0` → `archive_set_dedup(ctx, 1)`
    * `local_c0 == 12` → big-endian copy of 3 u32s from the header into
      `ctx[0x1ef0..0x1efc]` (dedup parameters: window, min, max).
5. **Eight mandatory `lsm_sb_read` calls** (one per tree). Authoritative
  TLV slot ↔ arch-offset ↔ tree-name table is in
  `ARCHIVE3_TLV_DIRECTORY.md`; in summary:

  | TLV | ctx offset | C-source name | User-facing alias |
  |----:|------------|---------------|-------------------|
  | 0   | 0x1078     | `imap`        | `lsm` (meta)      |
  | 1   | 0x1088     | `dmap`        | `data_map`        |
  | 2   | 0x1090     | `segment_map` | `segment_map`     |
  | 3   | 0x10e8     | `dedup_map`   | `dedup_map`       |
  | 4   | 0x10a8     | `nlink_map`   | `nlink_map`       |
  | 5   | 0x10b8     | `smap`        | `slices`          |
  | 6   | 0x10f8     | `umap`        | `umap`            |
  | 7   | 0x12a8     | `keymap`      | `keymap`          |

  (The earlier table here had heuristic tree names that turned out to
  be wrong — see the canonical doc.) Any failure aborts.

6. **v7+ only**: `lsm_sb_read(ctx[0x12b0])` (extended LSM tree, likely
  encryption-key-store), then a 19-byte struct (3 bytes flags + u64 offset)
  is copied into a stack frame and passed to `FUN_180051dd0(ctx[0x12b0],&local)`.

7. `FUN_18004aa10(ctx, scratch, scratch_len)` — yet-another-init (probably
  global allocator-bitmap state). If non-zero → return.

8. **Object history (post-v? feature):** if `local_a0 != 0`:
    * Require `ctx->iflags & 0x80` (objstore) else
      `"object history is not supported (...)"`, `-EAR_NOTFOUND`.
    * Require `local_a0 == 0xb70` else
      `"invalid object history size (...)"`, `-EAR_NOTFOUND`.
    * BE-copy the 0xb70-byte block into `ctx[0x658]` (the table allocated
      back in §2.10).

9. Suspend automerge on item-index tree, run `FUN_180054130` (LSM root
  apply for that tree using a u64 offset / u32 size from the header),
  resume automerge.

### 4.6 `FUN_180014820` — slice list / EOF reconciliation (C)

Proposed name: **`archive_validate_slices_and_trim_tail`**.

Branches:

* **Object-store mode** (`stored_flags & 4`): require slice-list size,
  ctx->next_alloc, and ctx->next_dealloc all be multiples of volume-size;
  bug otherwise. Set ctx EOF (`+0x80/0x88`) to slice-list end and return.
* **Local mode**:
  1. `cur_size = ar_io_get_archive_size(io)`.
  2. If `cur_size == on_disk_size`: nothing to do, return 0.
  3. If `cur_size < on_disk_size`: log "archive file size (%llu) is less
     than expected (%llu)" → `-EAR_NOTFOUND`.
  4. `cur_size > on_disk_size` (file has tail): if the ctx's stored
     `last_known_eof` differs from the header's recorded `prev_known_eof`
     (BE-decoded at hdr offset 0x1a8), then:
       * Run `FUN_180038570(ctx, prev_eof)` (re-read previous CI from
         that offset to refresh ctx state).
       * Cross-check UUID, commit-seq, CI-seq for monotonicity (4 separate
         `-EAR_NOTFOUND` paths if any goes backwards).
  5. **Truncate** the tail: acquire write-lock (`FUN_1800172a0(io, 2, 0)`),
     `ar_io_trunc(io, hdr_size, &local_err)`, downgrade lock back to
     read (`FUN_1800172a0(io, 1, &ctx->err)`).
       * If trunc succeeded: log "archive file unused tail freed",
         release in-memory range `FUN_18005af50(io, hdr_size, prev_eof)`.
       * If trunc failed with `-EAR_INVALIDARG` or `-EAR_NOTFOUND`: try
         to *page-align* the existing size by reading and re-writing
         the misaligned tail (only for non-local astor). Otherwise
         propagate.
  6. Set `*trim_bytes_out = (cur_size_after - on_disk_size)`.
  7. Returns 0 (mandatory: any IO error fails open).

### 4.7 `FUN_180009fb0` — slice and version reconciliation (C)

Proposed name: **`archive_validate_slices_and_version`**.

```c
if (ctx->version < 2) {
    ctx->bytes_used = 0;
    ctx->bytes_total = 0;
    iter = ar_slice_list_start(ctx, scratch_3kb);
    while (iter > 0) {
        ctx->bytes_total += iter.bytes_total;
        ctx->bytes_used  += iter.bytes_used;
        iter = ar_slice_list_next(scratch);
    }
    ar_slice_list_release(scratch);
    if (iter < 0) return iter;
}
if (mode != ANALYSIS) {
    if (ctx->open_flags & 2 == 0) {                  // upgrade not allowed
        if (version != 8 && version != 7) {
            log "Upgrade is not allowed, archive version=%d"
            return -0x138f;     // EAR_UPGRADE_DISABLED
        }
    } else {                                         // upgrade allowed
        if (version != 8 ||
            (ctx->stored_flags & 0x20) == 0 ||
            ((ctx->stored_flags & 0x40) == 0 && mode == 1 /*RW*/)) {
            uVar3 = 1;       // "needs upgrade" bit
        }
        ctx->open_flags = (ctx->open_flags & ~1u) | uVar3;
    }
}
return 0;
```

So the version gate logic is split across:

* `FUN_180014140` rejects version >= 9 (newer-than-supported).
* `FUN_180009fb0` rejects version < 7 unless caller sets the "allow
  upgrade" open flag.

### 4.8 `FUN_18000d690` — auto-demote to RO (C)

Proposed name: **`archive_demote_to_ro`**.

Triggered when `FUN_180006d20` returns nonzero (= we tried to open RW but
something is preventing writes). The path is:

1. `FUN_18001ad90(rc, ctx->io, &ctx->err)` — translate the io error: this
   returns `true` only for "permission denied / read-only filesystem" type
   errors. Hard errors fall through unchanged.
2. Sanity: ctx must not yet have any LSM tree allocated and
   `ctx[0x340] == 0` (else bug).
3. Reset open-progress fields, log
   `"ar %u (R/O): archive is write-protected, falling back to read-only"`.
4. `FUN_1800365b0(io)` re-opens the dir read-only.
5. `FUN_180004130(ctx)` — flush/reset the io state for read-only.
6. `ctx[0x13cd] = 1` (mark "stale state").
7. **Auto-commit retry:** decrements `ctx[0x13c4]`. On reaching zero, log
   `"autocommit failed, fail with last error"` and return
   `-EAR_AUTOCOMMIT` (0xffffec6b). Otherwise:
   * `FUN_18002b2f0(ctx)` (autocommit prep)
   * Either `FUN_18000c970(ctx, "new volume", 0)` (if marked stale) or read
     `ctx[0x4a0]` / `ctx[0x14c]` (last error) for return code.
   * `FUN_18002b2c0(ctx)` (autocommit cleanup)
8. Returns the final rc, or `1` to signal "retry needed".

### 4.9 `FUN_180006d20` (C)

```c
if (FUN_180017db0(ctx->io)            // ar_io_volume_is_writable
    && mode != ANALYSIS
    && ctx->ci_page_offset != -1
    && (ctx->open_flags & 1) == 0)    // not yet committed
{
    return FUN_18000e050(ctx);   // archive_open_initial_commit
}
return 0;
```

So it's the gating for the initial commit on RW open.

---

## 5. Flowchart

```
archive_open(ctx, dir, name, mode, errp)         [0x180009900]
  └── archive_open_at(... vol=-1, cutoff=-1 ...)  [0x180009930]
        ├── pre-flight argument checks (ostor/astor + mode)
        │     -> -EAR_REWRITE_NS on bad combo
        ├── FUN_18000d0b0  (archive_attach_dir)              [0x18000d0b0]
        │     └── ar_io_set_dir(io, dir, name, mode)
        ├── pcs_co_set_ctx(...)                              (coroutine setup)
        ├── archive_load_header                              [0x180004ab0]
        │     ├── FUN_180035850 (archive_io_list_volumes)    [0x180035850]
        │     │     └── FUN_1800359c0 (collect_volumes)      [0x1800359c0]
        │     ├── FUN_1800173a0 / FUN_1800172a0  (objstore lock acquire)
        │     ├── FUN_1800388b0 (scan_for_last_good)         [0x1800388b0]
        │     │     ├── FUN_180035f20 (open_volume_for_header)
        │     │     ├── FUN_180039df0 (CI iter init)
        │     │     └── FUN_180039340 (search-back)
        │     └── PER-VOLUME LOOP:
        │           ├── FUN_180035560 (cached vol entry?)
        │           ├── FUN_180035f20 (open volume for hdr)  [0x180035f20]
        │           ├── FUN_180038770 (load_volume_ci_page)  [0x180038770]
        │           │     ├── FUN_180039df0 (CI iter init)
        │           │     ├── FUN_180039f10 (read+CRC next CI page)  *
        │           │     ├── FUN_180038990 (validate CI vs ctx)     *
        │           │     └── FUN_1800398c0 (commit chosen page → ctx[0x4a8])
        │           └── recovery branch on -EAR_NO_VOL_HDR
        ├── FUN_1800161f0 (astor cap fallbacks)              [0x1800161f0]
        ├── FUN_180015eb0 (alloc object-history table)       [0x180015eb0]
        ├── FUN_180014140 (validate header record)           [0x180014140]
        │     ├── magic ARCI? else -EAR_NOTFOUND
        │     ├── version <= 8? else -EAR_NEWVER
        │     ├── FUN_180014fe0 (apply_header_fields)        [0x180014fe0]
        │     │     ├── UUID match
        │     │     ├── version equal
        │     │     ├── seq monotonic (commit, CI)
        │     │     ├── feature_used  & ~supported -> -EAR_NEWVER
        │     │     ├── feature_required & ~supported (RW) -> -EAR_NEWVER
        │     │     ├── encr_alg < 2  else -EAR_NOTFOUND
        │     │     ├── dedup_alg < 2 else -EAR_NOTFOUND
        │     │     └── slice_from_disk x2 + FUN_180034620 valid checks
        │     ├── FUN_1800094a0 (post-header LSM alloc)
        │     ├── FUN_1800155d0 (parse_header_tlv_directory) [0x1800155d0]
        │     │     ├── FUN_180015a30 (TLV walker)           [0x180015a30]
        │     │     ├── FUN_180036170 (load name strings)
        │     │     ├── 8 × lsm_sb_read   (mandatory)        [lsm_sb_read]
        │     │     ├── lsm_sb_read tree #9 (v7+; encr keystore?)
        │     │     ├── FUN_180051dd0 (apply v7 extra root)
        │     │     ├── FUN_18004aa10 (alloc-bitmap init)
        │     │     ├── object-history copy (size==0xb70)
        │     │     └── FUN_180054130 (item-index root)
        │     ├── (RW upgrade) FUN_180037d00 + ar_io_write_sync
        │     ├── FUN_180014820 (validate_slices_and_trim_tail) [0x180014820]
        │     │     ├── ar_io_get_archive_size
        │     │     ├── tail too short? -> -EAR_NOTFOUND
        │     │     ├── tail too long → FUN_180038570 (re-read prev_CI)
        │     │     ├── ar_io_trunc + lock dance
        │     │     └── FUN_18005af50 (forget cached pages in tail)
        │     ├── (RW only) FUN_180012b70 (post-commit bookkeeping)
        │     ├── ar_space_free + FUN_18005af50  (release tail)
        │     └── __pcs_free(picked_page)
        ├── FUN_18000c740 (ostor flag check)                 [0x18000c740]
        │     -> -EAR_NOTFOUND on flag mismatch
        ├── FUN_180010c90 (encryption codec hookup, if encr) [0x180010c90]
        ├── (per-volume janitor: delete leftovers via FUN_1800367c0)
        ├── (RW) FUN_180003980 (alloc-cache-populate coroutine)
        ├── FUN_180009fb0 (validate_slices_and_version)      [0x180009fb0]
        │     ├── version 7|8 only (else -0x138f)
        │     └── slice-list walk (v<2 only)
        ├── FUN_180006d20 / FUN_18000d690                    (RO demote)
        │     -> -EAR_AUTOCOMMIT on retry exhaustion
        ├── FUN_18001a600 ? -> writing checkpoint (RO with pending state)
        ├── lsm_automerge_resume(ctx[0x21f])
        ├── FUN_18000a3c0 (register_open: usage + linked-list link)
        └── FUN_18000a0e0 (epilogue: log result, restore co ctx, return rc)
```

`*` = the heart of the CRC check loop — the page reader at
`FUN_180039f10` is the single point at which `xxh64` (per `RESEARCH_TIBX_STRINGS.md`)
gets evaluated for each ARCI page. **It is _not_ run for any other
non-CI page during open** — see §10 for implications.

---

## 6. Error path summary

| Failure | Returned to caller | Logged | Recoverable? |
|---|---|---|---|
| Bad magic on chosen CI page | `-EAR_NOTFOUND` (0xffffec75) | "header magic 0x%02X..." | No |
| Stored payload too big for record | `-EAR_NOTFOUND` | "stored header offs %llu, payload %u > cap %u" | No |
| Version >= 9 | `-EAR_NEWVER` (0xffffec64) | "version (%d) is newer than max_supported (8)" | No (but see object-history flow which uses analysis mode) |
| Version < 7 with !ALLOW_UPGRADE | `-0x138f` | "Upgrade is not allowed, archive version=%d" | Caller can retry with the upgrade flag set |
| Feature bitmask above 0x1ff | `-EAR_NEWVER` | "features 0x%llx are newer than 0x%llx" | No |
| UUID mismatch (re-open) | `-EAR_NOTFOUND` | "archive UUID does not match" | No |
| Commit/CI sequence regression | `-EAR_NOTFOUND` | "commit sequence is broken" / "CI sequence is broken" | No |
| First-CI offset moved | `-EAR_NOTFOUND` | "first CI offset is unknown" | No |
| Hash alg unknown | `-EAR_NOTFOUND` | "unknown hash alg %u" | No |
| Dedup alg unknown | `-EAR_NOTFOUND` | "unknown dedup alg %u" | No |
| object-history not supported | `-EAR_NOTFOUND` | "object history is not supported" | No |
| object-history wrong size | `-EAR_NOTFOUND` | "invalid object history size" | No |
| object-storage flag mismatch | `-EAR_NOTFOUND` | "object storage flag does not match" | No |
| `ar_io_trunc` failed unexpectedly | passes through io error | "archive file size differs from EOF" | No |
| File too short | `-EAR_NOTFOUND` | "archive file size (%llu) is less than expected (%llu)" | No |
| RW open on RO filesystem | demoted to RO via FUN_18000d690, then retried open | "(R/O): archive is write-protected" | Yes (auto) |
| Autocommit retry exhausted | `-EAR_AUTOCOMMIT` | "autocommit failed, fail with last error" | No |
| `pcs_get_urandom` failed | `-EAR_NOMEM` | (none) | No |
| Volume `vol` not found (with explicit vol) | `-EAR_NO_VOL_HDR` | "archive volume %u is not found" | No |
| All volumes exhausted, no header | `-EAR_NOTFOUND` | "can't find header in %u volume(s)" | No |
| Astor open ostor mismatch | `-EAR_REWRITE_NS` | "rewrite mode is not supported by ostor" / "on astor" | No |

The caller's `errp` (param 7 in `archive_open_at`, passed through as
`&ctx->err` internally) gets the rich `ar_error_t` (textual + numeric)
when failure occurs; the integer return is the "summary" code.

---

## 7. Relationship to existing RE coverage

We have prior docs for the following components, so this open trace just
references them:

| Component | Existing doc | Open-time entry point |
|---|---|---|
| Header layout | `ARCHIVE3_HEADER_FORMAT.md` | `FUN_180014fe0` |
| TLV walker / directory | `ARCHIVE3_TLV_DIRECTORY.md` | `FUN_180015a30` |
| LSM superblock format | `ARCHIVE3_LSM_SUPERBLOCK.md` | `lsm_sb_read` |
| Page CRC | `ARCHIVE3_PAGE_VERIFY.md` | `FUN_180039f10` |
| Page type 0x05 | `ARCHIVE3_PAGE_05.md` (in progress) | n/a (open does not touch) |
| Chunk index | `ARCHIVE3_CHUNK_INDEX.md` | n/a (open does not touch) |
| File map | `RESEARCH_TIBX_FILE_MAP.md` | n/a |

---

## 8. Five next-most-important functions to RE

These are functions `archive_open_at` _depends on_ for correctness that we
have not yet documented in detail. Ordered by how blocking they are for a
correct external reader implementation:

1. **`FUN_180038770` / `archive_load_volume_ci_page` @ `0x180038770`** —
   the CI-chain walker. We need to know how it iterates from
   `last_CI_offset` backwards; what makes a CI page "good enough to commit"
   (`FUN_180038990`); whether it requires a contiguous chain or tolerates
   gaps; and whether `prev_ci_offset` is used (incremental / chain
   archives). This is _the_ entry point for any reader that wants to handle
   torn writes / chain-following, and it directly references
   `FUN_180039df0` (iter init), `FUN_180039f10` (page read+CRC) and
   `FUN_180039340` (search) which are the actual on-disk format consumers.

2. **`FUN_180039f10` and `FUN_180039340`** (called by both the scan and the
   walker) — these are the **one and only** place open-time pages are
   verified by xxh64. The exact byte layout of the CRC and which bytes are
   covered (head + payload + tail nonce?) controls whether our reader can
   independently validate `last_CI` — we currently rely on
   `ARCHIVE3_PAGE_VERIFY.md` which is for non-CI pages. Confirm whether CI
   pages use the same scheme.

3. **`FUN_18004aa10` @ `0x18004aa10`** — invoked by
   `archive_parse_header_tlv_directory` after all 8 LSM superblocks load.
   Strings nearby suggest it is the **allocator bitmap loader** (parses the
   in-header free-space map). Without this, our reader's chunk-offset →
   page-mapping is unreliable across incremental commits because the bitmap
   determines which old data is dead and reusable.

4. **`FUN_180015eb0` and `FUN_180054130`** — together they own the
   "object-history" / "item-index root commit" flow. The 0xb70 magic-size
   constant and the per-tree LSM root pointer suggest this is how the root
   pointer of the item-index tree is rotated atomically during commit. For
   an incremental-aware reader we need to follow this from open to know
   _which_ root pointer is "current" vs "previous".

5. **`FUN_180038570` @ `0x180038570`** — the "re-read previous CI page"
   used by `FUN_180014820` when the file size disagrees with the CI's
   `prev_known_eof`. This is the explicit "follow chain backwards by one
   step" function, distinct from the higher-level CI walker. Documenting
   this gives us the full incremental-archive chain-following logic — it
   reads the older CI, re-applies its UUID/seq, and re-checks all
   monotonicity constraints.

---

## 9. Surprises and notable findings

These are points where the actual implementation differs from naive
expectations:

* **No global page CRC sweep on open.** Open only verifies the one CI page
  it picks (and walks back through CI pages that fail validation). It does
  **not** validate every data page or every LSM page at open. Page CRCs
  are checked **lazily** as pages get read. So opening a corrupt-but-not-
  -in-the-CI-page archive will succeed and only fail when the corrupt
  region is later read.

* **No LSM tree walk on open.** All 8 (or 9) trees only have their
  *superblock* read (`lsm_sb_read`). The per-tree pages are never
  iterated at open time. This implies that listing files _is_ a separate
  operation from open; corruption inside a tree's body will not block
  open.

* **Version-too-new error path is encryption-aware.** The "features are
  newer than %llx" path includes a `FUN_18000d010(supported_features_idx)`
  that returns a string codec name — the same codec mechanism used by the
  TLV walker. So features get displayed by symbolic name, not just bitmask.

* **Encryption never prompts.** `FUN_180010c90` only wires the codec
  hooks if `ctx[0x1e69]` (the `encr_alg` byte at hdr offset 0x0d) is
  non-zero, but nothing in `archive_open*` solicits a key or asks for a
  passphrase. This means the encryption key must already be installed on
  the ctx before open via one of the `archive_set_*` setters (or a
  related "encrypt init" entry — see `archive_encr_is_initialized` at
  `0x180010d80`). Open will succeed even without a key, but page reads
  will fail later.

* **`archive_open` always tries to write something on RW open.**
  `FUN_180006d20` triggers an immediate `archive_open_initial_commit` if
  the volume is writable, the open is not analysis, and there is a CI
  page already on disk. If write fails, `FUN_18000d690` quietly demotes
  to RO. So even an "RW open" of a clean archive performs IO and may
  silently change to RO without the caller knowing — they need to check
  `archive_get_mode` post-open to know what they actually got.

* **Recovery branch returns `1`, not zero.** `archive_load_header`'s
  positive return values are not "found multiple matches"; they signal
  "torn-write recovery in progress, the caller must run the
  demote-to-RO + commit flow". This changes how a reader interprets the
  return value.

* **Per-volume janitor inside open.** After successful header load, if
  open mode != ANALYSIS, `archive_open_at` sweeps over volumes that the
  CI claims should not exist (i.e. higher-numbered than
  `header.last_volume`) and **deletes them on disk** via
  `FUN_1800367c0`. This means a read-only-feeling open can mutate the
  filesystem. Critical to keep in mind for any "snapshot/preview" tool.

* **Trim-on-open.** `FUN_180014820` will `ar_io_trunc` the archive file
  to remove a known-bad tail (e.g. from a torn append). Same caveat: a
  "read-only intent" open in mode==1 will modify the file.

* **Object-history is mandatory size-checked.** The `0xb70` magic value
  is hardcoded as the only acceptable object-history blob size. If the
  on-disk size differs by even 1 byte, open fails.

* **TLV directory expects exactly 8 named LSM trees.** The 8 mandatory
  `lsm_sb_read` calls are unconditional; only the 9th (chunkmap-data v2,
  on v7+) is gated. Older v6 archives simply do not have the 9th tree
  in their TLV directory, but our reader must be ready for either count
  based on `version >= 7`.

* **The TLV walker's directory is a fixed 20-slot table.** Both the
  string-table index and the per-tree slot count are bounded by 20, even
  though only 8–10 entries are used in the wild. So a reader that
  pre-allocates 16 entries (mirroring the volume array) can be sure of
  not overflowing.

---

## 10. Function-name normalization — recommended Ghidra labels

Names this study would apply (proposed):

| Address | Proposed name |
|---|---|
| `0x180009900` | `archive_open` (already public) |
| `0x180009930` | `archive_open_at` (already public) |
| `0x180004ab0` | `archive_load_header` (matches existing convention) |
| `0x180014140` | `archive_validate_header_record` |
| `0x180014fe0` | `archive_apply_header_fields` |
| `0x1800155d0` | `archive_parse_header_tlv_directory` |
| `0x180014820` | `archive_validate_slices_and_trim_tail` |
| `0x180009fb0` | `archive_validate_slices_and_version` |
| `0x18000d0b0` | `archive_attach_dir` |
| `0x18000c740` | `archive_check_objstore_flag` |
| `0x180010c90` | `archive_install_encryption_codecs` |
| `0x18000d690` | `archive_demote_to_ro` |
| `0x180006d20` | `archive_maybe_initial_commit` |
| `0x18000a3c0` | `archive_register_open` |
| `0x18000a0e0` | `archive_open_finish` |
| `0x180038770` | `archive_load_volume_ci_page` |
| `0x1800388b0` | `archive_scan_for_last_good` |
| `0x180039df0` | `archive_ci_iter_init` |
| `0x180039f10` | `archive_ci_iter_next` |
| `0x180038990` | `archive_ci_validate` |
| `0x1800398c0` | `archive_ci_commit_chosen` |
| `0x180038570` | `archive_reread_prev_ci` |
| `0x180035850` | `archive_io_list_volumes` |
| `0x180035f20` | `archive_open_volume_for_header` |
| `0x1800367c0` | `archive_io_delete_stale_volume` |
| `0x180015eb0` | `archive_alloc_object_history_table` |
| `0x18004aa10` | `archive_load_alloc_bitmap` (inferred) |
| `0x180054130` | `archive_apply_item_index_root` (inferred) |
| `0x180051dd0` | `archive_apply_v7_extra_root` (inferred) |

All names above are proposals; addresses are confirmed.
