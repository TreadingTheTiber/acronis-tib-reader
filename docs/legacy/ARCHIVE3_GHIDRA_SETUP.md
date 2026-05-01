# archive3.dll — Ghidra MCP access

This document describes how subsequent agents query the Ghidra MCP for the
Acronis True Image 2024 `.tibx` reader (`archive3.dll`).

## TL;DR

- **Approach:** Option A — `archive3.dll` is loaded into the **same** Ghidra
  MCP server already running on re-host port 8089 alongside `product.bin`.
  No second instance, no second tunnel.
- **Endpoint (from WSL):** `http://127.0.0.1:8089/<endpoint>` via the existing
  SSH tunnel.
- **Required query parameter:** `program=archive3.dll` on every tool call —
  otherwise the call falls through to the *current* program, which is
  `product.bin`. There is no `set_current_program` semantic exposed; treat the
  `program` parameter as mandatory.

## Why Option A

`~/start_ghidra_mcp.sh` on re-host launches one bare-metal headless server
(`com.xebyte.headless.GhidraMCPHeadlessServer`) that supports multiple loaded
programs concurrently and routes calls by the `program` query parameter
(see `HeadlessProgramProvider.getProgram(name)` in `~/ghidra-mcp/src/...`).
Adding a program to the live server is a single POST; spinning up a second
server would have required another JVM (~4 GB heap), another port, another
tunnel, and divergent state. Option A wins on simplicity.

## How the program was loaded

```bash
# On re-host, against the running MCP:
curl -sS -X POST "http://127.0.0.1:8089/load_program" \
  -H "Content-Type: application/json" \
  -d '{"file": "/path/to/archive3_re/archive3.dll"}'
# -> {"success": true, "program": "archive3.dll"}

# Then trigger full auto-analysis:
curl -sS -X POST "http://127.0.0.1:8089/run_analysis?program=archive3.dll"
# -> {"success":true,"duration_ms":47295,"total_functions":2091,
#     "new_functions":657,"program":"archive3.dll"}
```

Auto-analysis took **~47 s** for the 865 KB DLL and grew the function table
from 1434 (loader-only) to 2091 (full analysis).

## Quirks subsequent agents must know

1. **Always pass `program=archive3.dll`.** The server's "current" program is
   `product.bin` and it stays that way. Any endpoint that takes a `program`
   parameter accepts it as a *query string* parameter (not body) — even on
   POST endpoints. Example:
   `curl -sS "http://127.0.0.1:8089/decompile_function?program=archive3.dll&address=0x1800083f0"`.
2. **Image base is `0x180000000`** (standard x64 PE). Function addresses you
   see in `~/archive3_re/archive3_exports_full.txt` are already absolute
   (e.g. `archive_dump_headers -> 1800083f0`).
3. **`/save_program` does NOT work for archive3.dll.** It was loaded
   *standalone* (not into the `productbin` project), so Ghidra reports
   `"Location does not exist for a save operation!"`. The analysis lives in
   the server's memory only. **If the MCP server restarts, repeat the
   load+analyze sequence above.** This costs ~50 s, so it's cheap.
   Alternatively, an agent that needs persistence can use `/create_project`
   or import the DLL into the existing `productbin` project via Ghidra's
   `analyzeHeadless` CLI before starting the server.
4. **Symbol resolution by name.** `/decompile_function` only takes addresses,
   but `/list_exports?program=archive3.dll&query=<name>` and
   `/search_functions_enhanced` accept names and return addresses. Most
   archive_* / ar_* exports survived as named symbols (no stripping).
5. **Both programs share the same MCP, hence the same tunnel.** The WSL
   tunnel `localhost:8089 -> re-host:8089` is already up. Do **not** open
   port 8090; nothing listens there.
6. **`compiler=windows`, `language=x86:LE:64:default`** — confirmed x86-64 PE.
   `product.bin` is 32-bit ELF; don't mix function addresses between them.

## Companion file `archive3_adapter.dll`

`archive3_adapter.dll` (270 KB) at `~/archive3_re/archive3_adapter.dll` has
**not** been loaded yet. When needed, repeat the same sequence with that
file path. It will get its own program name (`archive3_adapter.dll`) and
the same `program=` routing applies.

## Quick reference — common calls

```bash
# Health / inventory
curl -sS "http://127.0.0.1:8089/list_open_programs"
curl -sS "http://127.0.0.1:8089/analysis_status?program=archive3.dll"

# Symbol -> address
curl -sS "http://127.0.0.1:8089/list_exports?program=archive3.dll&query=archive_open"
curl -sS "http://127.0.0.1:8089/search_functions_enhanced?program=archive3.dll&query=tibx"

# Decompile
curl -sS "http://127.0.0.1:8089/decompile_function?program=archive3.dll&address=0x1800083f0&timeout=120"

# Strings
curl -sS "http://127.0.0.1:8089/search_strings?program=archive3.dll&query=tibx"

# Cross-references to a function/data
curl -sS "http://127.0.0.1:8089/get_xrefs_to?program=archive3.dll&address=0x1800083f0"
```

## Sample decompile — `archive_dump_headers` @ `0x1800083f0`

Smoke-tested via `/decompile_function` (output below). It's a thin wrapper
around the archive open/finalize plumbing:

```c
ulonglong archive_dump_headers
            (longlong param_1, undefined8 param_2, uint param_3,
             ulonglong param_4, int *param_5)
{
    ...
    local_48 = DAT_1800c9100 ^ (ulonglong)auStackY_d8;     // /GS canary
    local_90 = param_4;
    lVar2 = archive_alloc();                                 // alloc archive ctx
    FUN_18000d0b0((longlong *)(lVar2 + 0x68), param_1, param_2, 2, &local_90);
                                                            // ar_io_init-style call,
                                                            // mode=2 (read), io ctx at +0x68
    local_98[0] = 0x10;
    uVar3 = FUN_180004ab0(lVar2, local_88, 0, local_98,
                          param_3, local_90,
                          (undefined8 *)(lVar2 + 0xc0));    // load archive headers
    uVar1 = (uint)uVar3;
    if ((int)uVar1 < 0) {
        pcs_log(0, "ar:%u: failed to open archive pa...", *(uint*)(lVar2+0x78),
                *(char**)(lVar2+0x440));
    } else if ((int)uVar1 < 1) {
        uVar1 = FUN_180013500(lVar2);                       // dump-headers worker
    } else {
        uVar1 = 0xffffec75;                                 // -5003: empty archive
        pcs_log(0, "ar:%u: archive file '%s' is empt...", *(uint*)(lVar2+0x78),
                *(char**)(lVar2+0x440));
    }
    uVar3 = ar_io_fini((longlong *)(lVar2 + 0x68), param_5); // close
    uVar4 = uVar3 & 0xffffffff;
    if ((int)uVar3 != 0) {
        pcs_log(0, "ar:%u: failed to close archive e...", *(uint*)(lVar2+0x78), uVar3);
    }
    archive_free(lVar2);
    if (uVar1 != 0) {
        uVar4 = (ulonglong)uVar1;
    }
    return uVar4;                                           // negative -> open err
                                                            // else last error from
                                                            // dump worker / ar_io_fini
}
```

Observations from this single function:

- `archive_alloc()` + `archive_free()` form the standard archive-context
  bracket; the context is a struct with at least these offsets:
    - `+0x68` — IO state (passed to `FUN_18000d0b0` / `ar_io_fini`).
    - `+0x78` — `uint` archive id used in every log message ("ar:%u:").
    - `+0xc0` — pointer slot written by the header loader `FUN_180004ab0`
      (probably the parsed-header cursor / array head).
    - `+0x440` — `char*` archive path used in error messages.
- `FUN_18000d0b0` is the IO open helper; mode constant `2` here strongly
  suggests an open-mode enum (read=2). Worth renaming to `ar_io_init`.
- `FUN_180004ab0` is the **header loader** — six arguments, returns negative
  on error, 0 on success, positive when the archive is empty. Good early
  target for follow-up RE: the four small-int args (0, &{0x10}, param_3,
  param_4) probably select header version/section/flags.
- `FUN_180013500` is the actual "dump headers" routine — small int return
  code, called when the archive opened cleanly. Next agent should decompile
  it; that's where the human-readable header dump that produced our strings
  recon (`tibx`, `archive_dump_*`) actually lives.
- Error code `0xffffec75` (= `-5003`) is the canonical "empty archive"
  sentinel; expect to see it elsewhere in the codebase as a constant.
- `pcs_log` is the cross-product Acronis logging shim; format strings
  beginning with `"ar:"` are this DLL's tag.
