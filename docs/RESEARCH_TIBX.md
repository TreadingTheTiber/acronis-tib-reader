# Research: Open-Source / Public Knowledge of `.tibx` (Acronis "Archive3")

**Date:** 2026-04-30
**Author:** Research agent (web sweep, ~40 minutes)
**Question:** Has anyone reverse-engineered Acronis's post-2020 `.tibx` (TIB eXtended) format? Is there a viable basis to add `.tibx` support to `tibread`, partner with an existing project, or is this greenfield?

---

## Bottom Line

**Zero open-source `.tibx` parsers exist.** After ~40 minutes of focused searches, I found exactly one open-source repo touching `.tibx`, and it is *not* a parser — it is a redistribution of Acronis's own proprietary shell-extension binaries (DLLs). The classic-`.tib` open-source effort (`dennisss/acronis-tib`) is dormant and explicitly scoped to the older format; no `.tibx` work is in flight there.

The good news: the Acronis-bundled DLL set in the redistribution repo confirms key architectural assumptions for `.tibx`:

- `archive3.dll` / `archive3_adapter.dll` is the format-handler module (Acronis internally calls the format **"Archive3"**, succeeding `.tib`'s "Archive2").
- `sqlite3.dll` ships alongside it — confirms the SQLite-backed container assertion.
- `zstd.dll` ships alongside it — confirms Zstd is the compression algorithm (Acronis's own KB also names it directly).

That is essentially all the public signal there is. There are no academic papers, no DFIR blog posts, no Kaitai Struct templates, no 010 Editor templates, no forum threads with hex-level analysis, no `.tibx` issues on the existing `acronis-tib` repo, no Hacker News discussion. **`.tibx` reverse-engineering is, as far as the open web is concerned, unstarted.**

**Recommendation: do not pursue `.tibx` support in `tibread` at this time.** Specific reasoning at the bottom.

---

## Findings by Category

### 1. Open-source projects

#### 1a. `dennisss/acronis-tib` (the only RE effort that exists)

- **URL:** https://github.com/dennisss/acronis-tib
- **Scope:** Classic `.tib` only. README explicitly says "in particular the ones with file extensions `.tib` and `.tib.metadata`." No mention of `.tibx`.
- **Activity:** ~13 commits total, no releases, README says "still a work in progress." Open issues are basic ("How to use this tool?", "Is your parser still in progress?") — none about `.tibx`.
- **License:** (Visible in repo; not material here since we won't be lifting code for `.tibx`.)
- **Maturity:** Proof-of-concept for old-format `.tib`. Useful prior art and morale boost for the *classic* format we already handle, but contributes nothing toward `.tibx`.
- **Verdict:** Confirms there is no community `.tibx` work. If someone were going to start, this is the natural place — and they haven't.

#### 1b. `deac34/TIB-TIBX-ShellEx` (NOT a parser — Acronis binary redistribution)

- **URL:** https://github.com/deac34/TIB-TIBX-ShellEx
- **Scope:** A repackaged Acronis 2021 shell extension installer. Repo description: "ACRONIS 2021 VIEW BACKUP FILES TIB,TIBX-ShellEx-25.8.1.39216.exe."
- **Contents:** Compiled Acronis DLLs only — no source, no notes, no specs. Notable file list:
  - `archive3.dll`, `archive3_adapter.dll` — the TIBX format handler
  - `sqlite3.dll` — confirms SQLite container
  - `zstd.dll` — confirms Zstd compression
  - `libcrypto10.dll`, `libssl10.dll` — OpenSSL, presumably for encryption
  - `tishell32.dll`, `tishell64.dll` — Windows shell extension
- **Maturity:** Not a research artifact; it's a convenience installer. But the DLL inventory is *forensically useful* — it tells us what to point Ghidra/IDA at if we ever do RE the format ourselves: `archive3.dll` is the lone target.
- **Verdict:** Useful intel (confirms tech stack), zero source-code value.

#### 1c. No other repos found

Searches for "tibx parser", "tibx reader", "tibx decoder", "libacronis", "Acronis backup extract", and combinations with "Python"/"Rust"/"Go" returned zero relevant projects. No Kaitai Struct (`.ksy`) definition exists. No 010 Editor binary template exists publicly.

### 2. Forums / blogs / community RE

- **Acronis forum threads** (mount-tibx-file, restore-tibx-different-machine, etc.): All user-support traffic. No format discussion, no third-party tools mentioned. Consensus from Acronis staff and power users is "you must use Acronis software." Forensic Focus thread on `.tib` predates `.tibx`.
- **Reddit, Hacker News, OpenRCE, Tuts4You, RaidForums, X-Ways forum:** No `.tibx` threads surfaced. Site-restricted searches returned empty.
- **DFIR blogs:** None found. Generic "Acronis incident response" content is about *using* Acronis to respond, not about parsing `.tibx`.
- **StackOverflow:** No `tibx`-tagged questions found.
- **Verdict:** The format has not been touched by the public RE community. This is unusual for a 6-year-old format, but explainable — Acronis is enterprise/consumer backup, not a high-prestige RE target like games, DRM, or malware.

### 3. Academic / paper research

- **Verdict:** Nothing. Searches for forensic-analysis papers covering Acronis backup formats returned generic DFIR content unrelated to `.tibx`. No theses, no conference papers, no journal articles surfaced.

### 4. Acronis SDK / commercial third-party tools

- **Acronis Cyber Platform API** (https://developer.acronis.com): A REST API for orchestration (creating backups, managing tenants). It does **not** expose any file-level `.tibx` reader. There is no public Acronis SDK for reading the on-disk format. Acronis-published Python samples (`acronis/acronis-cyber-platform-python-examples`) are about the cloud API, not the archive format.
- **Commercial recovery services** (SOS Ransomware, Digital Recovery): Marketing copy claims they can recover damaged/encrypted `.tibx`, but there is no published methodology. These are paid forensic services, not tools. Their existence implies *some* private knowledge in the recovery industry, but nothing usable to us.
- **"TIBX Converter" sites** (convert.guru, datatypes.net, etc.): Web-based "convert TIBX to VHD/ZIP/ISO" pages. Reading their copy carefully ("standard online file converters fail completely when trying to process a `.TIBX` file"), these appear to be SEO landing pages that do not actually convert the format — they exist to capture search traffic and funnel users to Acronis or paid recovery. **Treat as noise.**
- **Acronis's own conversion tools:** Acronis True Image can convert `.tib`/`.tibx` to VHD via "Convert Acronis backup to Windows backup" — but this requires a working Acronis install, defeating the purpose for our user.

### 5. Adjacent / prior-art format research

- **Acronis whitepaper:** "TIBX – Next-Generation Archive Format in Acronis Backup Cloud" (2018), `https://dl.acronis.com/u/PP_TIBX_Archive_Overview_in_Acronis_Backup_Cloud_EN-US_180607.pdf`. PDF is rasterized/marketing-grade; WebFetch could not extract usable text. Acronis's own KB articles at https://kb.acronis.com/tag/tibx and https://kb.acronis.com/content/63498 / `64744` repeat the same talking points: "Archive3", uses Zstd, single-file-per-chain, in-archive checksummed metadata, "Always-incremental" or "Multi-full" schemes, default 200 GB split. None of this is byte-level.
- **SQLite-archive prior art:** SQLite itself ships an "SQLite Archive" (`sqlar`) format and the `sqlite3` CLI has `-A` archive mode. Not directly reusable for `.tibx` (Acronis's schema is custom), but the *idea* — open the file as a SQLite DB, inspect tables, follow blob references — is the obvious first investigative move. Tools: any SQLite browser (DB Browser for SQLite, `sqlite3` CLI). The container's leading bytes (`41 01 00 00`, then `QARCH` at offset 7) confirm Acronis prepends a small header before the SQLite content rather than starting at a clean SQLite magic (`SQLite format 3\0`) — so the file is *not* a vanilla SQLite DB; you'd need to either skip the header or carve out the SQLite portion.
- **Classic `.tib` parallel:** The `.tib` → `.tibx` jump is more than a versioning bump. `.tib` was a custom volume-header + block-stream layout; `.tibx` is a fundamentally different design (SQLite container of compressed blobs). RE knowledge from `tibread`'s classic-`.tib` work gives us nothing directly transferable except domain familiarity.

---

## What's Publicly Known About `.tibx` (synthesized)

From Acronis KB articles + the binary redistribution + the user's own reconnaissance:

| Aspect | Known | Source |
|---|---|---|
| Internal name | "Archive3" (vs. `.tib` = "Archive2") | Acronis KB 73032, 64744 |
| Container | SQLite-backed | DLL bundle ships `sqlite3.dll`; user's 4-byte header + `QARCH` magic confirms a wrapper |
| Magic header | `41 01 00 00` (`0x141`) at offset 0; ASCII `QARCH` at offset 7 | User-supplied |
| Compression | Zstandard (Zstd) | Acronis KB 16791; bundled `zstd.dll` |
| Encryption | AES via OpenSSL (libcrypto/libssl bundled); replaces MD5-hashed passwords with stronger KDF | DLL bundle; KB 63498 |
| File-per-chain | One `.tibx` per backup chain (Full + diffs + incrementals); 200 GB auto-split | KB 63441, 63444 |
| Metadata | Stored in-archive, checksummed (no sidecar XML) | Acronis KB |
| Deduplication | Built-in block-level dedup | KB 64744 |
| Format-handling DLL | `archive3.dll` (`+ archive3_adapter.dll`) | TIB-TIBX-ShellEx repo |
| Public byte-level spec | **None** | — |
| Public parser | **None** | — |

The first 4 bytes `41 01 00 00` decode as little-endian `0x00000141` = 321 decimal — likely a header length, version, or page-size hint, but unverified. `QARCH` is an obvious abbreviation of "Acronis Archive" with a leading `Q`; could mean nothing or could be a magic chosen by an internal Acronis component named with that prefix.

---

## Gaps & Opportunities

Things nobody has publicly done:

1. **Carve and open the SQLite DB.** The single highest-leverage experiment: skip the leading header (try 16, 32, 64, 128, 256, 512, 4096 bytes) and look for SQLite's `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` ("SQLite format 3\0") magic. If found, dump the schema with `sqlite3 .schema`. This single step would produce more `.tibx` knowledge than anything currently public.
2. **Disassemble `archive3.dll`** with Ghidra. Strings dump alone (table names, error messages, schema strings) is likely highly informative.
3. **Diff two `.tibx` files** of known content (e.g., back up an empty 1 MB volume, then back up a 1 MB volume with one known file). Compare resulting databases to identify chunk/blob tables.
4. **Publish a Kaitai Struct `.ksy`** for the leading header + SQLite schema once known. There would be genuine community appetite for this — it just hasn't been done.

The user's 51 GB `example.tibx` is a poor first specimen for #1 and #3 (large, unknown contents, expensive to iterate on). A small known-plaintext sample (a 100 MB synthetic volume backed up locally with Acronis Free Trial) is the right starting point.

---

## Recommended Approach

Three options, in increasing ambition:

### Option A — Don't pursue (recommended)

`.tibx` is a fundamentally different format from `.tib`. Adding support is not an incremental change to `tibread`; it is a new project. There is no community to leverage, no spec to consume, no SDK to wrap. The 51 GB user file is a single-data-point motivation; the engineering cost (probably 2-6 person-months for a partial reader, longer for one that handles encryption and dedup correctly) vastly exceeds the value of one extraction.

For the user's immediate need: install Acronis True Image trial (or use Acronis bootable recovery media), mount the `.tibx` once, extract whatever they need, uninstall. This is days vs. months and produces a correct result.

### Option B — Investigate, don't commit

A 1-2 day spike: take a synthetic small `.tibx`, attempt SQLite carve, run `strings` on `archive3.dll`, dump schema if accessible. If the schema turns out to be small/sane and blobs are plain Zstd of disk sectors, reassess. If it's deep with custom encoding, abandon.

This produces a public artifact (a blog post, a Kaitai sketch, or a `tibx-recon` README) even if no full reader emerges, and would be the first public RE notes for the format. Modest cost, modest payoff, helps the community.

### Option C — Full implementation

Build a `.tibx` reader in `tibread`. Estimated 2-6 person-months. Only sensible if (a) this turns into a recurring pattern of users with `.tibx` files, (b) Option B's spike reveals a friendly format, and (c) someone has the time. Right now none of these are true.

**Recommendation: Option A for the user's immediate file (have them use Acronis trial); Option B as an opportunistic side project if/when curiosity strikes; Option C only after Option B yields a clear "yes this is tractable" signal.**

If pursuing Option B/C, scope `tibx` as a **separate crate / module** under the `tibread` umbrella, not a feature-flag on the existing classic-`.tib` parser — the formats share nothing at the byte level.

---

## Summary Stats

- **Relevant open-source projects found:** 1 (and it's only Acronis binary redistribution, not actual code). 0 actual parsers.
- **Maturity of any existing `.tibx` work:** None public.
- **Maturity of adjacent `.tib` work (`dennisss/acronis-tib`):** Proof-of-concept, dormant, doesn't apply.
- **Academic papers:** 0 found.
- **Public byte-level format spec:** None.
- **Recommendation:** Don't add `.tibx` support to `tibread` now. Direct user to Acronis trial for the one-off extraction. Keep `.tibx` on a backlog labeled "investigate if recurring need."
