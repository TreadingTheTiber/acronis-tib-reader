# Reverse-engineering history

This is a play-by-play of how the `.tib` format was cracked. Mostly useful
as folklore and to motivate the format choices in `FORMAT.md`.

## Why this was needed

The original task was recovering a 1 TB Acronis True Image sector backup
(`example_full_b1_s1_v1.tib`) from a long-discontinued Acronis
installation. No publicly-available tool could read it. We had:
- The 1 TB `.tib` file
- The Acronis True Image binary (`product.bin`, 37.6 MB stripped i386 ELF)
- Some empirical clues (NTFS knowledge of where the source MFT *should* be)

## Phase 1: empirical content-anchor scan

Initial approach: scan the `.tib` for recognizable file headers (JPEG / PDF /
PNG / etc.) at every cluster boundary, and assume those positions were where
the original NTFS files lived. By matching MFT-claimed LCNs to scan-found
locations, we built a piecewise "shift map" mapping original-partition LCN
to actual offset-in-`.tib`.

This worked for ~55% of files. The shift map was empirical and noisy; large
gaps between anchors meant files in unanchored regions read garbage.

## Phase 2: Ghidra MCP setup

To go higher than 55% required understanding what Acronis was actually doing.
We installed Ghidra on a separate Linux box (`re-host`) and stood up
`bethington/ghidra-mcp` so an LLM agent could decompile, xref, and rename
functions over MCP. ~165 tools exposed.

## Phase 3: the breakthrough — `ExtraFileChunkMap`

A multi-agent swarm of 31 sub-agents drilled into different theories of what
the `.tib`'s post-data region contained. Most leads were dead ends:
- "It's the dedup hash table" — wrong (the table exists but is separate)
- "It's encrypted" — wrong (one column had AES-ECB-of-zeros patterns; turns
  out it was the canonical zero-block MD5 hash repeated)
- "It's a $Bitmap clone" — wrong
- "It's a sparse offset list" — wrong

**Agent #27** found the right thing by reading the decompiled body of
`FUN_089839b0` in Ghidra. Source line strings tied it to
`k:/8029/resizer/backup/openimg.cpp` and the function name `ExtraFileChunkMap`.
The pseudocode revealed a 3-stage pipeline:

1. zlib decompress
2. byte-wise N×12 column-major → row-major matrix transpose
3. zigzag-delta-decode 12-byte records `{u64 enc_offset_delta, u32 length}`

That's the chunk map. The transpose explains why every prior guess that
worked on the inflated bytes failed — pre-untranspose, the records look
like noise.

## Phase 4: validation + integration

Both MFT extent anchors validated cleanly on first run:
- `partition_block 6,144 → reader_block 6,017` (MFT extent 1) ✓
- `partition_block 2,864,367 → reader_block 1,693,384` (MFT extent 2) ✓

Cross-checked against the existing locally-built `blocks.idx`: 96% byte-for-byte
match. The 4% mismatches (92,917 entries) had different `file_offset` values
— blocks were stored slightly out of order on disk. That's where the next
breakthrough came from.

## Phase 5: the 4% block-reorder mystery

Building a partition-direct index from the chunk map and re-running the
recovery test jumped from 55% → 99.4%. The 0.6% remaining was almost all
genuine (Recycle Bin entries with deallocated source clusters, or files
whose source clusters were sparse on the original disk).

The 4% reorder cause was traced to `hybrid_backup.cpp::BackupOutOfOrder`:
each compressed chunk gets written to disk at the moment it arrives from
a parallel compressor pool sized at `sysconf(_SC_NPROCESSORS_ONLN)`. So
on-disk order = arrival order = whichever compressor finished first.
Mean displacement 0.05, max 22, mode ±1 — bounded by pool depth. Acronis's
own reader sorts by file_offset before reading; we do the same.

## Phase 6: subsystem recon (24 follow-up agents)

With the chunk map cracked, a dozen other subsystems were now tractable.
A reconnaissance pass over `product.bin`'s 699 referenced source paths
yielded a categorized map; subsequent focused agents decoded:

| Subsystem | Method | Outcome |
|---|---|---|
| Self-describing chunkmap discovery | Ghidra trace through `GetExtraFileImageParameters` | Agent A: 13-byte signature in metadata blob |
| Post-data streams 1-4 | zlib magic scan + Ghidra | Agent B: 7 streams (preamble mirror, LDM ×2, XML, 2 mini-descriptors), not the originally-hypothesized 4 |
| 40 MB MD5 manifest | Hashing + verification | Agent C: 200/200 verified, `MD5(preamble ‖ block)` |
| Differential chain format | Ghidra | Agent D: no embedded parent pointer; sidecar `mms.db` |
| Windows LDM (dynamic disk) | Format spec + Linux kernel reference | Agent E: this `.tib` was a 2-disk RAID-1 mirror |
| VSS shadow MFTs | FILE0 scan + path-set diff | Agent F: not actually VSS — fragments of an old C: drive (forensic snapshot, no recoverable content) |
| 3.16 MB tail region | Statistical analysis + Ghidra | Agents G/J/Q: 8-bit fingerprint cuckoo filter (790,843 buckets prime). Hash function unsolved without runtime instrumentation. |
| Encryption format | Ghidra | Agent H: AES-128/192/256-CBC + 3 KDFs (SHA256-stretch / PBKDF2 / scrypt) + RSA recovery |
| Source-path recon | `strings` + categorization | Agent I: 24 subsystems mapped, top-5 priorities surfaced |
| WOF/Xpress decompressor | Ghidra + MS-XCA spec | Agent N: working Xpress LZ77+Huffman, 2/2 vectors pass |
| LZNT1 decompressor | NTFS spec | Working pure-Python decompressor |
| Image-stream reorder root cause | Ghidra | Agent M: parallel compressor pool, bounded by CPU count |
| Cloud Storage protocol | Ghidra | Agent T: cloud `.tib` is byte-identical to local; just chopped at 128 MB |
| MMS catalog DB schema | Ghidra `CREATE TABLE` strings | Agent P: 19 tables, 4 fully extracted |
| CBT (changed-block tracking) | Ghidra | Agent R: 44-byte RegionMapping = incremental chunk-map entry |
| Sparse-block algorithm | Ghidra + popcount distribution | Agent W: rb-tree of NTFS-aware exclusions, two-tier (region + bitmap) |
| Multi-volume splits | Ghidra | Agent X: configurable threshold; metadata only in last volume |
| Volume-header keys | Empirical byte-equality vs catalog | Agent S: catalog IDs, NOT random nonces (2⁻⁹⁶ chance) |
| Adler32 coverage | Empirical + Ghidra | Agent AA: header[:hdr_len] with [0x18..0x1C] zeroed |
| Alternative volume magics | Ghidra | Agent BB: 4 magics, 2 are FS-mode v1/v2, 1 is tape footer |
| Per-block 5-byte overhead | Hex inspection | Agent Z: it's a 9th deflate STORED sub-block header (8 × 65535 + 8 trailing bytes) |
| Universal Restore | String search | Agent DD: NOT in this binary (lives in separate `arm.exe`) |
| Notary | String search | Agent Y: thin IPC client to separate `NotarizationSequencer` daemon |
| Metadata blob TLV | Ghidra | Agents O/U: 87 records, 62 distinct tags |

Plus several PARTIAL or NEGATIVE findings — see the full per-agent writeups
under `/path/to/tibread/*.md` in the original development tree.

## Lessons learned

1. **Decompile before guessing.** Every theory built from inflated-byte
   patterns was wrong because of the transpose step. Static decompile of the
   right function (`ExtraFileChunkMap`) immediately revealed the algorithm.
2. **Cross-validate via independent sources.** Many findings were confirmed
   by cross-checking: the LDM disk-group GUID matched the metadata-blob's
   computer_id; the MD5 manifest matched re-computed hashes from the chunk
   map; the volume-header `archive_key`/`slice_key`/`volume_key` matched the
   catalog DB byte-for-byte (2⁻⁹⁶ chance of coincidence).
3. **Bit density alone doesn't identify a structure.** Both the Bloom-filter
   and cuckoo-filter hypotheses produced 47.5% bit density — agents G and J
   chased Bloom for hours before agent Q noticed the per-byte distribution
   was bimodal and definitively cuckoo.
4. **Build a clean reader before optimizing.** The "shift map" empirical
   approach got us to 55% but the architectural-correct approach
   (partition-direct index from the chunk map) was both simpler and got us
   to 99.4% on the first try.
5. **Multi-agent RE works.** ~25 sub-agents in parallel, each with a focused
   mission and clear deliverable, decoded a format that would have taken a
   single human weeks. The hard part was scoping each mission tightly enough
   that agents didn't wander.
