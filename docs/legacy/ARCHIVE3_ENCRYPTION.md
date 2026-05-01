# archive3.dll encryption — full RE notes

Status: **derived entirely from static decompilation of `archive3.dll`**
(no encrypted `.tibx` test corpus). Confidence levels are tagged
inline:
- **(C)** = confirmed via decompilation — the exact opcodes / EVP
  calls / struct offsets are visible in the binary.
- **(I)** = inferred — derived from naming, surrounding code, and
  cryptographic norms; no observed test data to validate.

Source files in archive3.dll:
- `libarchive3/archive_encr.c` — high-level setter API and per-archive
  state. Up to line 632 visible in strings; functions at
  `0x180010c90`–`0x180012c60`.
- An untitled crypto provider in the same DLL implementing
  `wrap_key`, `unwrap_key`, `wrap_key_pkey`, `unwrap_key_pkey`,
  `encrypt`, `decrypt`, plus eleven other vtable entries — functions
  at `0x18003fdc0`–`0x180040f10`. Strings live in `.rdata` at
  `0x1800ae###..0x1800af###`. Probably `archive_encr_openssl.c` or
  similar (no path string for it).

The encryption code is gated by **`hdr+0x0d`** in the open-flow agent's
notes; the in-memory equivalent is `arch+0x1e69`, the byte holding
the active algorithm id (`0` = no encryption). Inside the .tibx
header that bit is in `puVar6+0xd` in `FUN_180012c60` (commit-header
serialiser).

---

## 1. Algorithm id table — `FUN_180040eb0` (C)

A single byte selects both the cipher and the data-key length. Decoded
from the switch statement in `FUN_180040eb0`:

| id | EVP cipher       | key bytes | mode |
|----|------------------|-----------|------|
| 0  | (no encryption)  | —         | —    |
| 1  | EVP_aes_128_cbc  | 16        | CBC  |
| 2  | EVP_aes_192_cbc  | 24        | CBC  |
| 3  | EVP_aes_256_cbc  | 32        | CBC  |
| 4  | (unused)         | —         | —    |
| 5  | EVP_aes_128_gcm  | 16        | GCM  |
| 6  | EVP_aes_192_gcm  | 24        | GCM  |
| 7  | EVP_aes_256_gcm  | 32        | GCM  |

`archive_encr_alg_from_str` / `archive_encr_alg_get_str` round-trip
between this byte and the human strings `"aes-128-cbc"` …
`"aes-256-gcm"`.

---

## 2. Public setter API

All of these live in `libarchive3/archive_encr.c` and take an opaque
`archive*` (`param_1`) as the first argument. They are also exported
under `Ordinal_*` aliases.

| symbol                          | va         | line | purpose |
|---------------------------------|------------|------|---------|
| `archive_encr_set_alg`          | 0x180010ea0 | 191 | Pick the data-key cipher (id 1..7). Must be called once before any user is added. (C) |
| `archive_encr_set_engine`       | 0x180011100 | 192 | Install the OpenSSL provider vtable (default = `get_openssl_engine()` at 0x180040f10). (C) |
| `archive_encr_set_passwd`       | 0x180011200 | 193 | Add (or replace) a password-protected user. Stores the wrapped data key in the encryption-key LSM tree. (C) |
| `archive_encr_set_pub_keys`     | 0x1800113d0 | 194 | Add one or more cert-protected users by parsing a multi-line PEM PUBLIC KEY blob. (C) |
| `archive_encr_use_passwd`       | 0x180011670 | 195 | Unlock an *existing* archive with a password (read path). Looks up the `[0x01][user]` LSM key, fetches the wrapped blob, sets `arch+0x1e88..0x1e9c` to (user, wrapped_blob). (C) |
| `archive_encr_use_priv_key`     | 0x1800119c0 | 196 | Unlock an existing archive with a PEM private key. Computes the SHA-256 pkey-id and looks up `[0x02][pkey_id][user_idx]`. (C) |
| `archive_encr_use_pub_keys`     | 0x180011c50 | 197 | Like `use_priv_key` but only validates that the user's public-key id is known — does *not* unwrap (used for re-key flows). (C) |
| `archive_encr_rm_user`          | 0x180010da0 | —   | Remove a user from the LSM tree. (I) |
| `archive_encr_has_user`         | 0x180010bc0 | —   | Existence check. (I) |
| `archive_encr_get_alg`          | 0x1800107d0 | —   | Read the active algorithm id. (C) |
| `archive_set_pbkdf2_iter_log2`  | 0x180040e80 | 347 | Set the **global** PBKDF2 iteration log2 (range 10..24, default = **20** ⇒ 1 048 576 iterations). Affects all subsequently wrapped passwords. Stored in `DAT_1800ae4f7`. (C) |
| `archive_encr_get_mtime`        | 0x180010b20 | —   | Last modification time of the encryption-key tree. (I) |
| `archive_encr_user_list_*`      | 0x1800120b0 | —   | Iterate users. (I) |

The `remote_archive_encr_*` aliases at `0x18000e440..0x18000e630` are
RPC shims that proxy these calls into a worker thread; they accept the
same arguments.

The setter API never prompts the user — both `use_passwd` and
`use_priv_key` require the credential to already be available in
process memory. The setters are normally called by the UI layer after
it has prompted out-of-band.

---

## 3. The OpenSSL engine vtable — `0x180079010` (C)

`archive_encr_set_engine` plugs a 13-pointer struct into
`arch+0x1e80`. The default is `&PTR_FUN_180079010`, returned by
`get_openssl_engine`. The slots are:

| offset | va         | symbol (inferred) | signature |
|--------|------------|-------------------|-----------|
| +0x00  | 0x18003fdf0 | `generate_key`    | `(arch_id, &out_key_struct, alg_id) -> err` |
| +0x08  | 0x18003fd70 | `get_overhead`    | `(key_struct) -> u8 (segment ciphertext-overhead bytes)` |
| +0x10  | 0x18003ffe0 | `wrap_key`        | `(arch_id, key_struct, &out_blob, password) -> blob_size` |
| +0x18  | 0x1800400d0 | `unwrap_key`      | `(arch_id, &out_key_struct, blob, blob_size, password) -> err` |
| +0x20  | 0x1800402f0 | `encrypt`         | `(arch_id, key_struct, &out_buf, plaintext, pt_len) -> ct_len` |
| +0x28  | 0x180040550 | `decrypt`         | `(arch_id, key_struct, &out_buf, ciphertext, ct_len) -> pt_len` |
| +0x30  | 0x1800407b0 | `cmp_keys`        | `(key_a, key_b) -> bool (timing-leaky on 1st u64 only)` — used as the password verifier |
| +0x38  | 0x18003fdc0 | `free_key`        | `(key_struct) -> void (OPENSSL_cleanse + free)` |
| +0x40  | 0x180040800 | `load_pkey`       | `(arch_id, &out_pkey, &pem_buf, is_priv:0|1, password|NULL) -> err` |
| +0x48  | 0x1800408e0 | `get_pkey_id`     | `(arch_id, pkey, out_buf, buf_sz) -> id_size` — SHA-256 of the DER `SubjectPublicKeyInfo`, length 32 |
| +0x50  | 0x180040a60 | `wrap_pkey`       | `(arch_id, key_struct, &out_blob, pubkey) -> blob_size` |
| +0x58  | 0x180040c00 | `unwrap_pkey`     | `(arch_id, &out_key_struct, blob, blob_size, privkey) -> err` |
| +0x60  | 0x180040e70 | `free_pkey`       | `(pkey) -> void` (Ghidra failed to disassemble; thin EVP_PKEY_free wrapper) |

**In-memory `key_struct`** (the unwrapped form, sized
`0x20 + EVP_CIPHER_get_key_length(cipher)`):

```
+0x00  EVP_CIPHER*  cipher                 // result of EVP_aes_*_<mode>()
+0x08  u64          gcm_counter            // atomic, 0 at unwrap; pre-incremented per encrypt
+0x10  u8[16]       gcm_iv_base            // 16 random bytes from RAND_bytes() at unwrap (GCM only — ignored for CBC)
                                            // Actually only the high 8 bytes are used:
                                            //   IV = (counter:u64_LE) || (iv_base[0..8])
+0x18  u8           alg_id                 // 1..7
+0x19  u8[]         data_key               // raw AES key, key_length bytes
```

`gcm_iv_base` is generated *fresh* at every call to
`unwrap_key` / `unwrap_pkey` / `generate_key` — i.e. it changes every
time the archive is opened. Combined with the monotonic counter this
gives 96-bit unique IVs as long as a single open writes fewer than
2^64 segments.

---

## 4. KDF + key-wrap formats

### 4.1 Password user blob (format byte = `0x01`) (C)

Stored as the **value** of an LSM record whose **key** is
`[0x01] || user_name_bytes` (the user name is NUL-stripped by
`strlen(param_2)` at line 44 of `archive_encr_set_passwd`, then 1 byte
of format prefix is prepended; no NUL terminator on disk).

Blob layout (produced by `wrap_key` = `FUN_18003ffe0`,
parsed by `unwrap_key` = `FUN_1800400d0`):

```
+0x00  u8       format = 0x01                    // password
+0x01  u8       alg_id (1..7, same as section 1)
+0x02  u8       pbkdf2_iter_log2  (10..24, defaults to 20)
+0x03  u8       reserved (zero — padding from __pcs_zmalloc)
+0x04  u8[16]   pbkdf2_salt        (RAND_bytes at wrap time)
+0x14  u8[N]    AES-256-CBC(KEK, IV=zeros, padding=PKCS#7) of the
                raw data key, where N = round_up(key_length_bytes, 16).
```

`KEK = PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16,
1<<iter_log2, EVP_sha256(), 32, &out)`. **Always 32 bytes**, **always
SHA-256**, **always 16-byte salt**, regardless of `alg_id` (so even
when wrapping a 128-bit data key the KEK is 256 bits and the wrap
uses AES-256-CBC). The KEK IV passed to `EVP_CipherInit_ex` is **NULL
(implicit zero)** — see `FUN_180040f20` line 55. **Confirmed.**

For AES-128 (16-byte data key): wrapped portion is 16 bytes of
ciphertext + 16 bytes of PKCS#7 padding block = 32 bytes ⇒ total blob
0x14 + 32 = **52 bytes**.

For AES-256 (32-byte data key): wrapped portion is 32 + 16 = 48 bytes
⇒ total blob 0x14 + 48 = **68 bytes**.

The **password verifier** is *not* a stored hash — it's the
`cmp_keys` vtable entry (`FUN_1800407b0`, slot +0x30): both candidate
keys have their first u64 (the EVP_CIPHER pointer) compared, and on
match the raw key bytes are memcmp'd. `archive_encr_use_passwd` does
trial-decryption: if `unwrap_key` returns success and `cmp_keys`
matches an existing in-memory data key, the password is correct.
There is **no MAC tag and no integrity bit** at this layer — a
mistyped password may successfully decrypt to garbage, in which case
the data segment GCM-tag mismatch is the actual failure signal.

(For first-time `archive_encr_set_passwd` there is nothing to compare
against — the wrapped blob is simply written into the LSM and
becomes the canonical record.)

### 4.2 Public-key user blob (format byte = `0x02`) (C)

LSM key is `[0x02] || pkey_id[32] || user_idx_BE32`, where
`pkey_id = SHA-256(i2d_PUBKEY(pubkey))` (the 32-byte digest of the
DER `SubjectPublicKeyInfo` encoding) and `user_idx` is a 32-bit BE
counter that lets a single pubkey hold multiple wrapped copies of the
key (used during re-keying, see `archive_encr_use_pub_keys`).

Blob value layout (produced by `wrap_pkey` = `FUN_180040a60`,
parsed by `unwrap_pkey` = `FUN_180040c00`):

```
+0x00  u8       format = 0x02                  // pubkey
+0x01  u8       alg_id (1..7)
+0x02  u8       reserved (zero)
+0x03  u8       reserved (zero)
+0x04  u8[N]    RSA-OAEP-encrypt(pubkey, raw_data_key)
                where N = RSA modulus size (256 for RSA-2048,
                512 for RSA-4096).
```

Padding: **`EVP_PKEY_CTX_set_rsa_padding(ctx, 4)` = `RSA_PKCS1_OAEP_PADDING`**.
The OAEP MGF1 digest defaults to SHA-1 — the binary does **not** call
`EVP_PKEY_CTX_set_rsa_oaep_md` or `EVP_PKEY_CTX_set_rsa_mgf1_md`, so
both the OAEP digest and the MGF1 digest are SHA-1 (OpenSSL default).
No OAEP label is set. **Confirmed** (`FUN_180040a60` line 519,
`FUN_180040c00` line 519).

### 4.3 Multi-recipient layout

The encryption-key tree (LSM tree at `arch+0x12a8`, the **9th** LSM
tree per `FUN_180012c60`) holds *one record per recipient*:

```
key=[0x01][alice]            -> wrapped(K_data, password='alice's pwd', salt_a, iter_a)
key=[0x01][bob]              -> wrapped(K_data, password='bob's pwd', salt_b, iter_b)
key=[0x02][sha256(cert_c)][BE 1]  -> RSA-OAEP(cert_c.pubkey, K_data)
key=[0x02][sha256(cert_d)][BE 1]  -> RSA-OAEP(cert_d.pubkey, K_data)
key=[0x02][sha256(cert_c)][BE 2]  -> RSA-OAEP(cert_c.pubkey, K_data')   ; second key after rekey
```

There is exactly **one logical data key per `key_id`** (the segment
header's `key_id` field, see §5). `archive_encr_set_passwd` looks up
the existing key by id 1, decrypts it with the new user's
already-supplied wrap-blob, then re-wraps it under the new password
salt — i.e. all users share the same `K_data`. The four-byte
`user_idx` BE-suffix on cert keys allows multiple historical
`K_data`s to be stored under one cert (ids 1, 2, 3 …) so that a user
who has been removed and re-added can still decrypt old segments
written under the previous `K_data`.

The active key id is in `arch+0x1ee8` (mirrored to the archive
header's `encr_last_key_id` field per the JSON dump at
`0x18009cc40`).

---

## 5. Encrypted segment format ("SE" magic) (C)

Plaintext segments use inner magic `"SG\x00\x01"` at page-relative
offset +8. Encrypted segments use **`"SE\x00\x00"`** at the same
offset (the trailing two bytes of the magic word are zero — see
`DAT_1800c2d88` at `0x1800c2d88` and the dispatch at `FUN_1800676c0`
line 55).

The 0x2C-byte fixed header (`SG_HEADER_OFFSET..SG_PAYLOAD_OFFSET`)
keeps the same layout as a plaintext SG header — `len`, `zlen`,
`key_id`, `comp`, `cache` are all populated. For SE segments
`key_id` is non-zero and identifies which `K_data` (in the
encryption-key LSM tree) this segment is encrypted with.

The encrypted payload begins at +0x2C and is structured as:

```
+0x2C..0x3C   16-byte AES nonce/IV
              - GCM:  little-endian u64 segment-counter || 8 random bytes
                      from EVP_PKEY's gcm_iv_base[0..8].  The counter
                      is unique per (open-session, key); the iv_base
                      is unique per open-session.
              - CBC:  16 random bytes from RAND_bytes() per segment.

+0x3C..0x4C   GCM only — 16-byte authentication tag
              (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG=16, 16)).
              For CBC, these bytes are part of the ciphertext.

+0x4C..       Ciphertext.  Length:
              - GCM: zlen   - 0x20  (just the data; GCM has no padding)
              - CBC: zlen   - 0x10  (data + PKCS#7 final block)
              On disk, the segment header's `zlen` field already includes
              the IV + tag (so `zlen = 0x20 + ciphertext_len` for GCM,
              `zlen = 0x10 + ciphertext_len` for CBC).
```

The plaintext recovered from decryption is then handled exactly like
a plaintext SG payload — i.e. the LZ4 / Zstd decompressor still runs
on it (encryption wraps the *compressed* representation).

`get_overhead` (vtable +0x08) returns:
- 0x20 (= 32) for GCM ⇒ matches the 16-byte IV + 16-byte tag.
- `iv_length + block_size` = 0x10 + 0x10 = **0x20** for CBC ⇒ matches
  the 16-byte IV + worst-case full padding block.

**Important — the IV is *not* derived from `segment_id`.** It is
written verbatim into the segment payload. This means an
implementation only needs the (key_struct, on-disk segment bytes) to
decrypt; it does not need to know the segment's logical address.

### 5.1 GCM IV uniqueness across opens

The 64-bit `gcm_counter` resets to **0** every time the archive is
opened (`unwrap_key` calls `RAND_bytes` for the iv_base but does not
persist any per-archive state). That means two different sessions
that re-encrypt with the *same* `K_data` would have IV collisions on
the first segment if they had the same `iv_base`. Acronis avoids this
by:

1. Drawing a **fresh 16-byte `iv_base`** at every unwrap, of which
   the high 8 bytes go into the IV (`unwrap_key` line 134 / 544 —
   `RAND_bytes(plVar4 + 1, 0x10)`).
2. Concatenating the counter as the **low 8 bytes** of the IV (so
   distinct counters within one session never collide).

This gives ≈ 2^64 IVs per open + ≈ 2^64 distinct iv_bases, total IV
space ≈ 2^96 = the full GCM IV. Standard NIST SP800-38D guidance.

### 5.2 Segment-id collision cost

Because the IV is stored, a reader does not need to track any global
counter. A *writer*, however, must never reuse `(K_data, IV)` — and
the `gcm_counter` resets per open. If two distinct writers pick up
the *same* `K_data` (e.g. multi-master replication), their iv_bases
must not collide. There is no mechanism in archive3.dll to detect
such a collision.

This is **the** cryptographic risk class for archive3.dll's
encryption design and is worth documenting before recommending the
format for active multi-writer use. Read-only use (which is what
tibread does) is unaffected.

---

## 6. Reader implementation roadmap

Decrypting an archive given a user-supplied password requires four
steps:

1. **Locate the encryption-key LSM tree.** Per
   `FUN_180012c60`, the per-archive header allocates 9 LSM trees in
   the order `... 0x10f8, 0x12a8, 0x12b0`. The encryption-key tree is
   the one at `arch+0x12a8` — i.e. the **second-to-last** tree.
   tibread already parses the LSM tree directory; the encryption tree
   should appear as one of the entries, identified by the inner key
   format `[0x01]…` / `[0x02]…`. (I — the exact slot index in
   ARCH/TLV must still be confirmed from a real encrypted archive.)

2. **Iterate users; find the user record matching the supplied
   password username** (LSM key prefix `0x01`). Read the value blob
   per §4.1.

3. **Run PBKDF2-HMAC-SHA256** with `(password, salt[16], 1<<iter_log2,
   keylen=32)` to derive the KEK, then **AES-256-CBC-decrypt** the
   wrapped-key portion (with NUL/zero IV, PKCS#7 padding) to recover
   `K_data`. Length of `K_data` = `key_length(alg_id)`.

4. **Per encrypted segment:** read 16-byte IV at +0x2C; for GCM also
   read 16-byte tag at +0x3C and call `EVP_DecryptUpdate` /
   `Final_ex` after `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG)`. The
   ciphertext starts at +0x4C (GCM) / +0x3C (CBC) and continues
   through the segment's continuation pages exactly like plaintext
   SG. After decryption, hand the buffer to the existing
   `decompress_segment` path (it has no idea encryption was
   involved).

For the certificate path, replace step 3 with **RSA-OAEP-decrypt**
using the user's private key (PEM); see §4.2.

A skeleton implementation is provided in
`tibread/tibx/encryption.py`. **It has been written from spec only —
no encrypted .tibx has been used to validate it end-to-end.** The
PBKDF2 + AES-256-CBC unwrap path is straightforwardly testable
against any OpenSSL-equivalent reference using known
`(password, salt, iter)` triples.

---

## 7. Open questions / TODO

- **Where in the ARCH page are the `iter_log2` default and the
  encryption-key-tree slot id?** The flag bit `hdr+0x0d` says "is
  encrypted"; there must also be a TLV slot or a fixed offset
  pointing at the LSM tree that holds the wrapped keys. tibread's
  TLV parser (`docs/legacy/ARCHIVE3_TLV_DIRECTORY.md`) will need a
  pass with an encrypted sample to identify which TLV slot stores
  this. (I)
- **CBC PKCS#7 stripping:** EVP_DecryptFinal_ex strips the padding,
  so plaintext_size = `EVP_DecryptUpdate.outlen + EVP_DecryptFinal.outlen`.
  No issue, just noting.
- **Compressed-then-encrypted ordering:** §5 implies the writer first
  compresses, then encrypts (since `len > zlen` is meaningful in the
  SG header even for SE, and the GCM tag covers the compressed
  bytes). Confirmed by reading order in `FUN_180068a30` (decrypt at
  vtable +0x28) followed by `FUN_1800686d0` (decompress) in
  `FUN_180067170`. (C)
- **Old-format compatibility:** the binary mentions
  `archive_set_compatibility` and "format newer (%d) then supported"
  errors — the `version` byte at +0x0a in the segment header may
  indicate an older encryption schema. Out of scope for tibread v1. (I)
