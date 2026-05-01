"""
tibread.tibx.encryption — wrapped-key parsing and segment decryption.

Implements the on-disk crypto formats reverse-engineered from
``archive3.dll`` (see ``docs/legacy/ARCHIVE3_ENCRYPTION.md`` for the
full spec). This module is **untested against real encrypted .tibx
data** — Acronis archive3 has not been observed in the wild with the
encryption flag set in any sample available to this project. The code
below is a faithful translation of the binary's algorithms; it should
be byte-for-byte equivalent to the OpenSSL EVP path used by the DLL,
but treat it as a skeleton until validated end-to-end.

Public surface
==============

* :class:`AlgId` — enum of the 7 supported AES variants (`(id, cipher,
  key_bits, mode)`).
* :class:`WrappedPasswordKey` / :class:`WrappedPubkeyKey` — parsed
  on-disk wrapped-key blobs.
* :func:`parse_wrapped_blob` — auto-detect format byte (0x01 / 0x02)
  and dispatch.
* :func:`unwrap_password_key` — run PBKDF2-HMAC-SHA256 + AES-256-CBC
  to recover the raw data key from a password blob.
* :func:`unwrap_pubkey_key` — RSA-OAEP-decrypt a pubkey blob.
* :func:`decrypt_segment_payload` — decrypt the bytes that live at
  ``+SG_PAYLOAD_OFFSET`` of an SE segment.

Dependencies
============

Requires the ``cryptography`` package (>= 41) for EVP equivalents.
This is the only encryption-time dependency; tibread's plaintext
read path remains crypto-free.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import Optional, Union

# `cryptography` is heavy; import lazily so users with plaintext-only
# archives don't pay the import cost.

INNER_MAGIC_SE = b"SE\x00\x00"
"""Inner magic word of an encrypted segment, at +SG_HEADER_OFFSET."""

#: Default PBKDF2 iteration log2 used by archive3.dll
#: (``DAT_1800ae4f7`` initialised to 0x14). Iterations = 1 << this.
DEFAULT_PBKDF2_ITER_LOG2 = 20

#: Permitted range for ``pbkdf2_iter_log2`` per archive3.dll's bounds
#: check at ``unwrap_key`` line 113 and ``archive_set_pbkdf2_iter_log2``.
MIN_PBKDF2_ITER_LOG2 = 10
MAX_PBKDF2_ITER_LOG2 = 24

#: KEK cipher used to wrap the data key. **Always** AES-256-CBC,
#: regardless of the data-key algorithm. KEK IV is implicit zeros.
KEK_KEY_BYTES = 32
KEK_IV = b"\x00" * 16

#: PBKDF2 salt size (bytes). Hard-coded in archive3.dll (``unwrap_key``
#: at offset 0x14 in the blob, length 16).
PBKDF2_SALT_SIZE = 16

#: Format byte values.
FORMAT_PASSWORD = 0x01
FORMAT_PUBKEY = 0x02

#: GCM IV / tag sizes used by the encrypt path. Hard-coded in
#: ``FUN_1800402f0`` via ``EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)``.
GCM_IV_SIZE = 16
GCM_TAG_SIZE = 16

#: CBC IV size — full AES block, drawn from RAND_bytes per segment.
CBC_IV_SIZE = 16


class AlgId(enum.IntEnum):
    """Enumeration matching ``FUN_180040eb0`` in archive3.dll."""

    AES_128_CBC = 1
    AES_192_CBC = 2
    AES_256_CBC = 3
    AES_128_GCM = 5
    AES_192_GCM = 6
    AES_256_GCM = 7

    @property
    def key_bytes(self) -> int:
        return {
            AlgId.AES_128_CBC: 16,
            AlgId.AES_192_CBC: 24,
            AlgId.AES_256_CBC: 32,
            AlgId.AES_128_GCM: 16,
            AlgId.AES_192_GCM: 24,
            AlgId.AES_256_GCM: 32,
        }[self]

    @property
    def is_gcm(self) -> bool:
        return self in {AlgId.AES_128_GCM, AlgId.AES_192_GCM, AlgId.AES_256_GCM}

    @property
    def is_cbc(self) -> bool:
        return self in {AlgId.AES_128_CBC, AlgId.AES_192_CBC, AlgId.AES_256_CBC}


@dataclass(frozen=True)
class WrappedPasswordKey:
    """An on-disk password-wrapped data key (LSM record value).

    Parsed from a 0x14 + N-byte buffer per ``unwrap_key`` /
    ``FUN_1800400d0``.
    """

    alg: AlgId
    iter_log2: int
    salt: bytes  # exactly 16 bytes
    wrapped_key: bytes  # remaining ciphertext, multiple of 16 bytes

    @property
    def iterations(self) -> int:
        return 1 << self.iter_log2


@dataclass(frozen=True)
class WrappedPubkeyKey:
    """An on-disk pubkey-wrapped data key (LSM record value).

    Parsed from a 4 + RSA_modulus_bytes-byte buffer per
    ``unwrap_key_pkey`` / ``FUN_180040c00``.
    """

    alg: AlgId
    rsa_oaep_ciphertext: bytes


@dataclass(frozen=True)
class DataKey:
    """Recovered (plaintext) data key plus metadata.

    Equivalent to the in-memory key struct used by archive3.dll
    (vtable slot +0x18 / +0x58 produces this).
    """

    alg: AlgId
    key: bytes  # raw AES key, alg.key_bytes long


# ---------------------------------------------------------------------------
# Blob parsing
# ---------------------------------------------------------------------------


def parse_wrapped_blob(
    blob: bytes,
) -> Union[WrappedPasswordKey, WrappedPubkeyKey]:
    """Auto-detect the format byte and parse accordingly.

    Raises ``ValueError`` for short / malformed buffers and
    ``NotImplementedError`` for unknown format bytes.
    """
    if len(blob) < 4:
        raise ValueError(f"wrapped blob too short: {len(blob)} bytes")
    fmt = blob[0]
    if fmt == FORMAT_PASSWORD:
        return _parse_password_blob(blob)
    if fmt == FORMAT_PUBKEY:
        return _parse_pubkey_blob(blob)
    raise NotImplementedError(f"unknown wrapped-blob format byte: 0x{fmt:02x}")


def _parse_password_blob(blob: bytes) -> WrappedPasswordKey:
    if len(blob) < 0x14:
        raise ValueError(
            f"password blob too short: got {len(blob)}, need >= 0x14"
        )
    fmt, alg_byte, iter_log2, _reserved = struct.unpack_from("<BBBB", blob, 0)
    assert fmt == FORMAT_PASSWORD
    if alg_byte not in {a.value for a in AlgId}:
        raise ValueError(f"invalid alg id 0x{alg_byte:02x} in password blob")
    if not (MIN_PBKDF2_ITER_LOG2 <= iter_log2 <= MAX_PBKDF2_ITER_LOG2):
        raise ValueError(
            f"pbkdf2_iter_log2={iter_log2} out of range "
            f"[{MIN_PBKDF2_ITER_LOG2}, {MAX_PBKDF2_ITER_LOG2}]"
        )
    salt = blob[4 : 4 + PBKDF2_SALT_SIZE]
    wrapped = blob[4 + PBKDF2_SALT_SIZE :]
    if len(wrapped) == 0 or len(wrapped) % 16 != 0:
        raise ValueError(
            f"wrapped key length {len(wrapped)} is not a positive "
            f"multiple of the AES block (16)"
        )
    return WrappedPasswordKey(
        alg=AlgId(alg_byte),
        iter_log2=iter_log2,
        salt=salt,
        wrapped_key=wrapped,
    )


def _parse_pubkey_blob(blob: bytes) -> WrappedPubkeyKey:
    if len(blob) <= 4:
        raise ValueError(
            f"pubkey blob too short: got {len(blob)}, need > 4"
        )
    fmt, alg_byte, _r1, _r2 = struct.unpack_from("<BBBB", blob, 0)
    assert fmt == FORMAT_PUBKEY
    if alg_byte not in {a.value for a in AlgId}:
        raise ValueError(f"invalid alg id 0x{alg_byte:02x} in pubkey blob")
    return WrappedPubkeyKey(alg=AlgId(alg_byte), rsa_oaep_ciphertext=blob[4:])


# ---------------------------------------------------------------------------
# Unwrap (= recover raw data key)
# ---------------------------------------------------------------------------


def derive_kek(password: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256(password, salt, iterations) -> 32 bytes.

    Reproduces the call inside ``FUN_180040f20`` (``wrap_key``):
    ``PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, 16, iter, EVP_sha256(),
    32, &out)``. Note the password is **not** NUL-terminated on the
    way in — archive3.dll passes ``strlen(pass)`` as the length.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if len(salt) != PBKDF2_SALT_SIZE:
        raise ValueError(f"salt must be {PBKDF2_SALT_SIZE} bytes")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEK_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def unwrap_password_key(
    blob: Union[bytes, WrappedPasswordKey],
    password: Union[bytes, str],
) -> DataKey:
    """Recover the raw data key from a password-wrapped blob.

    Parameters
    ----------
    blob :
        Either the raw bytes from the LSM record or a pre-parsed
        :class:`WrappedPasswordKey`.
    password :
        Either the password as ``bytes`` or as a ``str`` (which is
        encoded to UTF-8 — archive3.dll treats the password as opaque
        bytes via ``strlen``, so the encoding the UI used to obtain
        the password must match what the writer used; UTF-8 matches
        OpenSSL's typical behaviour but is not guaranteed by the DLL).

    Raises
    ------
    ValueError
        On length mismatch, padding error, or short ciphertext.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    if isinstance(blob, (bytes, bytearray, memoryview)):
        wrapped = _parse_password_blob(bytes(blob))
    else:
        wrapped = blob

    if isinstance(password, str):
        password = password.encode("utf-8")

    kek = derive_kek(password, wrapped.salt, wrapped.iterations)

    cipher = Cipher(algorithms.AES(kek), modes.CBC(KEK_IV))
    dec = cipher.decryptor()
    padded = dec.update(wrapped.wrapped_key) + dec.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        raw_key = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError(
            "PKCS#7 unpadding failed — likely wrong password "
            "(no MAC is stored at this layer; the only verifier is "
            "the GCM tag on a real segment, or comparing against "
            "another user's already-unwrapped K_data)"
        ) from exc

    expected = wrapped.alg.key_bytes
    if len(raw_key) != expected:
        raise ValueError(
            f"unwrapped key length {len(raw_key)} != expected "
            f"{expected} for {wrapped.alg.name}"
        )
    return DataKey(alg=wrapped.alg, key=raw_key)


def unwrap_pubkey_key(
    blob: Union[bytes, WrappedPubkeyKey],
    private_key_pem: bytes,
    private_key_password: Optional[bytes] = None,
) -> DataKey:
    """Recover the raw data key from a pubkey-wrapped blob.

    Uses RSA-OAEP with SHA-1 digest and SHA-1 MGF1 mask — these are
    the OpenSSL defaults invoked when archive3.dll calls
    ``EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)`` and
    nothing else (no calls to ``set_rsa_oaep_md`` or
    ``set_rsa_mgf1_md`` were observed). No OAEP label is set.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if isinstance(blob, (bytes, bytearray, memoryview)):
        wrapped = _parse_pubkey_blob(bytes(blob))
    else:
        wrapped = blob

    priv = serialization.load_pem_private_key(
        private_key_pem, password=private_key_password
    )

    raw_key = priv.decrypt(
        wrapped.rsa_oaep_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    expected = wrapped.alg.key_bytes
    if len(raw_key) != expected:
        raise ValueError(
            f"unwrapped key length {len(raw_key)} != expected "
            f"{expected} for {wrapped.alg.name}"
        )
    return DataKey(alg=wrapped.alg, key=raw_key)


# ---------------------------------------------------------------------------
# Segment decryption
# ---------------------------------------------------------------------------


def decrypt_segment_payload(
    encrypted_payload: bytes,
    data_key: DataKey,
) -> bytes:
    """Decrypt one SE segment's payload (the bytes at +0x2C).

    The on-disk layout (per ``docs/legacy/ARCHIVE3_ENCRYPTION.md §5``)
    is:

    GCM
        ``[16-byte IV][16-byte GCM tag][ciphertext]``

    CBC
        ``[16-byte random IV][ciphertext (PKCS#7 padded)]``

    Returns the decrypted (still-compressed if `comp != 0` in the
    enclosing SG header) plaintext. The caller is responsible for
    running the existing decompression path on the result.

    Notes
    -----
    For GCM, this calls AESGCM.decrypt with empty AAD — archive3.dll
    does not call ``EVP_EncryptUpdate(ctx, NULL, &outl, aad, aad_len)``
    in ``FUN_1800402f0``, so the tag covers only the ciphertext.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    if data_key.alg.is_gcm:
        if len(encrypted_payload) < GCM_IV_SIZE + GCM_TAG_SIZE:
            raise ValueError(
                f"GCM payload too short: {len(encrypted_payload)} bytes "
                f"(need >= {GCM_IV_SIZE + GCM_TAG_SIZE})"
            )
        iv = encrypted_payload[:GCM_IV_SIZE]
        tag = encrypted_payload[GCM_IV_SIZE : GCM_IV_SIZE + GCM_TAG_SIZE]
        ciphertext = encrypted_payload[GCM_IV_SIZE + GCM_TAG_SIZE :]
        aesgcm = AESGCM(data_key.key)
        try:
            return aesgcm.decrypt(iv, ciphertext + tag, associated_data=None)
        except InvalidTag as exc:
            raise ValueError(
                "GCM tag mismatch — wrong key, corrupted segment, or "
                "(less likely) two writers reused an IV"
            ) from exc

    # CBC
    if len(encrypted_payload) <= CBC_IV_SIZE:
        raise ValueError(
            f"CBC payload too short: {len(encrypted_payload)} bytes"
        )
    if (len(encrypted_payload) - CBC_IV_SIZE) % 16 != 0:
        raise ValueError(
            "CBC ciphertext (without IV) is not a multiple of the AES "
            "block size — segment is malformed"
        )
    iv = encrypted_payload[:CBC_IV_SIZE]
    ciphertext = encrypted_payload[CBC_IV_SIZE:]
    cipher = Cipher(algorithms.AES(data_key.key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError(
            "CBC PKCS#7 unpadding failed — wrong key or corrupted segment"
        ) from exc


# ---------------------------------------------------------------------------
# LSM-record key construction (for looking up wrapped blobs)
# ---------------------------------------------------------------------------


def lsm_key_for_password_user(user: Union[bytes, str]) -> bytes:
    """Build the LSM key for a password user record.

    Per ``archive_encr_set_passwd`` line 44–49: the on-disk LSM key is
    ``[0x01] || strlen(user) bytes of the user name`` (no NUL).
    """
    if isinstance(user, str):
        user = user.encode("utf-8")
    return bytes([FORMAT_PASSWORD]) + user


def lsm_key_for_pubkey_user(pkey_id: bytes, user_idx: int = 1) -> bytes:
    """Build the LSM key for a pubkey user record.

    Per ``archive_encr_use_priv_key`` line 188–190: the LSM key is
    ``[0x02] || pkey_id[32] || BE32(user_idx)``. The pkey_id is the
    SHA-256 of ``i2d_PUBKEY(public_key)`` — i.e. the digest of the
    DER-encoded ``SubjectPublicKeyInfo``.
    """
    if len(pkey_id) != 32:
        raise ValueError(f"pkey_id must be 32 bytes (SHA-256), got {len(pkey_id)}")
    return bytes([FORMAT_PUBKEY]) + pkey_id + struct.pack(">I", user_idx)


def compute_pkey_id(public_key_pem: bytes) -> bytes:
    """SHA-256(DER(SubjectPublicKeyInfo)) — the pkey-id used in LSM keys.

    Mirrors the engine vtable's ``get_pkey_id`` slot (+0x48 ⇒
    ``FUN_1800408e0``): ``EVP_Digest(EVP_sha256(), i2d_PUBKEY(pkey))``.
    """
    from cryptography.hazmat.primitives import hashes, serialization

    pub = serialization.load_pem_public_key(public_key_pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize()


__all__ = [
    "INNER_MAGIC_SE",
    "DEFAULT_PBKDF2_ITER_LOG2",
    "MIN_PBKDF2_ITER_LOG2",
    "MAX_PBKDF2_ITER_LOG2",
    "PBKDF2_SALT_SIZE",
    "FORMAT_PASSWORD",
    "FORMAT_PUBKEY",
    "GCM_IV_SIZE",
    "GCM_TAG_SIZE",
    "CBC_IV_SIZE",
    "AlgId",
    "WrappedPasswordKey",
    "WrappedPubkeyKey",
    "DataKey",
    "parse_wrapped_blob",
    "derive_kek",
    "unwrap_password_key",
    "unwrap_pubkey_key",
    "decrypt_segment_payload",
    "lsm_key_for_password_user",
    "lsm_key_for_pubkey_user",
    "compute_pkey_id",
]
