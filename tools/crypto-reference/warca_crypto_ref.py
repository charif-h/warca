"""Reference implementation of the Warca v1 crypto format (ADR 0001).

This is a readable, unoptimised implementation used to generate and check
test vectors. The production implementation lives in the Rust vault core and
must produce byte-identical results for every vector in
tests/vectors/crypto-v1.json.

Requires: cryptography >= 44 (for Argon2id).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
WRAP_NONCE_LEN = 12
TAG_LEN = 16
WRAPPED_KEY_LEN = WRAP_NONCE_LEN + KEY_LEN + TAG_LEN  # 60

MAGIC = b"WRCA"
FORMAT_VERSION = 1
NONCE_PREFIX_LEN = 7
HEADER_LEN = 4 + 1 + 1 + 1 + 1 + 16 + 16 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN  # 107
MIN_CHUNK_LOG2 = 6
MAX_CHUNK_LOG2 = 24
DEFAULT_CHUNK_LOG2 = 20

OBJECT_TYPES = {"original": 1, "ocr_pdf": 2, "thumbnail": 3, "page_image": 4, "oplog_segment": 5}


class FormatError(Exception):
    """The object is malformed, truncated, tampered with, or uses the wrong key."""


# --- Key derivation ---------------------------------------------------------

def derive_kek(passphrase: str, salt: bytes, memory_kib: int, iterations: int, lanes: int) -> bytes:
    """Passphrase -> key-encryption key with Argon2id (version 0x13)."""
    kdf = Argon2id(salt=salt, length=KEY_LEN, iterations=iterations, lanes=lanes, memory_cost=memory_kib)
    return kdf.derive(unicodedata.normalize("NFC", passphrase).encode("utf-8"))


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(ikm)


SUBKEYS = ("index-key", "naming-key", "sync-key")


def derive_subkey(vmk: bytes, vault_id: bytes, name: str) -> bytes:
    assert name in SUBKEYS
    return hkdf(vmk, vault_id, b"warca/v1/" + name.encode())


def derive_recovery_kek(recovery_key: bytes, vault_id: bytes) -> bytes:
    return hkdf(recovery_key, vault_id, b"warca/v1/recovery-kek")


# --- Key wrapping -----------------------------------------------------------

WRAP_PURPOSES = ("vmk-by-passphrase", "vmk-by-recovery", "vmk-by-device",
                 "collection-key", "identity-key", "dek")


def wrap_aad(purpose: str, context: bytes) -> bytes:
    assert purpose in WRAP_PURPOSES
    return b"warca/v1/wrap\x00" + purpose.encode() + b"\x00" + context


def wrap_key(wrapping_key: bytes, key: bytes, purpose: str, context: bytes, nonce: bytes) -> bytes:
    assert len(key) == KEY_LEN and len(nonce) == WRAP_NONCE_LEN
    return nonce + AESGCM(wrapping_key).encrypt(nonce, key, wrap_aad(purpose, context))


def unwrap_key(wrapping_key: bytes, wrapped: bytes, purpose: str, context: bytes) -> bytes:
    if len(wrapped) != WRAPPED_KEY_LEN:
        raise FormatError("wrapped key has wrong length")
    try:
        return AESGCM(wrapping_key).decrypt(wrapped[:WRAP_NONCE_LEN], wrapped[WRAP_NONCE_LEN:],
                                            wrap_aad(purpose, context))
    except InvalidTag as e:
        raise FormatError("wrong key or tampered wrapped key") from e


# --- Object naming ----------------------------------------------------------

def object_name(naming_key: bytes, object_id: bytes) -> str:
    return hmac.new(naming_key, object_id, hashlib.sha256).hexdigest()


def object_path(naming_key: bytes, object_id: bytes) -> str:
    name = object_name(naming_key, object_id)
    return f"objects/{name[:2]}/{name}.bin"


# --- Object container -------------------------------------------------------

def _chunk_nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


def build_header(object_type: int, chunk_log2: int, object_id: bytes, collection_id: bytes,
                 wrapped_dek: bytes, nonce_prefix: bytes) -> bytes:
    header = (MAGIC + bytes([FORMAT_VERSION, object_type, chunk_log2, 0]) + object_id + collection_id
              + wrapped_dek + nonce_prefix)
    assert len(header) == HEADER_LEN
    return header


def encrypt_object(plaintext: bytes, *, dek: bytes, dek_wrapping_key: bytes, vault_id: bytes,
                   object_id: bytes, collection_id: bytes, object_type: int,
                   wrap_nonce: bytes, nonce_prefix: bytes, chunk_log2: int = DEFAULT_CHUNK_LOG2) -> bytes:
    wrapped_dek = wrap_key(dek_wrapping_key, dek, "dek", vault_id + object_id, wrap_nonce)
    header = build_header(object_type, chunk_log2, object_id, collection_id, wrapped_dek, nonce_prefix)
    size = 1 << chunk_log2
    chunks = [plaintext[i:i + size] for i in range(0, len(plaintext), size)] or [b""]
    aead = AESGCM(dek)
    body = b"".join(
        aead.encrypt(_chunk_nonce(nonce_prefix, i, i == len(chunks) - 1), chunk, header)
        for i, chunk in enumerate(chunks))
    return header + body


def parse_header(data: bytes) -> dict:
    if len(data) < HEADER_LEN:
        raise FormatError("too short for a header")
    if data[:4] != MAGIC:
        raise FormatError("bad magic")
    if data[4] != FORMAT_VERSION:
        raise FormatError("unsupported version")
    if data[5] not in OBJECT_TYPES.values():
        raise FormatError("unknown object type")
    if not MIN_CHUNK_LOG2 <= data[6] <= MAX_CHUNK_LOG2:
        raise FormatError("chunk size out of range")
    if data[7] != 0:
        raise FormatError("reserved byte must be zero")
    return {
        "object_type": data[5],
        "chunk_log2": data[6],
        "object_id": data[8:24],
        "collection_id": data[24:40],
        "wrapped_dek": data[40:40 + WRAPPED_KEY_LEN],
        "nonce_prefix": data[40 + WRAPPED_KEY_LEN:HEADER_LEN],
    }


def decrypt_object(data: bytes, *, dek_wrapping_key: bytes, vault_id: bytes) -> bytes:
    h = parse_header(data)
    header = data[:HEADER_LEN]
    dek = unwrap_key(dek_wrapping_key, h["wrapped_dek"], "dek", vault_id + h["object_id"])
    aead = AESGCM(dek)
    full = (1 << h["chunk_log2"]) + TAG_LEN
    body = data[HEADER_LEN:]
    out, pos, index = [], 0, 0
    while True:
        remaining = len(body) - pos
        if remaining < TAG_LEN:
            raise FormatError("truncated: final chunk missing")
        last = remaining <= full
        piece = body[pos:pos + (remaining if last else full)]
        try:
            plain = aead.decrypt(_chunk_nonce(h["nonce_prefix"], index, last), piece, header)
        except InvalidTag as e:
            raise FormatError(f"chunk {index} failed authentication") from e
        if last and index > 0 and not plain:
            raise FormatError("empty final chunk after data")
        out.append(plain)
        if last:
            return b"".join(out)
        pos += full
        index += 1


# --- Recovery phrase --------------------------------------------------------

def recovery_words(recovery_key: bytes, wordlist: list[str]) -> list[str]:
    """BIP39 encoding of a 32-byte key as 24 words (encoding only; no seed derivation)."""
    assert len(recovery_key) == 32 and len(wordlist) == 2048
    checksum = hashlib.sha256(recovery_key).digest()[0]
    bits = int.from_bytes(recovery_key, "big") << 8 | checksum
    return [wordlist[(bits >> (11 * (23 - i))) & 0x7FF] for i in range(24)]


def recovery_key_from_words(words: list[str], wordlist: list[str]) -> bytes:
    if len(words) != 24:
        raise FormatError("a recovery phrase has 24 words")
    index = {w: i for i, w in enumerate(wordlist)}
    try:
        bits = 0
        for w in words:
            bits = bits << 11 | index[w]
    except KeyError as e:
        raise FormatError(f"unknown word {e}") from e
    key = (bits >> 8).to_bytes(32, "big")
    if hashlib.sha256(key).digest()[0] != bits & 0xFF:
        raise FormatError("checksum mismatch: a word is wrong")
    return key
