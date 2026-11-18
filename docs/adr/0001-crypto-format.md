# ADR 0001: Encryption format v1

- **Status:** Proposed
- **Date:** 2026-10-31
- **Issue:** #6

## Context

Warca stores scanned official documents (passports, contracts, certificates). Everything written to disk or uploaded to a sync provider must be encrypted on the device, and the cloud must only ever hold ciphertext. The format has to:

- derive keys from a passphrase in a way that is slow to brute-force,
- let the user change the passphrase without re-encrypting every file,
- offer a recovery path that does not depend on a server,
- stream large files without holding them in memory, and detect truncation, reordering and tampering,
- hide document names from the storage provider,
- leave room for sharing some documents with family members later.

Rolling a custom construction is the main risk in a project like this, so the format only combines standard primitives in well-documented ways.

## Decision

### Primitives

| Use | Primitive |
|---|---|
| Passphrase → key | Argon2id, version 0x13, 32-byte output |
| Subkeys | HKDF-SHA256, 32-byte output |
| Key wrapping and content | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Streaming content | AES-256-GCM in the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015), as used by Tink and `age` |
| Object names | HMAC-SHA256 |
| Recovery phrase | BIP39 English word list, used **only as an encoding** of a 256-bit key |
| Future sharing | X25519 identity key pairs |

All labels below are ASCII byte strings. `||` is concatenation. Integers are big-endian.

### Key hierarchy

```
passphrase ──Argon2id──▶ KEK ──unwraps──▶ VMK (vault master key, 32 random bytes)
recovery key ──HKDF──▶ recovery KEK ──unwraps──▶ VMK
device key (OS keychain, optional) ──unwraps──▶ VMK

VMK ──HKDF──▶ index key   (SQLCipher)
VMK ──HKDF──▶ naming key  (object names)
VMK ──HKDF──▶ sync key    (change-log segments)
VMK ──wraps──▶ collection keys ──wrap──▶ per-object data keys (DEK)
VMK ──wraps──▶ X25519 identity private key (reserved for sharing)
```

- `vault_id`: 16 random bytes, created with the vault, stored in `vault.json`. Used as HKDF salt and bound into every wrapped key.
- **VMK**: 32 random bytes. Never stored unwrapped. Changing the passphrase re-wraps only the VMK.

### Passphrase KDF

`KEK = Argon2id(password = UTF-8(passphrase), salt = 16 random bytes, m, t, p, length = 32)`

- Default: `m = 262144 KiB (256 MiB)`, `t = 3`, `p = 4`.
- Minimum accepted when opening a vault: `m = 65536 KiB`, `t = 2`, `p = 1` (for phones). The parameters are stored in `vault.json`, so they can be raised later by re-wrapping the VMK.
- The passphrase is NFC-normalised before encoding, so the same passphrase typed on different systems gives the same key.

### Subkeys

`subkey(name) = HKDF-SHA256(ikm = VMK, salt = vault_id, info = "warca/v1/" || name)` for `name` in `index-key`, `naming-key`, `sync-key`.

The index key opens the SQLCipher database as a raw key: `PRAGMA key = "x'<64 hex chars>'"` with SQLCipher 4 defaults.

### Key wrapping

```
wrap(wrapping_key, key, purpose, context):
    nonce = 12 random bytes
    aad   = "warca/v1/wrap" || 0x00 || purpose || 0x00 || context
    return nonce || AES-256-GCM(wrapping_key, nonce, key, aad)      # 12 + 32 + 16 = 60 bytes
```

| purpose | wrapping key | context |
|---|---|---|
| `vmk-by-passphrase` | passphrase KEK | `vault_id` |
| `vmk-by-recovery` | recovery KEK | `vault_id` |
| `vmk-by-device` | device key | `vault_id || device_id` |
| `collection-key` | VMK | `vault_id || collection_id` |
| `identity-key` | VMK | `vault_id || user_id` |
| `dek` | collection key, or sync key for change-log segments | `vault_id || object_id` |

Binding the purpose and IDs into the AAD means a wrapped key cannot be moved to another slot, collection, object or vault.

### Recovery key

- 32 random bytes, shown once as 24 words (BIP39 English list: 256 bits plus an 8-bit SHA-256 checksum) and as a QR code on a printable page.
- `recovery KEK = HKDF-SHA256(ikm = recovery key, salt = vault_id, info = "warca/v1/recovery-kek")`. No Argon2 is needed because the key is already 256 bits of randomness.
- The BIP39 seed derivation (PBKDF2) is **not** used; the words only encode the key.
- Optional later: split the recovery key 2-of-3 with Shamir secret sharing.

### Object names

`name = hex(HMAC-SHA256(naming key, object_id))`, stored at `objects/<name[0:2]>/<name>.bin`. `object_id` is a 16-byte ULID. The provider sees neither IDs nor document names.

### Object container

Every stored blob (original, OCR PDF, thumbnail, page image, change-log segment) uses this container.

**Header (107 bytes):**

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `WRCA` |
| 4 | 1 | format version = `0x01` |
| 5 | 1 | object type: 1 original, 2 OCR PDF, 3 thumbnail, 4 page image, 5 change-log segment |
| 6 | 1 | `chunk_log2`: chunk size is `2^chunk_log2` bytes; writers use 20 (1 MiB); readers accept 6 to 24 |
| 7 | 1 | reserved, must be 0 |
| 8 | 16 | `object_id` |
| 24 | 16 | `collection_id` (all zero for change-log segments) |
| 40 | 60 | wrapped DEK (`purpose = dek`) |
| 100 | 7 | `nonce_prefix`, random per object |

**Body:** the plaintext split into chunks of `2^chunk_log2` bytes; the last chunk may be shorter. An empty file is one empty final chunk. Each chunk `i` is encrypted as

```
nonce_i = nonce_prefix || uint32(i) || (0x01 if last chunk else 0x00)
chunk_ciphertext_i = AES-256-GCM(DEK, nonce_i, chunk_i, aad = header)
```

and the chunk ciphertexts are concatenated after the header.

**Reader rules.** A reader must reject the object, and return no plaintext from it, if:

- the magic, version, type, `chunk_log2` or reserved byte is invalid,
- the DEK does not unwrap,
- any chunk fails authentication (this covers header changes, reordering, a moved final flag and truncation),
- the data ends before a chunk flagged as final, or continues after it.

Because each chunk's nonce encodes its position and whether it is last, and the whole header is the AAD of every chunk, removing, reordering, duplicating or appending chunks always fails authentication.

Each object has its own random DEK, so a nonce is never reused under the same key; the random prefix is a second line of defence. One object can hold up to 2^32 chunks (4 PiB at 1 MiB chunks).

A viewer that streams a document may show chunks before the final one is verified only if it discards everything on a later failure. The default is to verify the whole object before display.

### `vault.json`

Plaintext JSON that holds no secrets:

```json
{
  "format": "warca-vault",
  "version": 1,
  "vault_id": "<base64url>",
  "kdf": { "alg": "argon2id", "version": 19, "memory_kib": 262144, "iterations": 3, "lanes": 4, "salt": "<base64url>" },
  "vmk_wrapped": {
    "passphrase": "<base64url 60 bytes>",
    "recovery": "<base64url 60 bytes>",
    "devices": { "<device_id>": "<base64url 60 bytes>" }
  },
  "created_at": "2026-10-31T12:00:00Z"
}
```

Collection keys, the identity key pair and per-device public keys are stored in the encrypted database and synced through the encrypted change log.

### Memory handling

Keys are held in memory only while the vault is unlocked and are zeroised on lock (`zeroize` crate). Decrypted content is never written to disk; the extraction worker receives it over a pipe.

## Test vectors

[`tests/vectors/crypto-v1.json`](../../tests/vectors/crypto-v1.json) covers Argon2id (small and production parameters), HKDF subkeys, VMK wrapping, the recovery phrase and recovery KEK, collection-key wrapping, object naming, four object containers (empty, short, exactly one chunk, three chunks, using 64-byte chunks), and six tampered objects that must be rejected.

The vectors are produced by the readable reference implementation in [`tools/crypto-reference/`](../../tools/crypto-reference/). The Argon2id outputs were cross-checked against the `argon2-cffi` library. The Rust vault core must reproduce every vector byte for byte, and reject every `must_reject` case.

## Consequences

- Changing the passphrase, adding a device or adding a recovery method is cheap: only the 60-byte wrapped VMK changes.
- Sharing a collection later means wrapping its collection key for another person's X25519 public key. No document is re-encrypted.
- Revoking someone's access protects documents added afterwards (new collection key); it cannot take back what they already downloaded.
- Losing both the passphrase and the recovery kit makes the vault unrecoverable, by design.
- Sizes, counts and timestamps of objects remain visible to the storage provider. Size padding can be added in a later version without changing the container.

## Alternatives considered

- **`age` file format:** well designed and close to this one, but its recipient model does not fit the collection-key hierarchy, and Warca needs its own header fields (object type, IDs). The STREAM layout is borrowed from it.
- **XChaCha20-Poly1305 (libsodium secretstream):** equally good and faster without AES hardware. AES-256-GCM was chosen because every target device has AES acceleration and it is the more widely audited choice. The version byte allows switching later.
- **Encrypting each file directly with a key derived from the passphrase:** rejected; a passphrase change would re-encrypt everything, and recovery and multiple devices would be awkward.

## Open questions for review

- Whether to add optional size padding (for example to the next 64 KiB) in v1.
- Whether the viewer should allow progressive display of verified chunks for very large PDFs.
