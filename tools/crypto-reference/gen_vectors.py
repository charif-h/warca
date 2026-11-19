"""Generate tests/vectors/crypto-v1.json from the reference implementation.

Usage:
    python3 -I tools/crypto-reference/gen_vectors.py --wordlist english.txt > tests/vectors/crypto-v1.json

The wordlist is the BIP39 English list:
https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
(sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda)

All "random" inputs are fixed so the output is deterministic. Never use these
values in a real vault.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warca_crypto_ref as w  # noqa: E402

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def h(b: bytes) -> str:
    return b.hex()


def seq(start: int, n: int) -> bytes:
    return bytes((start + i) % 256 for i in range(n))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", required=True)
    args = ap.parse_args()
    raw = open(args.wordlist, "rb").read()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        sys.exit("wordlist does not match the BIP39 English list")
    wordlist = raw.decode().split()

    vault_id = seq(0xA0, 16)
    vmk = seq(0x00, 32)
    salt = seq(0x10, 16)
    passphrase = "correct horse battery staple"
    out = {"format": "warca-crypto-v1-test-vectors", "warning": "Fixed test inputs. Never use in a real vault.",
           "common": {"vault_id": h(vault_id), "vault_master_key": h(vmk)}}

    # 1. Argon2id
    kdf_cases = []
    for params in ({"memory_kib": 65536, "iterations": 2, "lanes": 1, "note": "small parameters for fast tests"},
                   {"memory_kib": 262144, "iterations": 3, "lanes": 4, "note": "production default"}):
        kek = w.derive_kek(passphrase, salt, params["memory_kib"], params["iterations"], params["lanes"])
        kdf_cases.append({**params, "passphrase": passphrase, "salt": h(salt), "kek": h(kek)})
    out["argon2id"] = kdf_cases
    kek = bytes.fromhex(kdf_cases[0]["kek"])

    # 2. HKDF subkeys
    out["subkeys"] = {name: h(w.derive_subkey(vmk, vault_id, name)) for name in w.SUBKEYS}

    # 3. Wrapping the master key with the passphrase KEK
    wrap_nonce = seq(0x30, 12)
    wrapped = w.wrap_key(kek, vmk, "vmk-by-passphrase", vault_id, wrap_nonce)
    assert w.unwrap_key(kek, wrapped, "vmk-by-passphrase", vault_id) == vmk
    out["wrap_vmk_by_passphrase"] = {"kek": h(kek), "purpose": "vmk-by-passphrase", "context": h(vault_id),
                                     "aad": h(w.wrap_aad("vmk-by-passphrase", vault_id)),
                                     "nonce": h(wrap_nonce), "wrapped": h(wrapped)}

    # 4. Recovery key
    recovery_key = seq(0x40, 32)
    words = w.recovery_words(recovery_key, wordlist)
    assert w.recovery_key_from_words(words, wordlist) == recovery_key
    assert w.recovery_words(bytes(32), wordlist) == ["abandon"] * 23 + ["art"]  # BIP39 reference vector
    rkek = w.derive_recovery_kek(recovery_key, vault_id)
    rnonce = seq(0x50, 12)
    out["recovery"] = {"recovery_key": h(recovery_key), "words": " ".join(words), "recovery_kek": h(rkek),
                       "nonce": h(rnonce),
                       "wrapped_vmk": h(w.wrap_key(rkek, vmk, "vmk-by-recovery", vault_id, rnonce))}

    # 5. Collection key wrapped by the master key
    collection_id = seq(0xC0, 16)
    collection_key = seq(0x60, 32)
    cnonce = seq(0x70, 12)
    out["collection_key"] = {"collection_id": h(collection_id), "collection_key": h(collection_key),
                             "context": h(vault_id + collection_id), "nonce": h(cnonce),
                             "wrapped": h(w.wrap_key(vmk, collection_key, "collection-key",
                                                     vault_id + collection_id, cnonce))}

    # 6. Object naming
    naming_key = w.derive_subkey(vmk, vault_id, "naming-key")
    object_id = seq(0xD0, 16)
    out["object_naming"] = {"naming_key": h(naming_key), "object_id": h(object_id),
                            "name": w.object_name(naming_key, object_id),
                            "path": w.object_path(naming_key, object_id)}

    # 7. Object containers (chunk size 64 bytes so multi-chunk cases stay small)
    dek = seq(0x80, 32)
    common = dict(dek=dek, dek_wrapping_key=collection_key, vault_id=vault_id, object_id=object_id,
                  collection_id=collection_id, object_type=w.OBJECT_TYPES["original"],
                  wrap_nonce=seq(0x90, 12), nonce_prefix=seq(0xE0, 7), chunk_log2=6)
    objects = []
    for label, pt in (("empty", b""), ("short", b"Warca"), ("exactly one chunk", seq(0, 64)),
                      ("three chunks", seq(0, 150))):
        ct = w.encrypt_object(pt, **common)
        assert w.decrypt_object(ct, dek_wrapping_key=collection_key, vault_id=vault_id) == pt
        objects.append({"label": label, "plaintext": h(pt), "object": h(ct)})
    out["objects"] = {"dek": h(dek), "dek_wrapping_key": h(collection_key), "object_id": h(object_id),
                      "collection_id": h(collection_id), "object_type": 1, "chunk_log2": 6,
                      "wrap_nonce": h(common["wrap_nonce"]), "nonce_prefix": h(common["nonce_prefix"]),
                      "cases": objects}

    # 8. Objects that must be rejected
    good = bytes.fromhex(objects[3]["object"])
    hl, full = w.HEADER_LEN, 64 + w.TAG_LEN
    c0, c1, c2 = good[hl:hl + full], good[hl + full:hl + 2 * full], good[hl + 2 * full:]
    flipped_header = bytearray(good)
    flipped_header[10] ^= 1  # inside object_id
    flipped_body = bytearray(good)
    flipped_body[hl + 5] ^= 1
    bad = {
        "header byte changed": bytes(flipped_header),
        "ciphertext byte changed": bytes(flipped_body),
        "final chunk removed": good[:hl] + c0 + c1,
        "chunks reordered": good[:hl] + c1 + c0 + c2,
        "trailing data": good + b"\x00",
        "unsupported version": good[:4] + b"\x02" + good[5:],
    }
    rejected = []
    for label, data in bad.items():
        try:
            w.decrypt_object(data, dek_wrapping_key=collection_key, vault_id=vault_id)
            raise SystemExit(f"tampered case accepted: {label}")
        except w.FormatError:
            rejected.append({"label": label, "object": h(data)})
    out["must_reject"] = rejected

    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
