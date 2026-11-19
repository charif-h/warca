//! The Warca v1 crypto format, as specified in `docs/adr/0001-crypto-format.md`.
//!
//! Everything here is a direct translation of the ADR and of the Python
//! reference implementation in `tools/crypto-reference/`. The test vectors in
//! `tests/vectors/crypto-v1.json` are checked byte for byte by
//! `crates/warca-core/tests/vectors.rs`.

pub mod container;
pub mod recovery;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const WRAP_NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// nonce (12) + encrypted key (32) + tag (16)
pub const WRAPPED_KEY_LEN: usize = WRAP_NONCE_LEN + KEY_LEN + TAG_LEN;

/// A 256-bit secret key that is wiped from memory when dropped.
pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// Fresh random key from the operating system's CSPRNG.
pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(k.as_mut());
    k
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn key_from_slice(bytes: &[u8]) -> Result<Key> {
    if bytes.len() != KEY_LEN {
        return Err(Error::Format("key has the wrong length".into()));
    }
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(bytes);
    Ok(k)
}

// --- Passphrase KDF ---------------------------------------------------------

/// Argon2id parameters, in the units used by `vault.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl KdfParams {
    /// Production default from the ADR: 256 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 262_144,
        iterations: 3,
        lanes: 4,
    };
    /// The weakest parameters a vault may use (meant for phones).
    pub const MINIMUM: KdfParams = KdfParams {
        memory_kib: 65_536,
        iterations: 2,
        lanes: 1,
    };

    /// Reject parameters below the ADR minimum, and absurd values that a
    /// tampered `vault.json` could use to exhaust memory or CPU.
    pub fn validate(&self) -> Result<()> {
        let min = Self::MINIMUM;
        if self.memory_kib < min.memory_kib
            || self.iterations < min.iterations
            || self.lanes < min.lanes
        {
            return Err(Error::Format(
                "key-derivation parameters are below the minimum".into(),
            ));
        }
        if self.memory_kib > 4 * 1024 * 1024 || self.iterations > 64 || self.lanes > 64 {
            return Err(Error::Format(
                "key-derivation parameters are unreasonably large".into(),
            ));
        }
        Ok(())
    }
}

/// Passphrase -> key-encryption key with Argon2id v0x13.
/// The passphrase is NFC-normalised first so it gives the same key on every OS.
pub fn derive_kek(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Key> {
    let normalised: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.lanes,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Format(format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(normalised.as_bytes(), salt, out.as_mut())
        .map_err(|e| Error::Format(format!("Argon2 failed: {e}")))?;
    Ok(out)
}

// --- HKDF subkeys -----------------------------------------------------------

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The keys derived from the vault master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subkey {
    /// Opens the SQLCipher database.
    Index,
    /// Turns object IDs into storage names.
    Naming,
    /// Protects change-log segments (sync, milestone 5).
    Sync,
}

impl Subkey {
    pub fn label(self) -> &'static str {
        match self {
            Subkey::Index => "index-key",
            Subkey::Naming => "naming-key",
            Subkey::Sync => "sync-key",
        }
    }
}

pub fn derive_subkey(vmk: &[u8; KEY_LEN], vault_id: &[u8], which: Subkey) -> Key {
    let info = format!("warca/v1/{}", which.label());
    hkdf(vmk, vault_id, info.as_bytes())
}

pub fn derive_recovery_kek(recovery_key: &[u8; KEY_LEN], vault_id: &[u8]) -> Key {
    hkdf(recovery_key, vault_id, b"warca/v1/recovery-kek")
}

// --- Key wrapping -----------------------------------------------------------

/// What a wrapped key is for. Bound into the AAD so a wrapped key cannot be
/// moved to another slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapPurpose {
    VmkByPassphrase,
    VmkByRecovery,
    VmkByDevice,
    CollectionKey,
    IdentityKey,
    Dek,
}

impl WrapPurpose {
    pub fn label(self) -> &'static str {
        match self {
            WrapPurpose::VmkByPassphrase => "vmk-by-passphrase",
            WrapPurpose::VmkByRecovery => "vmk-by-recovery",
            WrapPurpose::VmkByDevice => "vmk-by-device",
            WrapPurpose::CollectionKey => "collection-key",
            WrapPurpose::IdentityKey => "identity-key",
            WrapPurpose::Dek => "dek",
        }
    }
}

pub fn wrap_aad(purpose: WrapPurpose, context: &[u8]) -> Vec<u8> {
    let mut aad = b"warca/v1/wrap\x00".to_vec();
    aad.extend_from_slice(purpose.label().as_bytes());
    aad.push(0);
    aad.extend_from_slice(context);
    aad
}

/// Wrap `key` with an explicit nonce. Only tests should choose the nonce;
/// everything else uses [`wrap_key`].
pub fn wrap_key_with_nonce(
    wrapping_key: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    purpose: WrapPurpose,
    context: &[u8],
    nonce: &[u8; WRAP_NONCE_LEN],
) -> [u8; WRAPPED_KEY_LEN] {
    let cipher = Aes256Gcm::new(wrapping_key.into());
    let aad = wrap_aad(purpose, context);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: key,
                aad: &aad,
            },
        )
        .expect("AES-GCM encryption of 32 bytes cannot fail");
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..WRAP_NONCE_LEN].copy_from_slice(nonce);
    out[WRAP_NONCE_LEN..].copy_from_slice(&ct);
    out
}

pub fn wrap_key(
    wrapping_key: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    purpose: WrapPurpose,
    context: &[u8],
) -> [u8; WRAPPED_KEY_LEN] {
    wrap_key_with_nonce(wrapping_key, key, purpose, context, &random_bytes())
}

pub fn unwrap_key(
    wrapping_key: &[u8; KEY_LEN],
    wrapped: &[u8],
    purpose: WrapPurpose,
    context: &[u8],
) -> Result<Key> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(Error::Format("wrapped key has the wrong length".into()));
    }
    let cipher = Aes256Gcm::new(wrapping_key.into());
    let aad = wrap_aad(purpose, context);
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&wrapped[..WRAP_NONCE_LEN]),
                Payload {
                    msg: &wrapped[WRAP_NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Unwrap)?,
    );
    key_from_slice(&plain)
}

// --- Object naming ----------------------------------------------------------

/// `hex(HMAC-SHA256(naming key, object_id))`
pub fn object_name(naming_key: &[u8; KEY_LEN], object_id: &[u8; 16]) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(naming_key).expect("HMAC accepts any key length");
    mac.update(object_id);
    hex::encode(mac.finalize().into_bytes())
}

/// `objects/<name[0:2]>/<name>.bin`, always with forward slashes.
pub fn object_path(naming_key: &[u8; KEY_LEN], object_id: &[u8; 16]) -> String {
    let name = object_name(naming_key, object_id);
    format!("objects/{}/{}.bin", &name[..2], name)
}
