//! Warca vault core.
//!
//! A vault is a folder that holds only ciphertext and one plaintext file with
//! no secrets:
//!
//! ```text
//! my.vault/
//!   vault.json          KDF parameters and the wrapped vault master key
//!   index.db            SQLCipher database (metadata, tags, notes, keys)
//!   objects/ab/ab…cd.bin  encrypted documents, named by HMAC of their ID
//! ```
//!
//! See `docs/adr/0001-crypto-format.md` for the format.

pub mod crypto;
mod db;
mod error;
mod ids;
mod store;
mod vault;

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use ids::{CollectionId, DocumentId, ObjectId};
pub use vault::{
    Collection, Document, DocumentUpdate, ImportOptions, ImportOutcome, RecoveryKit, Vault,
    MIN_PASSPHRASE_CHARS,
};
