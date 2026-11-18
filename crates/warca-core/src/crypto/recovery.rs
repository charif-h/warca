//! Recovery phrase: the 32-byte recovery key encoded as 24 BIP39 English
//! words (256 bits + 8-bit checksum). The words are only an encoding; the
//! BIP39 seed derivation is not used.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use super::{key_from_slice, Key, KEY_LEN};
use crate::error::{Error, Result};

pub const WORD_COUNT: usize = 24;

/// Encode a recovery key as 24 space-separated words.
pub fn words_from_key(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let m = Mnemonic::from_entropy_in(Language::English, key)
        .expect("32 bytes is a valid BIP39 entropy length");
    Zeroizing::new(m.to_string())
}

/// Decode a recovery phrase. Case and extra whitespace are ignored; a wrong
/// word or a typo is detected by the word list and the checksum.
pub fn key_from_words(phrase: &str) -> Result<Key> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    let count = cleaned.split(' ').filter(|w| !w.is_empty()).count();
    if count != WORD_COUNT {
        return Err(Error::RecoveryPhrase(format!(
            "a recovery phrase has {WORD_COUNT} words, this one has {count}"
        )));
    }
    let m = Mnemonic::parse_in_normalized(Language::English, &cleaned)
        .map_err(|e| Error::RecoveryPhrase(e.to_string()))?;
    let entropy = Zeroizing::new(m.to_entropy());
    key_from_slice(&entropy)
}
