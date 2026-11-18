use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    /// Malformed, truncated or tampered data, or data encrypted under another key.
    #[error("invalid or damaged data: {0}")]
    Format(String),
    /// A wrapped key did not open with the given key.
    #[error("the key does not match")]
    Unwrap,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("wrong recovery phrase")]
    WrongRecoveryKey,
    #[error("invalid recovery phrase: {0}")]
    RecoveryPhrase(String),
    #[error("passphrase too short: use at least {0} characters")]
    WeakPassphrase(usize),
    #[error("{0} is not empty; a new vault needs an empty or missing folder")]
    VaultExists(String),
    #[error("{0} is not a Warca vault")]
    NotAVault(String),
    #[error("{0} is not a PDF file")]
    NotAPdf(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("vault.json: {0}")]
    Json(#[from] serde_json::Error),
}
