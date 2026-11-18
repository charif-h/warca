//! Identifiers. All are ULIDs: 16 bytes on disk, 26 Crockford base32
//! characters when shown to people.

use std::fmt;
use std::str::FromStr;

use ulid::Ulid;

use crate::error::Error;

macro_rules! ulid_id {
    ($name:ident, $what:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Ulid);

        impl $name {
            pub fn new() -> Self {
                Self(Ulid::new())
            }
            pub fn from_bytes(b: [u8; 16]) -> Self {
                Self(Ulid::from_bytes(b))
            }
            pub fn to_bytes(self) -> [u8; 16] {
                self.0.to_bytes()
            }
            pub(crate) fn from_sql(v: Vec<u8>) -> rusqlite::Result<Self> {
                let b: [u8; 16] = v.try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        concat!("bad ", $what, " id").into(),
                    )
                })?;
                Ok(Self::from_bytes(b))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Error> {
                Ulid::from_string(s.trim())
                    .map(Self)
                    .map_err(|_| Error::Invalid(format!("{:?} is not a valid {} id", s, $what)))
            }
        }
    };
}

ulid_id!(DocumentId, "document");
ulid_id!(ObjectId, "object");
ulid_id!(CollectionId, "collection");
