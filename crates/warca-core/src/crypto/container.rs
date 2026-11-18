//! The object container (ADR 0001, "Object container"): a 107-byte header
//! followed by AES-256-GCM chunks in the STREAM construction.

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use super::{
    random_bytes, random_key, unwrap_key, wrap_key_with_nonce, WrapPurpose, KEY_LEN, TAG_LEN,
    WRAPPED_KEY_LEN, WRAP_NONCE_LEN,
};
use crate::error::{Error, Result};

pub const MAGIC: &[u8; 4] = b"WRCA";
pub const FORMAT_VERSION: u8 = 1;
pub const NONCE_PREFIX_LEN: usize = 7;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 16 + 16 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN;
pub const MIN_CHUNK_LOG2: u8 = 6;
pub const MAX_CHUNK_LOG2: u8 = 24;
pub const DEFAULT_CHUNK_LOG2: u8 = 20;

/// What a stored object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    Original = 1,
    OcrPdf = 2,
    Thumbnail = 3,
    PageImage = 4,
    ChangeLogSegment = 5,
}

impl ObjectType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => ObjectType::Original,
            2 => ObjectType::OcrPdf,
            3 => ObjectType::Thumbnail,
            4 => ObjectType::PageImage,
            5 => ObjectType::ChangeLogSegment,
            _ => return None,
        })
    }
}

/// The parsed, not yet authenticated, header of an object.
#[derive(Debug, Clone)]
pub struct Header {
    pub object_type: ObjectType,
    pub chunk_log2: u8,
    pub object_id: [u8; 16],
    pub collection_id: [u8; 16],
    pub wrapped_dek: [u8; WRAPPED_KEY_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..4].copy_from_slice(MAGIC);
        h[4] = FORMAT_VERSION;
        h[5] = self.object_type as u8;
        h[6] = self.chunk_log2;
        h[7] = 0;
        h[8..24].copy_from_slice(&self.object_id);
        h[24..40].copy_from_slice(&self.collection_id);
        h[40..40 + WRAPPED_KEY_LEN].copy_from_slice(&self.wrapped_dek);
        h[40 + WRAPPED_KEY_LEN..].copy_from_slice(&self.nonce_prefix);
        h
    }

    pub fn parse(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_LEN {
            return Err(Error::Format("too short for a header".into()));
        }
        if &data[..4] != MAGIC {
            return Err(Error::Format("bad magic".into()));
        }
        if data[4] != FORMAT_VERSION {
            return Err(Error::Format("unsupported version".into()));
        }
        let object_type = ObjectType::from_u8(data[5])
            .ok_or_else(|| Error::Format("unknown object type".into()))?;
        if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&data[6]) {
            return Err(Error::Format("chunk size out of range".into()));
        }
        if data[7] != 0 {
            return Err(Error::Format("reserved byte must be zero".into()));
        }
        let mut h = Header {
            object_type,
            chunk_log2: data[6],
            object_id: [0; 16],
            collection_id: [0; 16],
            wrapped_dek: [0; WRAPPED_KEY_LEN],
            nonce_prefix: [0; NONCE_PREFIX_LEN],
        };
        h.object_id.copy_from_slice(&data[8..24]);
        h.collection_id.copy_from_slice(&data[24..40]);
        h.wrapped_dek
            .copy_from_slice(&data[40..40 + WRAPPED_KEY_LEN]);
        h.nonce_prefix
            .copy_from_slice(&data[40 + WRAPPED_KEY_LEN..HEADER_LEN]);
        Ok(h)
    }
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&index.to_be_bytes());
    n[11] = last as u8;
    n
}

/// Read until `buf` is full or the reader is exhausted. Returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Inputs for writing one object.
pub struct ObjectSpec<'a> {
    pub object_type: ObjectType,
    pub object_id: [u8; 16],
    pub collection_id: [u8; 16],
    pub vault_id: &'a [u8],
    /// The collection key (or the sync key for change-log segments).
    pub dek_wrapping_key: &'a [u8; KEY_LEN],
    pub chunk_log2: u8,
}

/// Fixed random inputs, so test vectors can be reproduced.
pub struct Randomness<'a> {
    pub dek: &'a [u8; KEY_LEN],
    pub wrap_nonce: &'a [u8; WRAP_NONCE_LEN],
    pub nonce_prefix: &'a [u8; NONCE_PREFIX_LEN],
}

/// Encrypt everything from `input` into `output` as one object, with fresh
/// random DEK and nonces. Returns the number of plaintext bytes.
pub fn encrypt_stream<R: Read, W: Write>(spec: &ObjectSpec, input: R, output: W) -> Result<u64> {
    let dek = random_key();
    let wrap_nonce = random_bytes();
    let nonce_prefix = random_bytes();
    encrypt_stream_with(
        spec,
        &Randomness {
            dek: &dek,
            wrap_nonce: &wrap_nonce,
            nonce_prefix: &nonce_prefix,
        },
        input,
        output,
    )
}

/// Like [`encrypt_stream`] but with caller-chosen randomness. Never use fixed
/// values outside tests.
pub fn encrypt_stream_with<R: Read, W: Write>(
    spec: &ObjectSpec,
    rnd: &Randomness,
    mut input: R,
    mut output: W,
) -> Result<u64> {
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&spec.chunk_log2) {
        return Err(Error::Format("chunk size out of range".into()));
    }
    let mut context = spec.vault_id.to_vec();
    context.extend_from_slice(&spec.object_id);
    let wrapped_dek = wrap_key_with_nonce(
        spec.dek_wrapping_key,
        rnd.dek,
        WrapPurpose::Dek,
        &context,
        rnd.wrap_nonce,
    );
    let header = Header {
        object_type: spec.object_type,
        chunk_log2: spec.chunk_log2,
        object_id: spec.object_id,
        collection_id: spec.collection_id,
        wrapped_dek,
        nonce_prefix: *rnd.nonce_prefix,
    }
    .to_bytes();
    output.write_all(&header)?;

    let cipher = Aes256Gcm::new(rnd.dek.into());
    let size = 1usize << spec.chunk_log2;
    // Plaintext buffers are wiped after use.
    let mut cur = Zeroizing::new(vec![0u8; size]);
    let mut next = Zeroizing::new(vec![0u8; size]);
    let mut cur_len = read_full(&mut input, &mut cur)?;
    let mut index: u32 = 0;
    let mut total: u64 = 0;
    loop {
        // Look ahead one chunk to know whether the current one is the last.
        let next_len = if cur_len == size {
            read_full(&mut input, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let nonce = chunk_nonce(rnd.nonce_prefix, index, last);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &cur[..cur_len],
                    aad: &header,
                },
            )
            .map_err(|_| Error::Format("encryption failed".into()))?;
        output.write_all(&ct)?;
        total += cur_len as u64;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::Format("object too large".into()))?;
    }
    output.flush()?;
    Ok(total)
}

/// Encrypt a byte slice into a new `Vec`.
pub fn encrypt_bytes(spec: &ObjectSpec, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN * 2);
    encrypt_stream(spec, plaintext, &mut out)?;
    Ok(out)
}

/// Decrypt and fully verify an object read from `input`. No plaintext is
/// returned unless every chunk authenticates and the final chunk is present
/// and is the end of the data.
pub fn decrypt_stream<R: Read>(
    mut input: R,
    dek_wrapping_key: &[u8; KEY_LEN],
    vault_id: &[u8],
) -> Result<(Header, Zeroizing<Vec<u8>>)> {
    let mut header_bytes = [0u8; HEADER_LEN];
    if read_full(&mut input, &mut header_bytes)? < HEADER_LEN {
        return Err(Error::Format("too short for a header".into()));
    }
    let header = Header::parse(&header_bytes)?;
    let mut context = vault_id.to_vec();
    context.extend_from_slice(&header.object_id);
    let dek = unwrap_key(
        dek_wrapping_key,
        &header.wrapped_dek,
        WrapPurpose::Dek,
        &context,
    )
    .map_err(|_| Error::Format("the data key does not unwrap".into()))?;
    let cipher = Aes256Gcm::new(dek.as_ref().into());

    let full = (1usize << header.chunk_log2) + TAG_LEN;
    let mut out = Zeroizing::new(Vec::new());
    let mut cur = vec![0u8; full];
    let mut next = vec![0u8; full];
    let mut cur_len = read_full(&mut input, &mut cur)?;
    let mut index: u32 = 0;
    loop {
        if cur_len < TAG_LEN {
            return Err(Error::Format("truncated: final chunk missing".into()));
        }
        let next_len = if cur_len == full {
            read_full(&mut input, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let nonce = chunk_nonce(&header.nonce_prefix, index, last);
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &cur[..cur_len],
                        aad: &header_bytes,
                    },
                )
                .map_err(|_| Error::Format(format!("chunk {index} failed authentication")))?,
        );
        if last && index > 0 && plain.is_empty() {
            return Err(Error::Format("empty final chunk after data".into()));
        }
        out.extend_from_slice(&plain);
        if last {
            return Ok((header, out));
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::Format("object too large".into()))?;
    }
}

/// Decrypt and verify an object held in memory.
pub fn decrypt_bytes(
    data: &[u8],
    dek_wrapping_key: &[u8; KEY_LEN],
    vault_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_stream(data, dek_wrapping_key, vault_id).map(|(_, p)| p)
}
