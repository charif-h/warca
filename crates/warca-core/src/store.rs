//! Encrypted object store: one file per object under `objects/`, named by
//! HMAC of the object ID so the storage provider learns nothing from names.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::container::{self, ObjectSpec, ObjectType, DEFAULT_CHUNK_LOG2};
use crate::crypto::{object_path, Key, KEY_LEN};
use crate::error::{Error, Result};
use crate::ids::{CollectionId, ObjectId};

pub(crate) struct ObjectStore {
    root: PathBuf,
    naming_key: Key,
}

impl ObjectStore {
    pub fn new(root: &Path, naming_key: Key) -> Self {
        ObjectStore {
            root: root.to_path_buf(),
            naming_key,
        }
    }

    pub fn path_of(&self, id: ObjectId) -> PathBuf {
        let rel = object_path(&self.naming_key, &id.to_bytes());
        let mut p = self.root.clone();
        p.extend(rel.split('/'));
        p
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("objects").join("tmp")
    }

    /// Encrypt `input` into a new object. The file appears atomically: it is
    /// written to `objects/tmp/`, synced, then renamed into place.
    #[allow(clippy::too_many_arguments)]
    pub fn put<R: Read>(
        &self,
        id: ObjectId,
        object_type: ObjectType,
        collection: CollectionId,
        collection_key: &[u8; KEY_LEN],
        vault_id: &[u8],
        input: R,
    ) -> Result<u64> {
        let dest = self.path_of(id);
        if dest.exists() {
            return Err(Error::Invalid(format!("object {id} already exists")));
        }
        fs::create_dir_all(dest.parent().expect("object path has a parent"))?;
        fs::create_dir_all(self.tmp_dir())?;
        let tmp = self.tmp_dir().join(format!("{id}.part"));
        let result = (|| -> Result<u64> {
            let file = File::create(&tmp)?;
            let mut w = BufWriter::new(file);
            let spec = ObjectSpec {
                object_type,
                object_id: id.to_bytes(),
                collection_id: collection.to_bytes(),
                vault_id,
                dek_wrapping_key: collection_key,
                chunk_log2: DEFAULT_CHUNK_LOG2,
            };
            let n = container::encrypt_stream(&spec, input, &mut w)?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            fs::rename(&tmp, &dest)?;
            Ok(n)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Decrypt and fully verify an object. Checks that the header names the
    /// expected object, so one object file cannot be swapped for another.
    pub fn get(
        &self,
        id: ObjectId,
        collection_key: &[u8; KEY_LEN],
        vault_id: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.path_of(id);
        let file = File::open(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(format!("object file for {id}")),
            _ => Error::Io(e),
        })?;
        let (header, plain) =
            container::decrypt_stream(BufReader::new(file), collection_key, vault_id)?;
        if header.object_id != id.to_bytes() {
            return Err(Error::Format(
                "object file belongs to another object".into(),
            ));
        }
        Ok(plain)
    }

    pub fn delete(&self, id: ObjectId) -> Result<()> {
        match fs::remove_file(self.path_of(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Write `bytes` to `path` atomically (temp file, fsync, rename).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
