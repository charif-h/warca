//! Creating, unlocking and using a vault.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::crypto::container::ObjectType;
use crate::crypto::{
    derive_kek, derive_recovery_kek, derive_subkey, random_bytes, random_key, recovery, unwrap_key,
    wrap_key, KdfParams, Key, Subkey, WrapPurpose,
};
use crate::db;
use crate::error::{Error, Result};
use crate::ids::{CollectionId, DocumentId, ObjectId};
use crate::store::{write_atomic, ObjectStore};

/// Minimum passphrase length, in characters, for new vaults and passphrase
/// changes. The recovery phrase is the fallback for a forgotten passphrase.
pub const MIN_PASSPHRASE_CHARS: usize = 10;

const VAULT_FILE: &str = "vault.json";
const INDEX_FILE: &str = "index.db";
const DEFAULT_COLLECTION_NAME: &str = "Personal";

// --- vault.json ---------------------------------------------------------------

const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn b64d(field: &str, s: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|_| Error::Format(format!("{field} is not valid base64url")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    vault_id: String,
    kdf: KdfJson,
    vmk_wrapped: WrappedVmk,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfJson {
    alg: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedVmk {
    passphrase: String,
    recovery: String,
    #[serde(default)]
    devices: BTreeMap<String, String>,
}

impl VaultFile {
    fn load(root: &Path) -> Result<(VaultFile, [u8; 16])> {
        let path = root.join(VAULT_FILE);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotAVault(root.display().to_string()),
            _ => Error::Io(e),
        })?;
        let vf: VaultFile = serde_json::from_slice(&bytes)?;
        if vf.format != "warca-vault" {
            return Err(Error::NotAVault(root.display().to_string()));
        }
        if vf.version != 1 {
            return Err(Error::Format(format!(
                "unsupported vault version {}",
                vf.version
            )));
        }
        if vf.kdf.alg != "argon2id" || vf.kdf.version != 0x13 {
            return Err(Error::Format("unsupported key-derivation function".into()));
        }
        vf.kdf_params().validate()?;
        let id: [u8; 16] = b64d("vault_id", &vf.vault_id)?
            .try_into()
            .map_err(|_| Error::Format("vault_id must be 16 bytes".into()))?;
        Ok((vf, id))
    }

    fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            lanes: self.kdf.lanes,
        }
    }

    fn save(&self, root: &Path) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        write_atomic(&root.join(VAULT_FILE), &json)
    }
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond")
        .format(&Rfc3339)
        .expect("RFC 3339 formatting cannot fail for a UTC time")
}

fn check_passphrase_strength(passphrase: &str) -> Result<()> {
    if passphrase.nfc().count() < MIN_PASSPHRASE_CHARS {
        return Err(Error::WeakPassphrase(MIN_PASSPHRASE_CHARS));
    }
    Ok(())
}

// --- Public types -------------------------------------------------------------

/// The recovery phrase for a vault. Show it once, ask the user to write it
/// down or print it, and never store it.
pub struct RecoveryKit {
    pub words: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub id: CollectionId,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub id: DocumentId,
    pub collection_id: CollectionId,
    pub title: String,
    pub doc_type: Option<String>,
    pub original_filename: Option<String>,
    /// SHA-256 of the original file, hex. Used to detect duplicates.
    pub sha256: String,
    pub size_bytes: u64,
    pub notes: String,
    pub tags: Vec<String>,
    pub imported_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Defaults to the file name without its extension.
    pub title: Option<String>,
    pub doc_type: Option<String>,
    pub tags: Vec<String>,
    /// Defaults to the vault's default collection.
    pub collection: Option<CollectionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    Imported(DocumentId),
    /// The same file (by SHA-256) is already in the vault.
    Duplicate(DocumentId),
}

impl ImportOutcome {
    pub fn id(self) -> DocumentId {
        match self {
            ImportOutcome::Imported(id) | ImportOutcome::Duplicate(id) => id,
        }
    }
}

/// Changes to a document's metadata. `None` leaves a field unchanged.
#[derive(Debug, Clone, Default)]
pub struct DocumentUpdate {
    pub title: Option<String>,
    /// `Some(None)` clears the type.
    pub doc_type: Option<Option<String>>,
    pub notes: Option<String>,
    pub add_tags: Vec<String>,
    pub remove_tags: Vec<String>,
}

// --- Vault ----------------------------------------------------------------------

/// An unlocked vault. Keys live only as long as this value and are wiped from
/// memory when it is dropped (or [`Vault::lock`]ed).
pub struct Vault {
    root: PathBuf,
    file: VaultFile,
    vault_id: [u8; 16],
    vmk: Key,
    conn: Connection,
    store: ObjectStore,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new vault in `root` (which must be missing or empty) with the
    /// production key-derivation parameters.
    pub fn create(root: &Path, passphrase: &str) -> Result<(Vault, RecoveryKit)> {
        Self::create_with_params(root, passphrase, KdfParams::DEFAULT)
    }

    pub fn create_with_params(
        root: &Path,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<(Vault, RecoveryKit)> {
        check_passphrase_strength(passphrase)?;
        kdf.validate()?;
        if root.exists() {
            if !root.is_dir() || fs::read_dir(root)?.next().is_some() {
                return Err(Error::VaultExists(root.display().to_string()));
            }
        } else {
            fs::create_dir_all(root)?;
        }
        let result = Self::create_inner(root, passphrase, kdf);
        if result.is_err() {
            for name in [VAULT_FILE, INDEX_FILE, "index.db-wal", "index.db-shm"] {
                let _ = fs::remove_file(root.join(name));
            }
            let _ = fs::remove_dir_all(root.join("objects"));
        }
        result
    }

    fn create_inner(root: &Path, passphrase: &str, kdf: KdfParams) -> Result<(Vault, RecoveryKit)> {
        let vault_id: [u8; 16] = random_bytes();
        let salt: [u8; 16] = random_bytes();
        let vmk = random_key();
        let recovery_key = random_key();

        let kek = derive_kek(passphrase, &salt, kdf)?;
        let rkek = derive_recovery_kek(&recovery_key, &vault_id);
        let file = VaultFile {
            format: "warca-vault".into(),
            version: 1,
            vault_id: B64.encode(vault_id),
            kdf: KdfJson {
                alg: "argon2id".into(),
                version: 0x13,
                memory_kib: kdf.memory_kib,
                iterations: kdf.iterations,
                lanes: kdf.lanes,
                salt: B64.encode(salt),
            },
            vmk_wrapped: WrappedVmk {
                passphrase: B64.encode(wrap_key(
                    &kek,
                    &vmk,
                    WrapPurpose::VmkByPassphrase,
                    &vault_id,
                )),
                recovery: B64.encode(wrap_key(&rkek, &vmk, WrapPurpose::VmkByRecovery, &vault_id)),
                devices: BTreeMap::new(),
            },
            created_at: now(),
        };

        fs::create_dir_all(root.join("objects"))?;
        let vault = Self::assemble(root, file, vault_id, vmk, true)?;
        vault.create_collection_inner(DEFAULT_COLLECTION_NAME)?;
        // vault.json is written last, so a half-created folder is never
        // mistaken for a vault.
        vault.file.save(root)?;
        let words = recovery::words_from_key(&recovery_key);
        Ok((vault, RecoveryKit { words }))
    }

    /// Unlock with the passphrase.
    pub fn open(root: &Path, passphrase: &str) -> Result<Vault> {
        let (file, vault_id) = VaultFile::load(root)?;
        let salt = b64d("kdf.salt", &file.kdf.salt)?;
        let kek = derive_kek(passphrase, &salt, file.kdf_params())?;
        let wrapped = b64d("vmk_wrapped.passphrase", &file.vmk_wrapped.passphrase)?;
        let vmk = unwrap_key(&kek, &wrapped, WrapPurpose::VmkByPassphrase, &vault_id)
            .map_err(|_| Error::WrongPassphrase)?;
        Self::assemble(root, file, vault_id, vmk, false)
    }

    /// Unlock with the 24-word recovery phrase. Usually followed by
    /// [`Vault::change_passphrase`].
    pub fn open_with_recovery(root: &Path, phrase: &str) -> Result<Vault> {
        let (file, vault_id) = VaultFile::load(root)?;
        let recovery_key = recovery::key_from_words(phrase)?;
        let rkek = derive_recovery_kek(&recovery_key, &vault_id);
        let wrapped = b64d("vmk_wrapped.recovery", &file.vmk_wrapped.recovery)?;
        let vmk = unwrap_key(&rkek, &wrapped, WrapPurpose::VmkByRecovery, &vault_id)
            .map_err(|_| Error::WrongRecoveryKey)?;
        Self::assemble(root, file, vault_id, vmk, false)
    }

    fn assemble(
        root: &Path,
        file: VaultFile,
        vault_id: [u8; 16],
        vmk: Key,
        create: bool,
    ) -> Result<Vault> {
        let index_key = derive_subkey(&vmk, &vault_id, Subkey::Index);
        let naming_key = derive_subkey(&vmk, &vault_id, Subkey::Naming);
        let conn = db::open(&root.join(INDEX_FILE), &index_key, create)?;
        Ok(Vault {
            root: root.to_path_buf(),
            file,
            vault_id,
            vmk,
            conn,
            store: ObjectStore::new(root, naming_key),
        })
    }

    /// Lock the vault: closes the database and wipes keys from memory.
    pub fn lock(self) {
        drop(self)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn created_at(&self) -> &str {
        &self.file.created_at
    }

    /// Replace the passphrase. Only the 60-byte wrapped master key changes;
    /// no document is re-encrypted. Uses at least the current KDF strength.
    pub fn change_passphrase(&mut self, new_passphrase: &str) -> Result<()> {
        check_passphrase_strength(new_passphrase)?;
        let old = self.file.kdf_params();
        let d = KdfParams::DEFAULT;
        let params = KdfParams {
            memory_kib: old.memory_kib.max(d.memory_kib),
            iterations: old.iterations.max(d.iterations),
            lanes: old.lanes.max(d.lanes),
        };
        self.change_passphrase_with_params(new_passphrase, params)
    }

    pub fn change_passphrase_with_params(
        &mut self,
        new_passphrase: &str,
        params: KdfParams,
    ) -> Result<()> {
        check_passphrase_strength(new_passphrase)?;
        params.validate()?;
        let salt: [u8; 16] = random_bytes();
        let kek = derive_kek(new_passphrase, &salt, params)?;
        let mut file = self.file.clone();
        file.kdf.memory_kib = params.memory_kib;
        file.kdf.iterations = params.iterations;
        file.kdf.lanes = params.lanes;
        file.kdf.salt = B64.encode(salt);
        file.vmk_wrapped.passphrase = B64.encode(wrap_key(
            &kek,
            &self.vmk,
            WrapPurpose::VmkByPassphrase,
            &self.vault_id,
        ));
        file.save(&self.root)?;
        self.file = file;
        Ok(())
    }

    /// Make a new recovery phrase. The old one stops working.
    pub fn replace_recovery_kit(&mut self) -> Result<RecoveryKit> {
        let recovery_key = random_key();
        let rkek = derive_recovery_kek(&recovery_key, &self.vault_id);
        let mut file = self.file.clone();
        file.vmk_wrapped.recovery = B64.encode(wrap_key(
            &rkek,
            &self.vmk,
            WrapPurpose::VmkByRecovery,
            &self.vault_id,
        ));
        file.save(&self.root)?;
        self.file = file;
        Ok(RecoveryKit {
            words: recovery::words_from_key(&recovery_key),
        })
    }

    // --- Collections ------------------------------------------------------------

    fn collection_context(&self, id: CollectionId) -> Vec<u8> {
        let mut ctx = self.vault_id.to_vec();
        ctx.extend_from_slice(&id.to_bytes());
        ctx
    }

    fn create_collection_inner(&self, name: &str) -> Result<CollectionId> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("a collection needs a name".into()));
        }
        let id = CollectionId::new();
        let key = random_key();
        let wrapped = wrap_key(
            &self.vmk,
            &key,
            WrapPurpose::CollectionKey,
            &self.collection_context(id),
        );
        self.conn.execute(
            "INSERT INTO collections (id, name, wrapped_key, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id.to_bytes(), name, wrapped.as_slice(), now()],
        )?;
        Ok(id)
    }

    /// Collections group documents under one key, so that a collection can
    /// later be shared with a family member without re-encrypting anything.
    pub fn create_collection(&mut self, name: &str) -> Result<CollectionId> {
        self.create_collection_inner(name)
    }

    pub fn collections(&self) -> Result<Vec<Collection>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, created_at FROM collections ORDER BY created_at, id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Collection {
                id: CollectionId::from_sql(r.get(0)?)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The first collection, created with the vault.
    pub fn default_collection(&self) -> Result<CollectionId> {
        let bytes: Vec<u8> = self.conn.query_row(
            "SELECT id FROM collections ORDER BY created_at, id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        Ok(CollectionId::from_sql(bytes)?)
    }

    fn collection_key(&self, id: CollectionId) -> Result<Key> {
        let wrapped: Vec<u8> = self
            .conn
            .query_row(
                "SELECT wrapped_key FROM collections WHERE id = ?1",
                [id.to_bytes()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("collection {id}")))?;
        unwrap_key(
            &self.vmk,
            &wrapped,
            WrapPurpose::CollectionKey,
            &self.collection_context(id),
        )
        .map_err(|_| Error::Format(format!("the key of collection {id} does not unwrap")))
    }

    // --- Import -----------------------------------------------------------------

    /// Import a PDF. The file is encrypted into the object store; the original
    /// on disk is left untouched (the caller decides whether to delete it).
    pub fn import_pdf(&mut self, path: &Path, opts: ImportOptions) -> Result<ImportOutcome> {
        let display = path.display().to_string();
        let mut file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::Invalid(format!("{display} is not a file")));
        }

        // Pass 1: check it is a PDF and hash it.
        let mut head = [0u8; 1024];
        let n = read_up_to(&mut file, &mut head)?;
        if !head[..n].windows(5).any(|w| w == b"%PDF-") {
            return Err(Error::NotAPdf(display));
        }
        file.seek(SeekFrom::Start(0))?;
        let (sha, size) = hash_reader(&mut file)?;
        if let Some(existing) = self.document_by_hash(&sha)? {
            return Ok(ImportOutcome::Duplicate(existing));
        }

        let collection = match opts.collection {
            Some(c) => c,
            None => self.default_collection()?,
        };
        let key = self.collection_key(collection)?;
        let doc_id = DocumentId::new();
        let obj_id = ObjectId::new();

        // Pass 2: encrypt, hashing again to catch a file that changed in between.
        file.seek(SeekFrom::Start(0))?;
        let mut tee = HashingReader::new(BufReader::new(file));
        let written = self.store.put(
            obj_id,
            ObjectType::Original,
            collection,
            &key,
            &self.vault_id,
            &mut tee,
        )?;
        let (sha2, size2) = tee.finish();
        if sha2 != sha || size2 != size || written != size {
            let _ = self.store.delete(obj_id);
            return Err(Error::Invalid(format!(
                "{display} changed while it was being imported; try again"
            )));
        }

        let title = opts
            .title
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .or_else(|| {
                path.file_stem()
                    .map(|s| s.to_string_lossy().trim().to_string())
            })
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "Untitled".to_string());
        let filename = path.file_name().map(|s| s.to_string_lossy().into_owned());
        let doc_type = clean_optional(opts.doc_type);
        let ts = now();

        let res = (|| -> Result<()> {
            let tx = self.conn.transaction()?;
            tx.execute(
                "INSERT INTO documents (id, collection_id, title, doc_type, original_filename,
                    sha256, size_bytes, notes, imported_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?8, ?8)",
                params![
                    doc_id.to_bytes(),
                    collection.to_bytes(),
                    title,
                    doc_type,
                    filename,
                    sha.as_slice(),
                    size as i64,
                    ts
                ],
            )?;
            tx.execute(
                "INSERT INTO objects (id, document_id, object_type, size_bytes, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    obj_id.to_bytes(),
                    doc_id.to_bytes(),
                    ObjectType::Original as u8,
                    size as i64,
                    ts
                ],
            )?;
            for tag in &opts.tags {
                add_tag(&tx, doc_id, tag)?;
            }
            tx.commit()?;
            Ok(())
        })();
        if let Err(e) = res {
            let _ = self.store.delete(obj_id);
            return Err(e);
        }
        Ok(ImportOutcome::Imported(doc_id))
    }

    fn document_by_hash(&self, sha: &[u8; 32]) -> Result<Option<DocumentId>> {
        let found: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT id FROM documents WHERE sha256 = ?1",
                [sha.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.map(DocumentId::from_sql).transpose()?)
    }

    // --- Reading and editing ----------------------------------------------------

    /// All documents, newest first.
    pub fn documents(&self) -> Result<Vec<Document>> {
        self.query_documents(
            "SELECT id, collection_id, title, doc_type, original_filename, sha256, size_bytes,
                    notes, imported_at, updated_at
             FROM documents ORDER BY imported_at DESC, id DESC",
            [],
        )
    }

    /// Documents carrying `tag` (case-insensitive), newest first.
    pub fn documents_with_tag(&self, tag: &str) -> Result<Vec<Document>> {
        self.query_documents(
            "SELECT d.id, d.collection_id, d.title, d.doc_type, d.original_filename, d.sha256,
                    d.size_bytes, d.notes, d.imported_at, d.updated_at
             FROM documents d
             JOIN document_tags dt ON dt.document_id = d.id
             JOIN tags t ON t.id = dt.tag_id
             WHERE t.name = ?1
             ORDER BY d.imported_at DESC, d.id DESC",
            [tag.trim()],
        )
    }

    pub fn document(&self, id: DocumentId) -> Result<Document> {
        self.query_documents(
            "SELECT id, collection_id, title, doc_type, original_filename, sha256, size_bytes,
                    notes, imported_at, updated_at
             FROM documents WHERE id = ?1",
            [id.to_bytes()],
        )?
        .pop()
        .ok_or_else(|| Error::NotFound(format!("document {id}")))
    }

    fn query_documents<P: rusqlite::Params>(&self, sql: &str, p: P) -> Result<Vec<Document>> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut docs = stmt
            .query_map(p, |r| {
                let sha: Vec<u8> = r.get(5)?;
                Ok(Document {
                    id: DocumentId::from_sql(r.get(0)?)?,
                    collection_id: CollectionId::from_sql(r.get(1)?)?,
                    title: r.get(2)?,
                    doc_type: r.get(3)?,
                    original_filename: r.get(4)?,
                    sha256: hex::encode(sha),
                    size_bytes: r.get::<_, i64>(6)? as u64,
                    notes: r.get(7)?,
                    tags: Vec::new(),
                    imported_at: r.get(8)?,
                    updated_at: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut tag_stmt = self.conn.prepare(
            "SELECT t.name FROM tags t JOIN document_tags dt ON dt.tag_id = t.id
             WHERE dt.document_id = ?1 ORDER BY t.name COLLATE NOCASE",
        )?;
        for d in &mut docs {
            d.tags = tag_stmt
                .query_map([d.id.to_bytes()], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
        }
        Ok(docs)
    }

    /// All tags with the number of documents using each.
    pub fn tags(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.name, count(dt.document_id) FROM tags t
             LEFT JOIN document_tags dt ON dt.tag_id = t.id
             GROUP BY t.id HAVING count(dt.document_id) > 0
             ORDER BY t.name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn update_document(&mut self, id: DocumentId, update: DocumentUpdate) -> Result<Document> {
        self.document(id)?;
        let tx = self.conn.transaction()?;
        if let Some(title) = update.title {
            let title = title.trim();
            if title.is_empty() {
                return Err(Error::Invalid("the title cannot be empty".into()));
            }
            tx.execute(
                "UPDATE documents SET title = ?1 WHERE id = ?2",
                params![title, id.to_bytes()],
            )?;
        }
        if let Some(doc_type) = update.doc_type {
            tx.execute(
                "UPDATE documents SET doc_type = ?1 WHERE id = ?2",
                params![clean_optional(doc_type), id.to_bytes()],
            )?;
        }
        if let Some(notes) = update.notes {
            tx.execute(
                "UPDATE documents SET notes = ?1 WHERE id = ?2",
                params![notes, id.to_bytes()],
            )?;
        }
        for tag in &update.add_tags {
            add_tag(&tx, id, tag)?;
        }
        for tag in &update.remove_tags {
            tx.execute(
                "DELETE FROM document_tags WHERE document_id = ?1
                 AND tag_id = (SELECT id FROM tags WHERE name = ?2)",
                params![id.to_bytes(), tag.trim()],
            )?;
        }
        tx.execute(
            "UPDATE documents SET updated_at = ?1 WHERE id = ?2",
            params![now(), id.to_bytes()],
        )?;
        tx.commit()?;
        self.document(id)
    }

    fn original_object(&self, id: DocumentId) -> Result<(ObjectId, CollectionId)> {
        let (obj, coll): (Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT o.id, d.collection_id FROM objects o JOIN documents d ON d.id = o.document_id
                 WHERE o.document_id = ?1 AND o.object_type = ?2",
                params![id.to_bytes(), ObjectType::Original as u8],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("document {id}")))?;
        Ok((ObjectId::from_sql(obj)?, CollectionId::from_sql(coll)?))
    }

    /// Decrypt the original file into memory, after verifying every chunk.
    pub fn read_original(&self, id: DocumentId) -> Result<Zeroizing<Vec<u8>>> {
        let (obj, coll) = self.original_object(id)?;
        let key = self.collection_key(coll)?;
        let bytes = self.store.get(obj, &key, &self.vault_id)?;
        let doc = self.document(id)?;
        let sha: [u8; 32] = Sha256::digest(&bytes[..]).into();
        if hex::encode(sha) != doc.sha256 {
            return Err(Error::Format(format!(
                "document {id} does not match its recorded checksum"
            )));
        }
        Ok(bytes)
    }

    /// Write a decrypted copy of the original to `dest`. This puts plaintext on
    /// disk, so it is meant for explicit user exports only.
    pub fn export_original(&self, id: DocumentId, dest: &Path) -> Result<()> {
        let bytes = self.read_original(id)?;
        if dest.exists() {
            return Err(Error::Invalid(format!("{} already exists", dest.display())));
        }
        write_atomic(dest, &bytes)
    }

    /// Delete a document, its tags links and its encrypted objects.
    pub fn delete_document(&mut self, id: DocumentId) -> Result<()> {
        self.document(id)?;
        let objects: Vec<ObjectId> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM objects WHERE document_id = ?1")?;
            let rows = stmt.query_map([id.to_bytes()], |r| ObjectId::from_sql(r.get(0)?))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        self.conn
            .execute("DELETE FROM documents WHERE id = ?1", [id.to_bytes()])?;
        // Database first: an orphaned object file is harmless, a database row
        // pointing at a missing file is not.
        for obj in objects {
            self.store.delete(obj)?;
        }
        Ok(())
    }

    /// Decrypt and check every document. Returns the ones that failed.
    pub fn verify_all(&self) -> Result<Vec<(DocumentId, Error)>> {
        let mut failures = Vec::new();
        for doc in self.documents()? {
            if let Err(e) = self.read_original(doc.id) {
                failures.push((doc.id, e));
            }
        }
        Ok(failures)
    }

    /// Path of the encrypted file holding a document's original. For tests
    /// and diagnostics.
    #[doc(hidden)]
    pub fn original_object_path(&self, id: DocumentId) -> Result<PathBuf> {
        let (obj, _) = self.original_object(id)?;
        Ok(self.store.path_of(obj))
    }
}

// --- Helpers ----------------------------------------------------------------------

fn clean_optional(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn add_tag(conn: &Connection, doc: DocumentId, tag: &str) -> Result<()> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Ok(());
    }
    if tag.chars().count() > 64 {
        return Err(Error::Invalid("tags are limited to 64 characters".into()));
    }
    conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?1)", [tag])?;
    conn.execute(
        "INSERT OR IGNORE INTO document_tags (document_id, tag_id)
         SELECT ?1, id FROM tags WHERE name = ?2",
        params![doc.to_bytes(), tag],
    )?;
    Ok(())
}

fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn hash_reader<R: Read>(r: &mut R) -> Result<([u8; 32], u64)> {
    let mut h = HashingReader::new(r);
    std::io::copy(&mut h, &mut std::io::sink())?;
    Ok(h.finish())
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        HashingReader {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }
    fn finish(self) -> ([u8; 32], u64) {
        (self.hasher.finalize().into(), self.count)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}
