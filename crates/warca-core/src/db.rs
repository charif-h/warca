//! The encrypted index database (SQLCipher 4, raw key from the vault master
//! key) and its schema migrations.

use std::path::Path;

use rusqlite::Connection;

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};

/// Each entry upgrades the schema by one version. Never edit a released
/// migration; append a new one.
const MIGRATIONS: &[&str] = &[
    // 1: collections, documents, objects, tags
    r#"
    CREATE TABLE collections (
        id           BLOB PRIMARY KEY,
        name         TEXT NOT NULL,
        wrapped_key  BLOB NOT NULL,
        created_at   TEXT NOT NULL
    );

    CREATE TABLE documents (
        id                 BLOB PRIMARY KEY,
        collection_id      BLOB NOT NULL REFERENCES collections(id),
        title              TEXT NOT NULL,
        doc_type           TEXT,
        original_filename  TEXT,
        sha256             BLOB NOT NULL UNIQUE,
        size_bytes         INTEGER NOT NULL,
        notes              TEXT NOT NULL DEFAULT '',
        imported_at        TEXT NOT NULL,
        updated_at         TEXT NOT NULL
    );

    CREATE TABLE objects (
        id           BLOB PRIMARY KEY,
        document_id  BLOB NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        object_type  INTEGER NOT NULL,
        size_bytes   INTEGER NOT NULL,
        created_at   TEXT NOT NULL
    );
    CREATE INDEX objects_by_document ON objects(document_id, object_type);

    CREATE TABLE tags (
        id    INTEGER PRIMARY KEY,
        name  TEXT NOT NULL UNIQUE COLLATE NOCASE
    );

    CREATE TABLE document_tags (
        document_id  BLOB NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        tag_id       INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
        PRIMARY KEY (document_id, tag_id)
    );
    "#,
];

pub(crate) fn open(path: &Path, index_key: &[u8; KEY_LEN], create: bool) -> Result<Connection> {
    if !create && !path.exists() {
        return Err(Error::NotFound(format!("{}", path.display())));
    }
    let conn = Connection::open(path)?;
    // The key must be set before anything else touches the database.
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(index_key)))?;
    // Fails with "file is not a database" if the key is wrong.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| Error::Format("the index database does not open with this key".into()))?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;
    if current > target {
        return Err(Error::Invalid(format!(
            "this vault was written by a newer Warca (schema {current}, this build knows {target})"
        )));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let version = i as i64 + 1;
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {version};"))?;
        tx.commit()?;
    }
    Ok(())
}
