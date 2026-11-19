//! End-to-end tests of a vault on disk. All PDFs here are tiny synthetic files
//! generated on the fly.

use std::fs;
use std::path::{Path, PathBuf};

use warca_core::{DocumentUpdate, Error, ImportOptions, ImportOutcome, KdfParams, Vault};

const PASS: &str = "correct horse battery staple";
const FAST: KdfParams = KdfParams::MINIMUM;

fn synthetic_pdf(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let content = format!(
        "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n% synthetic test file: {body}\n%%EOF\n"
    );
    fs::write(&path, content).unwrap();
    path
}

fn new_vault(dir: &Path) -> (Vault, String) {
    let (vault, kit) = Vault::create_with_params(&dir.join("test.vault"), PASS, FAST).unwrap();
    (vault, kit.words.to_string())
}

#[test]
fn create_lock_and_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let (vault, words) = new_vault(tmp.path());
    assert_eq!(words.split(' ').count(), 24);
    assert_eq!(vault.collections().unwrap().len(), 1);
    vault.lock();

    assert!(matches!(
        Vault::open(&root, "wrong passphrase!"),
        Err(Error::WrongPassphrase)
    ));
    let vault = Vault::open(&root, PASS).unwrap();
    assert_eq!(vault.collections().unwrap()[0].name, "Personal");

    // vault.json holds no key material in the clear and names no documents.
    let json = fs::read_to_string(root.join("vault.json")).unwrap();
    assert!(json.contains("\"argon2id\""));
    assert!(!json.contains(PASS));
}

#[test]
fn refuses_to_create_over_existing_files() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("something.txt"), "hello").unwrap();
    assert!(matches!(
        Vault::create_with_params(tmp.path(), PASS, FAST),
        Err(Error::VaultExists(_))
    ));
}

#[test]
fn rejects_weak_passphrases_and_kdf_parameters() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        Vault::create_with_params(&tmp.path().join("a"), "short", FAST),
        Err(Error::WeakPassphrase(_))
    ));
    let weak = KdfParams {
        memory_kib: 1024,
        iterations: 1,
        lanes: 1,
    };
    assert!(Vault::create_with_params(&tmp.path().join("b"), PASS, weak).is_err());
}

#[test]
fn recovery_phrase_unlocks_and_resets_the_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let (mut vault, words) = new_vault(tmp.path());
    let pdf = synthetic_pdf(tmp.path(), "passport.pdf", "passport");
    let id = vault
        .import_pdf(&pdf, ImportOptions::default())
        .unwrap()
        .id();
    vault.lock();

    let mut wrong: Vec<&str> = words.split(' ').collect();
    wrong.swap(0, 1);
    assert!(Vault::open_with_recovery(&root, &wrong.join(" ")).is_err());

    let mut vault = Vault::open_with_recovery(&root, &words).unwrap();
    vault
        .change_passphrase_with_params("a brand new passphrase", FAST)
        .unwrap();
    vault.lock();

    assert!(matches!(
        Vault::open(&root, PASS),
        Err(Error::WrongPassphrase)
    ));
    let vault = Vault::open(&root, "a brand new passphrase").unwrap();
    assert_eq!(
        vault.read_original(id).unwrap().as_slice(),
        fs::read(&pdf).unwrap()
    );
}

#[test]
fn replacing_the_recovery_kit_revokes_the_old_phrase() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let (mut vault, old_words) = new_vault(tmp.path());
    let new_words = vault.replace_recovery_kit().unwrap().words.to_string();
    vault.lock();
    assert!(matches!(
        Vault::open_with_recovery(&root, &old_words),
        Err(Error::WrongRecoveryKey)
    ));
    Vault::open_with_recovery(&root, &new_words).unwrap();
}

#[test]
fn import_view_edit_and_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(tmp.path());
    let pdf = synthetic_pdf(tmp.path(), "Birth certificate.pdf", "birth");
    let original = fs::read(&pdf).unwrap();

    let outcome = vault
        .import_pdf(
            &pdf,
            ImportOptions {
                tags: vec!["family".into(), "Identity".into()],
                doc_type: Some("certificate".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let ImportOutcome::Imported(id) = outcome else {
        panic!("expected a new import")
    };

    let doc = vault.document(id).unwrap();
    assert_eq!(doc.title, "Birth certificate");
    assert_eq!(
        doc.original_filename.as_deref(),
        Some("Birth certificate.pdf")
    );
    assert_eq!(doc.doc_type.as_deref(), Some("certificate"));
    assert_eq!(doc.tags, vec!["family", "Identity"]);
    assert_eq!(doc.size_bytes, original.len() as u64);

    // The stored object is ciphertext: no trace of the PDF.
    let stored = fs::read(vault.original_object_path(id).unwrap()).unwrap();
    assert_eq!(&stored[..4], b"WRCA");
    assert!(!stored.windows(5).any(|w| w == b"%PDF-"));
    assert!(!stored.windows(5).any(|w| w == b"birth"));
    assert_eq!(
        vault.read_original(id).unwrap().as_slice(),
        original.as_slice()
    );

    // Same file again is a duplicate, even under another name.
    fs::copy(&pdf, tmp.path().join("copy.pdf")).unwrap();
    assert_eq!(
        vault
            .import_pdf(&tmp.path().join("copy.pdf"), ImportOptions::default())
            .unwrap(),
        ImportOutcome::Duplicate(id)
    );

    let doc = vault
        .update_document(
            id,
            DocumentUpdate {
                title: Some("Birth certificate (Charif)".into()),
                notes: Some("Original is in the blue folder".into()),
                add_tags: vec!["urgent".into()],
                remove_tags: vec!["IDENTITY".into()],
                doc_type: Some(None),
            },
        )
        .unwrap();
    assert_eq!(doc.title, "Birth certificate (Charif)");
    assert_eq!(doc.notes, "Original is in the blue folder");
    assert_eq!(doc.tags, vec!["family", "urgent"]);
    assert_eq!(doc.doc_type, None);
    assert_eq!(vault.documents_with_tag("FAMILY").unwrap().len(), 1);
    assert_eq!(
        vault.tags().unwrap(),
        vec![("family".into(), 1), ("urgent".into(), 1)]
    );

    let out = tmp.path().join("exported.pdf");
    vault.export_original(id, &out).unwrap();
    assert_eq!(fs::read(&out).unwrap(), original);
    assert!(
        vault.export_original(id, &out).is_err(),
        "must not overwrite"
    );

    let object_path = vault.original_object_path(id).unwrap();
    vault.delete_document(id).unwrap();
    assert!(!object_path.exists());
    assert!(matches!(vault.document(id), Err(Error::NotFound(_))));
    assert!(vault.documents().unwrap().is_empty());
}

#[test]
fn rejects_files_that_are_not_pdfs() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(tmp.path());
    let path = tmp.path().join("notes.pdf");
    fs::write(&path, "just some text").unwrap();
    assert!(matches!(
        vault.import_pdf(&path, ImportOptions::default()),
        Err(Error::NotAPdf(_))
    ));
}

#[test]
fn hundred_documents_survive_a_restart() {
    // Milestone 1 "done when": 100 documents survive a restart.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let src = tmp.path().join("scans");
    fs::create_dir(&src).unwrap();
    let (mut vault, _) = new_vault(tmp.path());
    let mut expected = Vec::new();
    for i in 0..100 {
        let pdf = synthetic_pdf(&src, &format!("doc-{i:03}.pdf"), &format!("document {i}"));
        let id = vault
            .import_pdf(
                &pdf,
                ImportOptions {
                    tags: vec![format!("batch-{}", i % 5)],
                    ..Default::default()
                },
            )
            .unwrap()
            .id();
        expected.push((id, fs::read(&pdf).unwrap()));
    }
    vault.lock();

    let vault = Vault::open(&root, PASS).unwrap();
    assert_eq!(vault.documents().unwrap().len(), 100);
    assert_eq!(vault.documents_with_tag("batch-3").unwrap().len(), 20);
    for (id, bytes) in &expected {
        assert_eq!(
            vault.read_original(*id).unwrap().as_slice(),
            bytes.as_slice()
        );
    }
    assert!(vault.verify_all().unwrap().is_empty());
}

#[test]
fn detects_tampered_and_swapped_object_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(tmp.path());
    let a = vault
        .import_pdf(
            &synthetic_pdf(tmp.path(), "a.pdf", "aaa"),
            ImportOptions::default(),
        )
        .unwrap()
        .id();
    let b = vault
        .import_pdf(
            &synthetic_pdf(tmp.path(), "b.pdf", "bbb"),
            ImportOptions::default(),
        )
        .unwrap()
        .id();
    let pa = vault.original_object_path(a).unwrap();
    let pb = vault.original_object_path(b).unwrap();

    // Swap the two encrypted files: each must be rejected, not shown as the other.
    let (ba, bb) = (fs::read(&pa).unwrap(), fs::read(&pb).unwrap());
    fs::write(&pa, &bb).unwrap();
    fs::write(&pb, &ba).unwrap();
    assert!(vault.read_original(a).is_err());
    assert!(vault.read_original(b).is_err());
    assert_eq!(vault.verify_all().unwrap().len(), 2);

    // Restore, then flip one byte of ciphertext.
    fs::write(&pa, &ba).unwrap();
    let mut bad = bb.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    fs::write(&pb, &bad).unwrap();
    assert!(vault.read_original(a).is_ok());
    assert!(vault.read_original(b).is_err());
}

#[test]
fn index_database_is_encrypted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let (mut vault, _) = new_vault(tmp.path());
    vault
        .import_pdf(
            &synthetic_pdf(tmp.path(), "Secret Title.pdf", "x"),
            ImportOptions {
                tags: vec!["confidential-tag".into()],
                ..Default::default()
            },
        )
        .unwrap();
    vault.lock();
    for name in ["index.db", "index.db-wal"] {
        if let Ok(bytes) = fs::read(root.join(name)) {
            assert!(
                !bytes.windows(15).any(|w| w == b"SQLite format 3"),
                "{name}"
            );
            assert!(!bytes.windows(12).any(|w| w == b"Secret Title"), "{name}");
            assert!(
                !bytes.windows(16).any(|w| w == b"confidential-tag"),
                "{name}"
            );
        }
    }
}

#[test]
fn collections_keep_separate_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.vault");
    let (mut vault, _) = new_vault(tmp.path());
    let family = vault.create_collection("Family").unwrap();
    let id = vault
        .import_pdf(
            &synthetic_pdf(tmp.path(), "kids.pdf", "kids"),
            ImportOptions {
                collection: Some(family),
                ..Default::default()
            },
        )
        .unwrap()
        .id();
    assert_eq!(vault.document(id).unwrap().collection_id, family);
    vault.lock();
    let vault = Vault::open(&root, PASS).unwrap();
    assert_eq!(vault.collections().unwrap().len(), 2);
    assert!(vault.read_original(id).is_ok());
}
