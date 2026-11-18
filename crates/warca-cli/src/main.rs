//! `warca`: a small command-line front end for the vault core, so the core can
//! be used and tested before the desktop app exists.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use warca_core::{
    DocumentId, DocumentUpdate, ImportOptions, ImportOutcome, KdfParams, Vault,
    MIN_PASSPHRASE_CHARS,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "warca",
    version,
    about = "Your encrypted safe-deposit box for documents"
)]
struct Cli {
    /// Vault folder.
    #[arg(long, short, env = "WARCA_VAULT", global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault and show its recovery phrase.
    Init {
        /// Use the weakest allowed key derivation (fast; for trying things out only).
        #[arg(long, hide = true)]
        insecure_fast_kdf: bool,
    },
    /// Import one or more PDF files. The originals are left in place.
    Import {
        files: Vec<PathBuf>,
        /// Tag to add to every imported document (repeatable).
        #[arg(long = "tag", short)]
        tags: Vec<String>,
        /// Document type, such as passport or contract.
        #[arg(long = "type")]
        doc_type: Option<String>,
    },
    /// List documents.
    List {
        /// Only documents with this tag.
        #[arg(long, short)]
        tag: Option<String>,
    },
    /// Show one document's details.
    Show { id: DocumentId },
    /// Change a document's title, type, notes or tags.
    Edit {
        id: DocumentId,
        #[arg(long)]
        title: Option<String>,
        /// Set the type; pass an empty string to clear it.
        #[arg(long = "type")]
        doc_type: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "add-tag")]
        add_tags: Vec<String>,
        #[arg(long = "remove-tag")]
        remove_tags: Vec<String>,
    },
    /// List tags with their document counts.
    Tags,
    /// Write a decrypted copy of a document to a file.
    Export { id: DocumentId, output: PathBuf },
    /// Delete a document from the vault.
    Delete {
        id: DocumentId,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Decrypt and check every document.
    Verify,
    /// Change the passphrase.
    Passwd,
    /// Unlock with the recovery phrase and set a new passphrase.
    Recover,
    /// Make a new recovery phrase (the old one stops working).
    NewRecoveryPhrase,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let root = cli
        .vault
        .clone()
        .context("no vault given: pass --vault <folder> or set WARCA_VAULT")?;
    match cli.command {
        Command::Init { insecure_fast_kdf } => init(&root, insecure_fast_kdf),
        Command::Recover => recover(&root),
        cmd => {
            let mut vault = unlock(&root)?;
            run_unlocked(&mut vault, cmd)
        }
    }
}

fn run_unlocked(vault: &mut Vault, cmd: Command) -> Result<()> {
    match cmd {
        Command::Import {
            files,
            tags,
            doc_type,
        } => {
            if files.is_empty() {
                bail!("give at least one PDF file to import");
            }
            let (mut new, mut dup, mut failed) = (0, 0, 0);
            for f in &files {
                let opts = ImportOptions {
                    tags: tags.clone(),
                    doc_type: doc_type.clone(),
                    ..Default::default()
                };
                match vault.import_pdf(f, opts) {
                    Ok(ImportOutcome::Imported(id)) => {
                        new += 1;
                        println!("imported  {id}  {}", f.display());
                    }
                    Ok(ImportOutcome::Duplicate(id)) => {
                        dup += 1;
                        println!("duplicate {id}  {} (already in the vault)", f.display());
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("failed    {}: {e}", f.display());
                    }
                }
            }
            println!("{new} imported, {dup} duplicates, {failed} failed");
            if failed > 0 {
                bail!("some files were not imported");
            }
        }
        Command::List { tag } => {
            let docs = match tag {
                Some(t) => vault.documents_with_tag(&t)?,
                None => vault.documents()?,
            };
            for d in &docs {
                let tags = if d.tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", d.tags.join(", "))
                };
                println!("{}  {}  {}{}", d.id, &d.imported_at[..10], d.title, tags);
            }
            println!("{} document(s)", docs.len());
        }
        Command::Show { id } => {
            let d = vault.document(id)?;
            println!("id:        {}", d.id);
            println!("title:     {}", d.title);
            println!("type:      {}", d.doc_type.as_deref().unwrap_or("-"));
            println!(
                "tags:      {}",
                if d.tags.is_empty() {
                    "-".into()
                } else {
                    d.tags.join(", ")
                }
            );
            println!(
                "file:      {}",
                d.original_filename.as_deref().unwrap_or("-")
            );
            println!("size:      {} bytes", d.size_bytes);
            println!("sha256:    {}", d.sha256);
            println!("imported:  {}", d.imported_at);
            println!("updated:   {}", d.updated_at);
            if !d.notes.is_empty() {
                println!("notes:\n{}", d.notes);
            }
        }
        Command::Edit {
            id,
            title,
            doc_type,
            notes,
            add_tags,
            remove_tags,
        } => {
            let d = vault.update_document(
                id,
                DocumentUpdate {
                    title,
                    doc_type: doc_type.map(|t| Some(t).filter(|t| !t.trim().is_empty())),
                    notes,
                    add_tags,
                    remove_tags,
                },
            )?;
            println!("updated {}  {}", d.id, d.title);
        }
        Command::Tags => {
            for (name, count) in vault.tags()? {
                println!("{count:>5}  {name}");
            }
        }
        Command::Export { id, output } => {
            vault.export_original(id, &output)?;
            println!(
                "wrote {} (unencrypted copy: delete it when you are done)",
                output.display()
            );
        }
        Command::Delete { id, yes } => {
            let d = vault.document(id)?;
            if !yes && !confirm(&format!("Delete \"{}\" from the vault?", d.title))? {
                println!("cancelled");
                return Ok(());
            }
            vault.delete_document(id)?;
            println!("deleted {id}");
        }
        Command::Verify => {
            let total = vault.documents()?.len();
            let failures = vault.verify_all()?;
            for (id, e) in &failures {
                println!("FAILED {id}: {e}");
            }
            println!("{} of {total} document(s) verified", total - failures.len());
            if !failures.is_empty() {
                bail!("some documents failed verification");
            }
        }
        Command::Passwd => {
            let new = new_passphrase()?;
            vault.change_passphrase(&new)?;
            println!("passphrase changed");
        }
        Command::NewRecoveryPhrase => {
            if !confirm("Your current recovery phrase will stop working. Continue?")? {
                println!("cancelled");
                return Ok(());
            }
            let kit = vault.replace_recovery_kit()?;
            show_recovery(&kit.words);
        }
        Command::Init { .. } | Command::Recover => unreachable!("handled before unlocking"),
    }
    Ok(())
}

fn init(root: &Path, fast: bool) -> Result<()> {
    println!("Creating a new vault in {}", root.display());
    println!("Choose a passphrase of at least {MIN_PASSPHRASE_CHARS} characters. A few unrelated words work well.");
    let pass = new_passphrase()?;
    println!("Deriving keys (this takes a few seconds by design)...");
    let params = if fast {
        KdfParams::MINIMUM
    } else {
        KdfParams::DEFAULT
    };
    let (vault, kit) = Vault::create_with_params(root, &pass, params)?;
    show_recovery(&kit.words);
    vault.lock();
    println!("Vault created.");
    Ok(())
}

fn recover(root: &Path) -> Result<()> {
    let phrase = Zeroizing::new(read_line("Enter your 24-word recovery phrase: ")?);
    let mut vault = Vault::open_with_recovery(root, &phrase)?;
    println!("Recovery phrase accepted. Choose a new passphrase.");
    let pass = new_passphrase()?;
    vault.change_passphrase(&pass)?;
    println!("Passphrase reset. Your recovery phrase still works.");
    Ok(())
}

fn unlock(root: &Path) -> Result<Vault> {
    let pass = passphrase("Passphrase: ")?;
    Vault::open(root, &pass).with_context(|| format!("could not unlock {}", root.display()))
}

fn show_recovery(words: &str) {
    println!();
    println!("RECOVERY PHRASE: write these 24 words on paper and keep them somewhere safe.");
    println!("They are the only way back in if you forget your passphrase. They are shown once.");
    println!();
    for (i, chunk) in words.split(' ').collect::<Vec<_>>().chunks(6).enumerate() {
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(j, w)| format!("{:>2}. {:<10}", i * 6 + j + 1, w))
            .collect();
        println!("  {}", line.join(" "));
    }
    println!();
}

/// Reads the passphrase from WARCA_PASSPHRASE if set (for scripts and tests),
/// otherwise prompts without echo.
fn passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("WARCA_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    if !io::stdin().is_terminal() {
        return Ok(Zeroizing::new(read_line(prompt)?));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn new_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("WARCA_NEW_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    let a = passphrase("New passphrase: ")?;
    if std::env::var("WARCA_PASSPHRASE").is_ok() {
        return Ok(a);
    }
    let b = passphrase("Repeat it: ")?;
    if *a != *b {
        bail!("the passphrases do not match");
    }
    Ok(a)
}

fn read_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut s = String::new();
    io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn confirm(question: &str) -> Result<bool> {
    let answer = read_line(&format!("{question} [y/N] "))?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}
