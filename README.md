# Warca

**A private, encrypted safe-deposit box for your scanned documents.**

Warca keeps passports, contracts, certificates, bills and other official papers encrypted on your own devices, reads them with OCR and a local AI model, and lets you find any of them in seconds. The cloud is optional and only ever stores encrypted data.

The name joins the Arabic *waraqa* (ورقة, a sheet of paper) and the Latin *arca* (a strongbox): a strongbox for your papers. It is pronounced *WAR-ka*.

> **Status: early development.** Nothing here is ready for real documents yet. See the [roadmap](#roadmap).

## What it will do

- **Encrypt everything on your device** with AES-256-GCM, using keys derived from your passphrase with Argon2id. A printed recovery kit covers a forgotten passphrase.
- **Make every scan searchable** with OCRmyPDF and Tesseract, in English, French and Arabic, including pages that mix scripts.
- **Suggest metadata with AI**: document type, issuer, people, dates, expiry and a summary, from a local model through Ollama, or an online provider you explicitly allow. You confirm the important fields.
- **Search instantly** with SQLite FTS5 inside an encrypted database, plus tags, people, dates and your own notes.
- **Sync between laptop and phone** through your own storage (WebDAV such as Nextcloud, or S3-compatible), without a Warca server.
- **Remind you** before documents expire.

## Architecture

The design is described in [docs/architecture.md](docs/architecture.md). In short:

| Part | Technology |
|---|---|
| App shell | Tauri 2 (desktop, later iOS and Android) |
| Vault core | Rust: encryption, storage, index, sync |
| Extraction worker | Python: OCRmyPDF, Tesseract, pikepdf |
| AI | Ollama on the device by default; pluggable providers |
| Database | SQLite + FTS5, encrypted with SQLCipher |

Design decisions are recorded in [docs/adr/](docs/adr/).

## Roadmap

Work is organised in [milestones](https://github.com/charif-h/warca/milestones):

| Milestone | Goal |
|---|---|
| M0 · Spikes and decisions | Remove the big unknowns before writing product code |
| M1 · Encrypted vault MVP | Store and view documents safely |
| M2 · OCR and full-text search | Find any document by any word in it |
| M3 · AI extraction and review | Documents organise themselves, with you in control |
| M4 · Annotations and organisation | Highlights, notes, smart folders, export |
| M5 · Sync and backup | A second device and a disaster-proof copy |
| M6 · Mobile app | The same vault on your phone |
| M7 · Semantic search | Ask questions in plain language |

## Contributing

Never commit real documents, even as test data. The `.gitignore` and CI block PDFs and images outside `tests/fixtures/synthetic/`, which is only for made-up documents.

Security problems: see [SECURITY.md](SECURITY.md).
