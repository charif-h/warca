# Warca architecture

This is the reference summary of the Warca design. Individual decisions are recorded as ADRs in [`adr/`](adr/).

## Principles

1. **Your device is the source of truth.** The app works fully offline. The cloud is a replica and a transport, never a requirement.
2. **Plaintext never leaves your devices unless you say so.** Documents, thumbnails, OCR text, filenames and the search index are encrypted before they touch disk or the network. The only exception is an online OCR or AI provider you explicitly enable for a given kind of document.
3. **Originals are immutable.** OCR output, metadata and annotations are layers on top and can be regenerated.
4. **AI suggests, you decide.** Key fields stay unconfirmed until you accept them, and a confirmed value is never overwritten by a model.
5. **Boring, inspectable formats.** SQLite, PDF/A and a documented encryption container.

## Components

```mermaid
flowchart LR
  subgraph Device["Your computer"]
    direction TB
    UI["Desktop UI<br/>Tauri webview + pdf.js"]
    Core["Vault core (Rust)<br/>crypto, storage, index, jobs, sync"]
    Worker["Extraction worker (Python)<br/>OCRmyPDF, Tesseract, pikepdf"]
    Router["Provider router<br/>local, own machine, or online"]
    LLM["Ollama on localhost"]
    DB[("Encrypted index<br/>SQLCipher + FTS5")]
    Blobs[("Encrypted object store")]
    UI <--> Core
    Core <--> Worker
    Worker --> Router --> LLM
    Core <--> DB
    Core <--> Blobs
  end
  Cloud[("Your cloud storage<br/>ciphertext only")]
  Phone["Phone app<br/>same Rust core"]
  Online["Online OCR / AI API<br/>opt-in"]
  Router -.->|"only if allowed"| Online
  Core -->|"encrypted objects + change log"| Cloud
  Phone <-->|"encrypted objects + change log"| Cloud
```

- **Vault core (Rust)** owns the keys and is the only component that reads or writes the vault.
- **Extraction worker (Python)** is a separate low-privilege process with no network access and no vault keys. It receives one decrypted document at a time over a pipe.
- **Provider router** sends each OCR or AI job to the provider allowed for that document: this computer (default), another machine you own, or an online API.

## Vault layout

```
MyVault.vault/
├── vault.json      # format version, KDF parameters, salt, wrapped keys
├── index.db        # SQLCipher: metadata, OCR text, FTS5 index, annotations
├── objects/        # encrypted write-once blobs, named by HMAC(naming key, id)
├── oplog/<device>/ # encrypted append-only change log, one folder per device
├── snapshots/      # encrypted metadata snapshots for fast bootstrap
└── trash/          # deleted objects, purged after 30 days
```

## Keys

```mermaid
flowchart TD
  P["Passphrase"] -->|"Argon2id"| KEK["Key-encryption key"]
  KEK -->|"unwraps"| VMK["Vault master key"]
  RK["Recovery key (printed kit)"] -->|"unwraps"| VMK
  DK["Device key (OS keychain)"] -->|"unwraps"| VMK
  VMK -->|"HKDF"| DBK["Index key"]
  VMK -->|"HKDF"| NK["Naming key"]
  VMK -->|"HKDF"| SK["Sync key"]
  VMK -->|"wraps"| CK["Collection keys"]
  CK -->|"wrap"| DEK["Per-file data keys"]
  DEK -->|"AES-256-GCM, chunked"| F["Encrypted objects"]
```

The exact format is specified in [ADR 0001](adr/0001-crypto-format.md).

**Family sharing (later).** Version 1 is single user, but every user has an X25519 identity key pair and documents belong to collections. Sharing a collection means wrapping its key for a family member's public key; no file is re-encrypted.

## Extraction pipeline

```mermaid
flowchart TD
  A["Import"] --> B["Hash, duplicate check"]
  B --> C["Encrypt and store original"]
  C --> D{"Text layer?"}
  D -->|"no"| E["OCRmyPDF + Tesseract (eng+fra+ara)"]
  D -->|"yes"| F["Text + word boxes"]
  E --> F
  F --> G["FTS5 index: searchable now"]
  G --> H["Rule pass: dates, IDs, IBANs"]
  H --> I["Model pass: type, fields, summary"]
  I --> J{"Value found in OCR text?"}
  J --> K["Review queue: you confirm key fields"]
```

- The model returns JSON that matches a fixed schema. Text is sent first; page images only when OCR confidence is low or the layout matters.
- Every extracted value is looked up in the OCR text; values that cannot be found are flagged.
- Document text is untrusted: the model has no tools and no network, so prompt injection can at worst produce wrong suggestions.

## Languages

Default language set: `eng+fra+ara`. Search normalises Arabic letter variants (أ إ آ → ا, ة/ه, ى/ي), removes tashkeel and tatweel, converts Eastern Arabic digits, and recognises Hijri dates. The UI uses automatic text direction.

## Sync and backup

- Objects are write-once and each device writes only its own change-log folder, so devices never write the same file.
- Changes carry hybrid logical clock timestamps; per field the latest wins, except that a user-confirmed value beats a model suggestion.
- The live SQLite file is never synced.
- Sync is not backup: Warca also makes scheduled encrypted backups and runs restore drills.

## Threat model (summary)

| Threat | Protection |
|---|---|
| Cloud breach or account takeover | Only ciphertext and HMAC names are uploaded |
| Stolen laptop or phone | Encrypted at rest, Argon2id, auto-lock, device revocation |
| Malicious PDF | Parsed in a sandboxed worker with no network and no keys |
| Online provider | Off by default, per-document privacy levels, redaction, audit badge |
| AI hallucination | Schema output, grounding check, human confirmation |
| Data loss | Write-once objects, 30-day trash, versioned and offline backups |
| Malware on an unlocked device | Out of scope |
