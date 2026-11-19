# Security policy

Warca is built to hold people's most sensitive documents, so security reports are very welcome.

## Status

Warca is in early development. **Do not store real documents in it yet.** The encryption format is still being specified in [`docs/adr/`](docs/adr/) and has not been reviewed.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for security problems.

Please include:

- what you found and which part of Warca it affects (encryption, storage, sync, extraction, UI),
- steps or a proof of concept to reproduce it,
- the impact you expect.

You will get an answer within 7 days. Fixes for confirmed issues are published with credit to the reporter, unless you prefer to stay anonymous.

## Scope

In scope: the encryption format and key handling, anything that could leak plaintext (documents, OCR text, metadata, thumbnails) to disk, the network or a sync provider, PDF parsing in the extraction worker, and sync integrity.

Out of scope: attacks that require malware already running on an unlocked device; this is listed as a residual risk in the threat model.
