# Crypto reference implementation

A small, readable Python implementation of the [v1 encryption format](../../docs/adr/0001-crypto-format.md). It exists to generate and check the test vectors; it is not used by the app.

Regenerate the vectors (needs `cryptography` >= 44 and the BIP39 English word list):

```sh
curl -sSO https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
python3 -I tools/crypto-reference/gen_vectors.py --wordlist english.txt > tests/vectors/crypto-v1.json
```

The output is deterministic, so `git diff` should show no change unless the format changed.
