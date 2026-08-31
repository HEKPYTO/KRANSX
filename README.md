# KRANSX

[![CI](https://forge.int.tsunyanapat.com/tsun/KRANSX/actions/workflows/ci.yml/badge.svg)](https://forge.int.tsunyanapat.com/tsun/KRANSX)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Authenticated encryption with adaptive compression for Python.

KRANSX seals arbitrary bytes into a compact, authenticated envelope. It applies Zstandard compression only when it reduces size, otherwise stores the payload as-is, and protects both with AES-256-GCM-SIV. The result is a single self-contained binary with 29 bytes of overhead.

## Features

- Adaptive compression — Zstandard when beneficial, raw otherwise
- Authenticated encryption — AES-256-GCM-SIV (nonce-misuse resistant)
- Small fixed overhead — 29 bytes (`suite` + `nonce` + `tag`)
- Simple API — `seal` / `open_data`, fully typed
- Dictionary support — optional Zstandard dictionaries for structured data
- CLI — `keygen`, `seal`, `open`, `train`
- No background services or async dependencies

## Installation

```bash
pip install kransx
```

For development:

```bash
uv sync --locked --extra dev
```

Requires Python 3.10+, `cryptography >= 42`, `zstandard >= 0.22`.

## Usage

### Python API

```python
import secrets
from kransx import open_data, seal

key = secrets.token_bytes(32)  # 32 uniformly random bytes
aad = b"record-42"              # associated data, authenticated but not encrypted

sealed = seal(b"hello world", key, aad=aad)
assert open_data(sealed, key, aad=aad) == b"hello world"
```

Authentication failures raise `cryptography.exceptions.InvalidTag` (wrong key, AAD, dictionary, or modified bytes). Structural errors raise `ValueError`.

With a shared dictionary (non-secret, improves compression on similar payloads):

```python
from kransx import train_dict

dictionary = train_dict([b'{"user":1,"action":"login"}'] * 300)
sealed = seal(b'{"user":1,"action":"login"}', key, dict_obj=dictionary)
assert open_data(sealed, key, dict_obj=dictionary) == b'{"user":1,"action":"login"}'
```

API reference:

```python
seal(data: bytes, key: bytes, *, dict_obj=None, aad=b"", compress=True, level=3) -> bytes
open_data(blob: bytes, key: bytes, *, dict_obj=None, aad=b"", max_output_size=64*1024*1024) -> bytes
train_dict(samples: Iterable[bytes], dict_size=16384) -> ZstdCompressionDict
save_dict(dictionary, path) / load_dict(path)
```

`compress=True` retains the Zstandard frame only when strictly smaller than the input. `max_output_size` limits the decompressed output size.

### CLI

```bash
kransx keygen key.bin
kransx seal plain.bin sealed.bin --key-file key.bin --aad 7265636f72642d3432
kransx open sealed.bin restored.bin --key-file key.bin --aad 7265636f72642d3432

kransx train 'samples/*.json' --output model.dict
kransx seal plain.bin out.bin --key-file key.bin --dict model.dict
kransx open out.bin restored.bin --key-file key.bin --dict model.dict --max-output-size 1048576
```

- `--aad` accepts hex-encoded bytes
- `--max-output-size` caps plaintext size on open
- Output files are created exclusively and never overwritten

## Design

Envelope layout: `suite (1) | nonce (12) | ciphertext | tag (16)`

| Suite | Payload | Authenticated associated data |
|-------|---------|-------------------------------|
| `0x21` | Zstandard frame | `suite` + dictionary binding + `aad` |
| `0x22` | raw bytes | `suite` + `aad` |

- The dictionary binding is `SHA-256` over the dictionary bytes (or a constant for no dictionary), ensuring a mismatched dictionary fails authentication before decompression.
- Keys are 32 random bytes expanded via HKDF-SHA256 to the AEAD key. A fresh 12-byte nonce is generated per seal.
- Opening validates the envelope before decryption: size and suite checks, then AEAD authentication, then — for compressed payloads — single-frame Zstandard validation and bounded decompression.

## Security considerations

This library implements the envelope only. Key generation, distribution, storage, rotation, and encrypted-input size bounding are the caller's responsibility.

- **Keys** must be 32 uniformly random bytes. Passwords are not valid keys.
- **Nonces** are generated with `os.urandom(12)` per seal. AES-GCM-SIV is nonce-misuse resistant, but reuse should still be avoided.
- **Compression oracles** — the sealed size reveals whether compression was used. Do not compress data that mixes secrets with attacker-controlled input without application-level separation. Use `compress=False` when this is a concern.
- **Resource limits** — `max_output_size` bounds decompressed output. For untrusted inputs, also bound the encrypted input size before calling `open_data`.

## Development

```bash
uv sync --locked --extra dev
uv run ruff check .
uv run mypy kransx
uv run pytest -q
```

Pre-commit hooks are configured for `ruff` and `mypy` (see `.pre-commit-config.yaml`).

```
kransx/  seal, open_data, dicts, cli
tests/   conformance vectors, tamper checks, resource limits
```

## License

MIT — see [LICENSE](LICENSE).
