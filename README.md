# KRANSX

[![CI](https://forge.int.tsunyanapat.com/tsun/KRANSX/actions/workflows/ci.yml/badge.svg)](https://forge.int.tsunyanapat.com/tsun/KRANSX/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://forge.int.tsunyanapat.com/tsun/KRANSX/src/branch/main/LICENSE)

KRANSX turns bytes into a compact, authenticated envelope. It uses Zstandard
when compression makes the payload smaller, stores raw bytes otherwise, and
protects either form with AES-256-GCM-SIV.

## Install

```bash
python -m pip install kransx
```

## Python

```python
import secrets

from kransx import open_data, seal

key = secrets.token_bytes(32)
message = b"hello from KRANSX"
aad = b"example"
envelope = seal(message, key, aad=aad)
assert open_data(envelope, key, aad=aad) == message
```

`aad` is authenticated but not encrypted; supply the same bytes to both calls.

## CLI

```bash
kransx keygen key.bin
kransx seal message.txt message.krx --key-file key.bin
kransx open message.krx restored.txt --key-file key.bin
```

Outputs are created exclusively and are never overwritten. Use `--aad` for
hexadecimal associated data, `--no-compress` for raw storage, and
`--max-output-size` to cap opened plaintext.

## Construction and security

The envelope is `suite || nonce || ciphertext || tag`: suite `0x21` stores a
smaller Zstandard frame and `0x22` stores raw bytes. A fresh 12-byte nonce,
suite, AAD, and compressed-suite dictionary binding are authenticated.

- Use protected, uniformly random 32-byte keys; passwords are not keys.
- Do not compress secrets mixed with attacker-controlled bytes.
- Bound untrusted encrypted input before opening it; `max_output_size` bounds
  recovered plaintext only.
- Rate-limit failed opens, count seals per key, and rotate keys to an applicable
  AES-GCM-SIV usage profile.

Key distribution, storage, rotation, input streaming, and rate limiting remain
application responsibilities.

## API

`seal(data, key, *, dict_obj=None, aad=b"", compress=True, level=3)` creates an
envelope.

```python
open_data(blob, key, *, dict_obj=None, aad=b"", max_output_size=64 * 1024 * 1024)
```

authenticates and opens one. `train_dict`, `save_dict`, and `load_dict` manage
optional Zstandard dictionaries; dictionary bytes are non-secret but must match
when opening compressed data.

## Development

```bash
uv sync --locked --extra dev
uv run pre-commit run --all-files
uv run pytest -q
uv build --no-sources
uv publish --dry-run --trusted-publishing never dist/*
```
