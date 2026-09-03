# KRANSX

[![PyPI](https://img.shields.io/pypi/v/kransx.svg)](https://pypi.org/project/kransx/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

```python
import secrets
from kransx import open_data, seal

key = secrets.token_bytes(32)
sealed = seal(b"hello world", key, aad=b"record-42")
assert open_data(sealed, key, aad=b"record-42") == b"hello world"
```

KRANSX picks the smallest of Zstandard, LZMA-6, and raw for every payload, then encrypts the winner with AES-256-GCM-SIV. Fixed cost: 29 bytes per envelope (1 suite + 12 nonce + 16 tag). Wrong key, wrong associated data, wrong dictionary, or modified bytes fail with `cryptography.exceptions.InvalidTag`. Malformed envelopes fail with `ValueError` before anything decrypts.

## Installation

```bash
pip install kransx
```

Development setup:

```bash
uv sync --locked --extra dev
```

Requires Python 3.10+, `cryptography >= 42`, `zstandard >= 0.22`.

## Measured behavior

Each line below is decided by a checked-in command that exits non-zero when broken.

| Behavior | Evidence | Command |
|---|---|---|
| Sealed output never exceeds the best single codec plus 29 bytes | 8 corpora, worst margin 0 | `kransx bench` |
| Overhead is exactly 29 bytes, empty to 1 MB | 8 sizes, all raw suite | `kransx bench` |
| Small JSON records seal 45% smaller with a trained dictionary | ratio 0.552 vs 0.85 gate, 5,000 records | `uv run python bench/bench_claim_c1_dict.py` |
| Tamper at any envelope offset is rejected | tamper and failure matrix, exact exceptions | `uv run pytest -q` (71 tests) |

## Python API

```python
seal(data: bytes, key: bytes, *, dict_obj=None, aad=b"", compress=True, level=3) -> bytes
open_data(blob: bytes, key: bytes, *, dict_obj=None, aad=b"", max_output_size=64*1024*1024) -> bytes
train_dict(samples: Iterable[bytes], dict_size=16384) -> ZstdCompressionDict
save_dict(dictionary, path) / load_dict(path)
```

`compress=True` runs the tournament and keeps the strictly smallest payload. Raw wins every tie, so incompressible input grows by exactly the 29-byte floor and nothing more. `max_output_size` caps decompressed output. Structural problems raise `ValueError`. Authentication problems raise `InvalidTag` and release no plaintext.

Shared dictionaries are non-secret compression aids for similar payloads:

```python
from kransx import train_dict

dictionary = train_dict([b'{"user":1,"action":"login"}'] * 300)
sealed = seal(b'{"user":1,"action":"login"}', key, dict_obj=dictionary)
assert open_data(sealed, key, dict_obj=dictionary) == b'{"user":1,"action":"login"}'
```

A mismatched dictionary fails authentication before decompression starts.

## CLI

```bash
kransx keygen key.bin
kransx seal plain.bin sealed.bin --key-file key.bin --aad 7265636f72642d3432
kransx open sealed.bin restored.bin --key-file key.bin --aad 7265636f72642d3432

kransx train 'samples/*.json' --output model.dict
kransx seal plain.bin out.bin --key-file key.bin --dict model.dict
kransx open out.bin restored.bin --key-file key.bin --dict model.dict --max-output-size 1048576
kransx bench
```

- `--aad` takes hex-encoded bytes.
- `--max-output-size` caps plaintext size on open.
- Output files are created exclusively and never overwritten.
- `bench` reruns the A+B claim gates and fails non-zero on any regression.

## Design

Envelope layout: `suite (1) | nonce (12) | ciphertext | tag (16)`.

| Suite | Payload | Authenticated associated data |
|-------|---------|-------------------------------|
| `0x21` | Zstandard frame | `suite` + dictionary binding + `aad` |
| `0x22` | raw bytes | `suite` + `aad` |
| `0x23` | LZMA bytes (preset 6) | `suite` + no-dictionary binding + `aad` |

The dictionary binding is `SHA-256` over the dictionary bytes, or over a fixed constant when no dictionary is used. Keys are 32 random bytes expanded through HKDF-SHA-256 to the AEAD key. Every seal generates a fresh 12-byte nonce. Opening checks size and suite first, authenticates second, and only then decompresses under the output cap: single Zstandard frame or a bounded LZMA stream, trailing bytes rejected either way.

## Security considerations

This library is the envelope only. Key generation, distribution, storage, rotation, and bounding encrypted-input size stay with the caller.

- **Keys** must be 32 uniformly random bytes. Passwords are not valid keys.
- **Nonces** come from `os.urandom(12)` per seal. AES-GCM-SIV tolerates reuse better than most modes, but do not reuse them.
- **Compression oracles.** Sealed size reveals which suite won. Never compress secrets mixed with attacker-controlled input without application-level separation. Pass `compress=False` when in doubt.
- **Resource limits.** `max_output_size` bounds decompressed output. For untrusted input, also cap the encrypted bytes before calling `open_data`.

This is an implementation with conformance vectors and tamper coverage, not an external audit.

## Development

```bash
uv sync --locked --extra dev
uv run ruff check .
uv run mypy kransx
uv run pytest -q
```

Layout: `kransx/` holds seal, open, dicts, cli. `tests/` holds conformance vectors, tamper checks, resource limits. `bench/` holds the claim gates and their result snapshots.

## License

MIT — see [LICENSE](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
