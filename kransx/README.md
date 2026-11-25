# KRANSX envelope specification v0.2

This document is the deep-module contract for `kransx`. It freezes the v0.2 wire format, the limits, and the threat model. The root [README](../README.md) holds the quickstart, measured claims, and release notes; this file holds the details a caller needs to reason about safety. Statements below describe the code in `kransx/core.py`, `kransx/cli.py`, and `kransx/dicts.py`, not an aspiration.

Module ownership:

| Module | Owns |
|---|---|
| `kransx.core` | `seal`, `open_data`: envelope construction, codec tournament, AEAD, limits |
| `kransx.dicts` | `train_dict`, `save_dict`, `load_dict`: shared Zstandard dictionaries |
| `kransx.cli` | `seal`, `open`, `train`, `keygen`, `bench` subcommands; no separate crypto |

The library owns the envelope only. Callers own keys, file paths, input byte caps, and application-level separation of secrets from attacker-controlled data.

## Wire format

Every envelope is:

```
suite (1 byte) || nonce (12 bytes) || ciphertext (payload length) || tag (16 bytes)
```

`cryptography`'s `AESGCMSIV.encrypt` appends the 16-byte tag to the ciphertext. Fixed overhead is `1 + 12 + 16 = 29` bytes, independent of payload and suite. An empty raw envelope is 29 bytes; a 15-byte raw payload yields a 44-byte envelope.

| Suite byte | Payload | Authentication data (AAD) |
|---|---|---|
| `0x21` | one ordinary Zstandard frame, optional dictionary | `suite || dict_binding || aad` |
| `0x22` | raw bytes | `suite || aad` |
| `0x23` | LZMA/XZ stream, preset 6 | `suite || none_binding || aad` |

The suite byte is itself authenticated: it is the first byte of every AAD construction. Unknown suite bytes raise `ValueError`; re-labelling a valid envelope with another valid suite byte fails authentication.

### Suite selection

`seal(data, key, compress=True, level=3)` starts with raw as the incumbent (`0x22`). When `compress=True`, the tournament tries, in order:

1. Zstandard at the caller's `level` (default `3`), with the supplied dictionary if any;
2. Zstandard at level `19`, with the same dictionary (skipped when `level == 19`, since it would duplicate step 1);
3. LZMA at preset `6`, never with a dictionary.

A candidate replaces the incumbent **only when strictly shorter**. Raw therefore wins every tie, and incompressible input grows by exactly the 29-byte floor. `compress=False` skips the tournament and forces `0x22`. The resulting envelope is never longer than the best single codec plus 29 bytes; this is checked by the `kransx bench` claim gate.

## Key derivation and nonce

- Caller-supplied key: exactly 32 bytes. Non-bytes raise `TypeError`; any other length raises `ValueError`.
- AEAD key: `HKDF-SHA256(length=32, salt=None, info=b"kransx/v0.1/aead/aes-256-gcm-siv")` applied to the caller key. The info string is a frozen wire constant; the `v0.1` label is an identifier kept for compatibility, not a negotiation knob.
- Nonce: fresh `os.urandom(12)` per `seal` call. The nonce is stored in the clear in the envelope. AES-GCM-SIV is misuse-resistant, but nonces must still not be deliberately reused.
- Key generation is not part of the library. The CLI `keygen` subcommand writes 32 `os.urandom` bytes.

## Associated data and dictionary binding

`aad` is caller-supplied bytes, appended verbatim after the suite byte and, for compressed suites, the 32-byte binding. The CLI accepts `--aad` as hex-encoded bytes.

| Case | Binding |
|---|---|
| `0x21` with dictionary | `SHA-256(b"kransx/v0.1/zstd-dictionary/" || b"bytes\x00" || dict.as_bytes())` |
| `0x21` without dictionary | `none_binding` |
| `0x23` (always) | `none_binding` |
| `0x22` (raw) | no binding field at all |

`none_binding = SHA-256(b"kransx/v0.1/zstd-dictionary/none")`. Dictionaries are public compression aids, not secrets, but they are bound: a missing, different, or substituted dictionary makes authentication fail before decompression. LZMA never uses a dictionary, so `--dict` has no effect on a `0x23` envelope; its AAD always carries `none_binding`.

## Limits and validation

`open_data(blob, key, ..., max_output_size=64 * 1024 * 1024)` enforces the following. All size values are bytes. A `ValueError` is raised for every structural or limit violation below.

| Control | Rule | Source |
|---|---|---|
| Envelope minimum | `len(blob) >= 29`, else `ValueError` | `core.open_data` |
| Maximum output (default) | `67,108,864` (64 MiB); must be a positive `int`, else `TypeError`/`ValueError` | `core.open_data`, CLI `--max-output-size` |
| Raw pre-AEAD cap | `len(blob) - 29 > max_output_size` → `ValueError` before the AEAD object is constructed | `core.open_data` |
| Zstandard frame shape | payload must start with `b"\x28\xb5\x2f\xfd"`; skippable frames and trailing bytes rejected | `core._decompress` |
| Zstandard advertised size | known content size above `max_output_size` → `ValueError` before decompression | `core._decompress` |
| Zstandard window bound | `max_window_size = min(1 << 31, max(1024, ceil(limit / 1024) * 1024))`; cap is `2,147,483,648` (2 GiB), default bound is `67,108,864` | `core._decompress` |
| Zstandard output cap | `decompress(..., max_output_size=limit, allow_extra_data=False)` | `core._decompress` |
| LZMA memory limit | `memlimit = max(16,777,216, limit + 1,048,576)`; floor 16 MiB, default `68,157,440` (65 MiB) | `core._decompress_lzma` |
| LZMA streaming cap | feed at most `65,536` bytes per chunk; `max_length = limit - len(out) + 1`; output above limit, truncation, or trailing bytes → `ValueError` | `core._decompress_lzma` |
| CLI encrypted-input cap | `max_output_size + 29 + 1,048,576`; default `68,157,469`; one byte more → `ValueError` | `cli._read_bounded`, `cli._open` |
| CLI plaintext-input cap | `--max-input-size`; default `67,108,864`; must be positive; one byte more → `ValueError` | `cli._read_bounded`, `cli._seal` |

`open_data` does not cap the encrypted input supplied by a library caller. Only the CLI does. A library caller facing untrusted bytes must impose its own input cap; the CLI formula is the reference choice.
The `seal` CLI reads at most `--max-input-size` bytes and rejects a non-positive value or an oversized input before writing output.

A compressed envelope is allowed to be larger than `max_output_size`: the cap applies to recovered plaintext, not to ciphertext. A Zstandard frame with unknown advertised size is still decompressed under the output and window bounds.

### Error behavior

| Condition | Result |
|---|---|
| Short blob, unknown suite, bad key length, non-private key file on POSIX, non-positive cap, oversized raw data, malformed frame, oversized or trailing decompressed data | `ValueError` |
| Wrong key, wrong AAD, wrong dictionary, any bit flip in suite/nonce/ciphertext/tag | `InvalidTag` (`cryptography.exceptions.InvalidTag`) |
| Wrong argument type (e.g. `str` where `bytes` expected) | `TypeError` |

`InvalidTag` is raised before any decompression or plaintext output. The CLI catches `InvalidTag`, `OSError`, `ValueError`, `OverflowError`, and `zstd.ZstdError` and reports them via `argparse` `parser.error`, which exits with status `2` and no traceback. A numeric option too large for the host raises `OverflowError` and takes the same path.

## Threat model

### Attacker without the key

- Confidentiality and integrity come from AES-256-GCM-SIV with a 32-byte derived key. Suite byte, nonce, AAD, and dictionary binding are all covered by authentication; any modification within an assigned suite fails with `InvalidTag`.
- Authentication gives no distinguishing oracle on the plaintext: wrong key, wrong AAD, wrong dictionary, and tampering within an assigned suite all fail with `InvalidTag` before any plaintext is released. Tampering that produces an unknown suite byte fails earlier with `ValueError`. GCM-SIV limits the damage of accidental nonce reuse.
- Unauthenticated denial of service is bounded, not eliminated. An attacker can spend caller CPU on authentication. Memory and output work are bounded by `max_output_size` and the caps above, but the **library does not bound ciphertext size**; the CLI bounds it at `max_output_size + 29 + 1 MiB`. Callers accepting untrusted envelopes must set an equivalent input cap.
- Suite choice and envelope length remain visible. Hiding them is a non-goal.

### Attacker with the key

- A key holder can construct valid envelopes, so the envelope provides no non-repudiation and no integrity against a key holder.
- Decompression memory is still bounded: Zstandard uses the advertised-size check, the `max_window_size` cap, and the output cap; LZMA uses `memlimit` and the streaming output cap. These bounds cover hostile compressed data even when the attacker knows the key.
- The bounds apply to the envelope layer, not to what the caller does with recovered plaintext.

### Local multi-user

- CLI `open` writes plaintext with `0600`, using `os.open(..., O_CREAT | O_EXCL, 0o600)`; it never overwrites an existing path.
- CLI `keygen` writes a fresh key with `0600` and `O_EXCL`.
- **Key-file mode is enforced on POSIX.** `_key` calls `stat()` and rejects any `st_mode & 0o077` bit before reading, so a 32-byte world-readable key file is refused with `ValueError("key file must be private (0600)")`; Windows keeps the length-only check. Keys made outside `keygen` must be `0600` to be usable.
- Sealed output (`seal`) and trained dictionaries (`train`) are written with the default `0644` mode (subject to the process umask). They are not secret material. Plaintext and keys are the confidential artifacts.

### Guarantees and non-goals

Guarantees: compress-then-encrypt with a strictly-smallest codec tournament and raw-wins-ties; authentication before decompression; fixed 29-byte overhead; 32-byte fresh nonces; explicit output, window, and memory caps; no plaintext on authentication failure.

Non-goals: key generation in the library, key distribution and rotation, hiding lengths or suite choice (traffic analysis), constant-time or side-channel-resistant implementation claims, FIPS validation, protection from compression oracles when secrets are mixed with attacker-controlled input (use `compress=False` or separate plaintext domains), and defense against a malicious dependency or a compromised host. This is a reference implementation with conformance vectors and tamper coverage, not an externally audited product.

## Versioning and migration policy

- `SPEC_VERSION = "0.2"` in `kransx/__init__.py` names this document. The package release version is separate (`__version__ = "0.3.0"`).
- Suite bytes `0x21`, `0x22`, and `0x23` are frozen. Never repurpose a byte or change the meaning of an existing suite.
- The v0.2 wire format accepts the v0.1 conformance vectors unchanged; the `v0.1` strings in HKDF info and dictionary binding are frozen identifiers retained for that reason.
- Any breaking wire change requires a new suite byte and a spec version bump. Old suites remain readable by the new version.
- This project is pre-1.0: the Python API may change across releases. Breaking API changes are recorded as release notes in the root [README](../README.md).
- No compatibility shims: no aliases, legacy flag branches, or silent rewrites of old envelopes. Migration is explicit at the caller boundary.

## Operational limits

| Category | Value | Enforced by |
|---|---|---|
| Envelope overhead | 29 bytes (1 + 12 nonce + 16 tag) | `core.seal`, `core.open_data` |
| Key size / AEAD key size | 32 / 32 bytes | `core._validate_key`, `core._aead_key` |
| Nonce / tag / binding size | 12 / 16 / 32 bytes | `core.seal`, `AESGCMSIV`, `core._compressed_aad` |
| Default plaintext output cap | 64 MiB (67,108,864 bytes) | `core.open_data`, CLI `--max-output-size` |
| CLI encrypted input cap | cap + 29 + 1 MiB; 68,157,469 bytes at default | `cli._read_bounded` |
| CLI plaintext-input cap | `--max-input-size`; 64 MiB (67,108,864 bytes) at default | `cli._read_bounded`, `cli._seal` |
| Zstandard window ceiling | 2 GiB (2,147,483,648 bytes); default bound 64 MiB | `core._decompress` |
| LZMA memory floor / default | 16 MiB / 65 MiB (68,157,440 bytes) | `core._decompress_lzma` |
| LZMA feed chunk | 65,536 bytes | `core._decompress_lzma` |
| Default Zstandard level / trained dictionary size | 3 / 16,384 bytes | `core.seal`, `cli._parser`, `dicts.train_dict` |
| CLI key file | exactly 32 bytes; POSIX mode must be `0600` (`st_mode & 0o077` rejected) | `cli._key` |
| CLI plaintext output mode | `0600`, `O_EXCL` | `cli._open` |
| CLI keygen mode | `0600`, `O_EXCL` | `cli._keygen` |
| CLI sealed output / dictionary mode | `0644` before umask, `O_EXCL` | `cli._write_new` |

## Verification performed

Each numeric claim above was checked against the implementation and, where noted, a test or a runtime computation:

| Claim | Verification performed |
|---|---|
| 29-byte overhead; 12-byte nonce; 16-byte tag | Read `core.py` constants and construction. Runtime: `_FIXED_OVERHEAD == 29`; `AESGCMSIV(…).encrypt(nonce, b"", b"")` length `16`; `seal(b"raw conformance", key, compress=False)` length `44`. Tests: `test_truncation_boundaries_fail`, `test_raw_conformance_vector`, `test_every_envelope_region_is_authenticated`. |
| 32-byte key and 32-byte derived AEAD key | Read `core._validate_key` and `core._aead_key`. Runtime: `len(_aead_key(key)) == 32`. Tests: `test_validation_and_unknown_suite`, `test_wrong_key_aad_and_dictionary_fail_authentication`. |
| 32-byte dictionary binding | Read `core._compressed_aad`. Runtime: `len(_NO_DICT_BINDING) == 32`; prefix read back as `kransx/v0.1/zstd-dictionary/`. Tests: `test_raw_content_dictionary_substitution_fails_authentication`, `test_cli_key_file_round_trip_and_expected_errors` (wrong key fails auth). |
| 64 MiB default output cap | Read `core.open_data` signature and CLI `--max-output-size` default; runtime evaluation gives `67,108,864`. Tests: `test_decompression_limits_known_and_unknown_size_frames`, `test_large_zstd_output_limit_is_accepted`. |
| Raw cap checked before AEAD | Read pre-AEAD branch in `core.open_data`. Test: `test_raw_size_is_rejected_before_decryption` replaces `AESGCMSIV` with a class that asserts it must not be constructed. |
| Zstandard advertised size, window bound, 2 GiB ceiling | Read `core._decompress` formula; runtime: ceiling `2,147,483,648`, default bound `67,108,864` (64 MiB). Tests: `test_decompression_limits_known_and_unknown_size_frames`, `test_zstd_window_limit_rejects_oversized_frame_window`, `test_large_zstd_output_limit_is_accepted`. |
| LZMA 16 MiB floor, default 65 MiB, 64 KiB chunks | Read `core._decompress_lzma`; runtime: floor `16,777,216`, default `68,157,440`. Tests: `test_lzma_memlimit_bounds_declared_dict`, `test_lzma_bomb_truncation_and_trailing_rejected`, `test_lzma_cross_chunk_trailing_rejected`. |
| CLI input cap `cap + 29 + 1 MiB` | Read `cli._open` and `cli._read_bounded`; runtime at default: `68,157,469`. Test: `test_cli_rejects_input_larger_than_output_limit` (2 MiB input with `--max-output-size 1024` exits 2, no output file). |
| CLI plaintext input cap `--max-input-size` | Read `cli._seal` and `cli._read_bounded`; default `67,108,864`, non-positive rejected. Tests: `test_cli_rejects_input_larger_than_max_input_size` (65-byte input with `--max-input-size 64` exits 2, no output; limit `0` exits 2). |
| CLI `0600` plaintext and key, `0644` sealed output | Read `cli._write_new`, `cli._open`, `cli._keygen`, and the POSIX `st_mode & 0o077` check in `cli._key`. Tests: `test_cli_output_modes`, `test_cli_key_file_round_trip_and_expected_errors`, `test_cli_rejects_world_readable_key` (0644 key exits 2, no output). |
| Codec tournament and suite bytes | Read `core.seal` candidate loop and `_SUITES`. Tests: `test_tournament_never_exceeds_best_single_plus_overhead`, `test_seal_selects_lzma_when_zstd_expands`, `test_suite_flip_to_other_valid_suite_fails`, `test_v01_vectors_still_open`. |
| CLI exit 2 mapping | Read `cli.main` exception handlers, including `OverflowError`. Tests: `test_cli_key_file_round_trip_and_expected_errors`, `test_cli_rejects_input_larger_than_output_limit`, `test_cli_rejects_overflowing_output_limit` (`--max-output-size 10**30` exits 2, no traceback). |

The targeted test selection above passed after these controls were added; document-only changes do not alter those behaviors.
