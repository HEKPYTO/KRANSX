# Changelog

## 0.2.1

- Removed an inert decompressor window bound; the one-shot API ignored it.
  Output size stays capped by `max_output_size`.
- `seal(level=19)` no longer compresses the same input twice.

## 0.2.0

- Codec tournament: `seal` tries Zstandard (requested level and 19) plus
  LZMA-6 and keeps the strictly smallest payload; raw wins all ties.
- New `0x23` LZMA suite with bounded decode and trailing-data rejection.
- `bench` CLI subcommand runs the A+B claim gates; new
  `bench/bench_claim_c1_dict.py` decides the C1 dict-JSON claim.
- 29-byte overhead floor and v0.1 wire compatibility unchanged.

## 0.1.0

- Initial envelope: Zstandard-or-raw adaptive seal, AES-256-GCM-SIV,
  HKDF-SHA256 key schedule, dictionary-bound AAD, 29-byte overhead.
