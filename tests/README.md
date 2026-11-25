# Tests

Run everything with:

```bash
uv run pytest -q
```

| File | Covers |
|---|---|
| `test_kransx.py` | conformance vectors, CLI behavior, file modes, limits, tamper coverage |
| `test_v02.py` | v0.2 codec tournament, LZMA and Zstandard failure paths, v0.1 vector compatibility |
| `test_properties.py` | Hypothesis round-trip, overhead, and tamper properties |
| `test_fuzz.py` | deterministic fixed-seed mutation fuzzing |
| `test_compat.py` | public API under the minimum supported dependency versions |

The compatibility file is also run in CI with `cryptography==42.0.0` and `zstandard==0.22.0`.
