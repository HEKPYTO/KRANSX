# Benchmark gates

Three claim gates guard the published behavior:

| Gate | Script | Command |
|---|---|---|
| A: sealed size never exceeds the best single codec plus 29 bytes | `bench_a.py` | `uv run kransx bench` |
| B: overhead, tamper matrix, failure modes | `bench_b.py` | `uv run kransx bench` |
| C1: dictionary benefit and round trips | `bench_claim_c1_dict.py` | `uv run python bench/bench_claim_c1_dict.py` |

Each gate exits non-zero when its claim fails. Result snapshots (`results_*.tsv`) are deterministic: timings print to stdout only. Regenerate the snapshots after any change under `kransx/`; `results_a.tsv` embeds source bytes in its `code_py` corpus.
