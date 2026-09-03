"""Lane A: kransx compression vs standalone baselines on fixed corpora."""

from __future__ import annotations

import bz2
import lzma
import random
import sys
import time
from pathlib import Path

import zstandard as zstd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kransx import open_data, seal, train_dict

KEY = bytes(range(32))
REPEATS = 5


def build_corpora() -> list[tuple[str, bytes]]:
    rng = random.Random(42)
    line = b'{"user":123,"action":"login","ok":true,"ts":"2026-09-03T00:00:00Z"}\n'
    json_logs = line * 2000
    sentence = b"The quick brown fox jumps over the lazy dog. "
    sentence += b"Pack my box with five dozen liquor jugs. "
    text = sentence * 3000
    paths = sorted(Path("kransx").glob("*.py"))
    code = b"".join([p.read_bytes() for p in paths])
    code = code * max(1, 200_000 // max(1, len(code)))
    runs = b"\x00" * 50_000 + b"\xff" * 50_000
    rand_small = bytes(rng.randrange(256) for _ in range(200))
    rand_100k = bytes(rng.randrange(256) for _ in range(100_000))
    return [
        ("json_logs", json_logs),
        ("text_rep", text),
        ("code_py", code[:200_000]),
        ("runs_bin", runs),
        ("rand_200B", rand_small),
        ("rand_100K", rand_100k),
        ("tiny_2B", b"hi"),
        ("empty", b""),
    ]


def timed(fn, *args):
    best = REPEATS * [0.0]
    for i in range(REPEATS):
        start = time.perf_counter()
        fn(*args)
        best[i] = time.perf_counter() - start
    return min(best)


def main() -> None:
    dict_obj = train_dict([b'{"user":1,"action":"login"}'] * 300)
    rows: list[str] = []
    header = "corpus\traw\tzstd1\tzstd3\tzstd19\tbz2\tlzma"
    header += "\tkransx\tkransx19\tkransx_dict\tsuite\tk/z19\tbest_single\tk_vs_best"
    rows.append(header)
    print(header)
    holds = True
    for name, data in build_corpora():
        z1 = zstd.ZstdCompressor(level=1).compress(data)
        z3 = zstd.ZstdCompressor(level=3).compress(data)
        z19 = zstd.ZstdCompressor(level=19).compress(data)
        b2 = bz2.compress(data)
        lz = lzma.compress(data)
        k = seal(data, KEY)
        k19 = seal(data, KEY, level=19)
        kd = seal(data, KEY, dict_obj=dict_obj)
        assert open_data(k, KEY) == data
        assert open_data(kd, KEY, dict_obj=dict_obj) == data
        t_seal = timed(seal, data, KEY) * 1000
        t_z19 = timed(zstd.ZstdCompressor(level=19).compress, data) * 1000
        ratio = (len(k) / len(z19)) if z19 else 1.0
        best_single = min(len(z19), len(lz), len(data))
        k_vs_best = len(k) - (best_single + 29)
        holds = holds and k_vs_best <= 0
        line_out = (
            f"{name}\t{len(data)}\t{len(z1)}\t{len(z3)}\t{len(z19)}\t"
            f"{len(b2)}\t{len(lz)}\t{len(k)}\t{len(k19)}\t{len(kd)}\t{k[0]:#x}\t"
            f"{ratio:.3f}\t{best_single}\t{k_vs_best}\tseal_ms={t_seal:.2f}\tz19_ms={t_z19:.2f}"
        )
        rows.append(line_out)
        print(line_out)
    out = Path(__file__).resolve().parent / "results_a.tsv"
    out.write_text("\n".join(rows) + "\n")
    print(f"wrote {out}")
    print("CLAIM-A-HOLDS" if holds else "CLAIM-A-BROKEN")
    if not holds:
        sys.exit(1)


if __name__ == "__main__":
    main()
