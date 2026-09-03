"""Lane B: envelope overhead, latency curve, and failure-mode matrix."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.exceptions import InvalidTag

from kransx import open_data, seal, train_dict

KEY = bytes(range(32))
WRONG_KEY = bytes([x ^ 1 for x in range(32)])
REPEATS = 5


def timed(fn, *args, **kwargs):
    return min(
        (s := time.perf_counter(), fn(*args, **kwargs), time.perf_counter() - s)[2]
        for _ in range(REPEATS)
    )


def expect(exc_types, fn, *args, **kwargs) -> str:
    try:
        fn(*args, **kwargs)
    except exc_types as e:
        return type(e).__name__
    return "NO-RAISE"


def main() -> None:
    rows: list[str] = []
    print("size\traw_len\tenv_len\toverhead\tsuite\tseal_ms\topen_ms")
    rows.append("size\traw_len\tenv_len\toverhead\tsuite\tseal_ms\topen_ms")
    for n in [0, 1, 16, 100, 1024, 10_240, 102_400, 1_048_576]:
        data = os.urandom(n) if n else b""
        env = seal(data, KEY)
        assert open_data(env, KEY) == data
        overhead = len(env) - n
        line = (
            f"{n}\t{n}\t{len(env)}\t{overhead}\t{env[0]:#x}\t"
            f"{timed(seal, data, KEY) * 1000:.3f}\t{timed(open_data, env, KEY) * 1000:.3f}"
        )
        rows.append(line)
        print(line)
    zeros = b"\x00" * 10_240
    env_z = seal(zeros, KEY)
    print(f"zeros_10K\tsuite={env_z[0]:#x}\tenv={len(env_z)}\traw_would_be={10_240 + 29}")
    rows.append(f"zeros_10K\tsuite={env_z[0]:#x}\tenv={len(env_z)}")

    print("tamper\tpos\tresult")
    rows.append("tamper\tpos\tresult")
    env = seal(b"A" * 100, KEY, aad=b"ctx")
    for label, pos in [("suite", 0), ("nonce", 5), ("ct", 20), ("tag", len(env) - 1)]:
        t = bytearray(env)
        t[pos] ^= 1
        r = expect((InvalidTag, ValueError), open_data, bytes(t), KEY, aad=b"ctx")
        rows.append(f"tamper\t{label}@{pos}\t{r}")
        print(f"tamper\t{label}@{pos}\t{r}")

    cases = [
        ("wrong_key", (InvalidTag,), open_data, (env, WRONG_KEY), {"aad": b"ctx"}),
        ("wrong_aad", (InvalidTag,), open_data, (env, KEY), {"aad": b"other"}),
        ("trunc_28", (ValueError,), open_data, (env[:28], KEY), {"aad": b"ctx"}),
        ("trunc_29", (InvalidTag, ValueError), open_data, (env[:29], KEY), {"aad": b"ctx"}),
        ("bad_suite", (ValueError,), open_data, (b"\x99" + env[1:], KEY), {"aad": b"ctx"}),
    ]
    blob100 = seal(os.urandom(100), KEY)
    cases.append(("raw_over_cap", (ValueError,), open_data, (blob100, KEY), {"max_output_size": 9}))
    samples = [b'{"user":1,"action":"login"}'] * 300
    d_good = train_dict(samples)
    d_bad = train_dict([b"totally different bytes xyz " * 4] * 300)
    blob = seal(b'{"user":1,"action":"login"}', KEY, dict_obj=d_good)
    cases.append(("wrong_dict", (InvalidTag,), open_data, (blob, KEY), {"dict_obj": d_bad}))
    print("case\tresult")
    rows.append("case\tresult")
    for name, excs, fn, args, kwargs in cases:
        r = expect(excs, fn, *args, **kwargs)
        rows.append(f"{name}\t{r}")
        print(f"{name}\t{r}")
    out = Path(__file__).resolve().parent / "results_b.tsv"
    out.write_text("\n".join(rows) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
