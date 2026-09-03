"""C1 DICT-JSON deciding bench (KRANS-X v0.3 SOTA claim C1).

Decision: sum(len(seal(rec, KEY, dict=D))) <= 0.85 * sum(len(zstd19(rec)) + 29)
over 5,000 seeded JSON log records sealed individually, with all-5000
round-trips under D and InvalidTag on wrong-dict opens.

Usage: uv run python bench/bench_claim_c1_dict.py (cwd = repo root)
"""

from __future__ import annotations

import bz2
import hashlib
import json
import lzma
import platform
import random
import sys
import time
from pathlib import Path

import zstandard as zstd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.exceptions import InvalidTag  # noqa: E402

import cryptography  # noqa: E402

from kransx import __version__ as KRANSX_VERSION  # noqa: E402
from kransx import open_data, seal, train_dict  # noqa: E402

SEED = 20260903
N_RECORDS = 5000
N_TRAIN = 500
DICT_SIZE = 16384
GATE = 0.85
KEY = bytes(range(32))
AAD = b""
REPEATS = 5
WRONG_DICT_SAMPLE = 50

CORPUS_SHA256 = "30bbc402967a24d57db7915041d4da8ac49fc58f9d969a4edb4443c11def8d95"

PINNED_ZSTANDARD = "0.25.0"
PINNED_ZSTD_VERSION = (1, 5, 7)
PINNED_CRYPTOGRAPHY = "50.0.1"
PINNED_KRANSX = "0.2.0"


def generate_corpus() -> list[bytes]:
    rng = random.Random(SEED)
    users = [f"user{i:04d}" for i in range(200)]
    actions = ["login", "logout", "read", "write", "share", "delete"]
    recs = []
    for i in range(N_RECORDS):
        recs.append(json.dumps({"user": rng.choice(users), "action": rng.choice(actions),
            "ok": rng.random() < 0.97, "ts": f"2026-09-03T00:{i//60:02d}:{i%60:02d}Z",
            "req": f"{rng.getrandbits(32):08x}"}, separators=(",", ":")).encode() + b"\n")
    return recs


def timed(fn, *args):
    best = REPEATS * [0.0]
    for i in range(REPEATS):
        start = time.perf_counter()
        fn(*args)
        best[i] = time.perf_counter() - start
    return min(best)


def main() -> None:
    print(f"kransx={KRANSX_VERSION} python={sys.version}")
    print(f"zstandard={zstd.__version__} ZSTD_VERSION={zstd.ZSTD_VERSION}")
    print(f"cryptography={cryptography.__version__} machine={platform.machine()}")
    print(f"key=bytes(range(32)) aad={AAD!r} seed={SEED} n={N_RECORDS} "
          f"train={N_TRAIN} dict_size={DICT_SIZE}")

    versions_ok = (
        zstd.__version__ == PINNED_ZSTANDARD
        and tuple(zstd.ZSTD_VERSION) == tuple(PINNED_ZSTD_VERSION)
        and cryptography.__version__ == PINNED_CRYPTOGRAPHY
        and KRANSX_VERSION == PINNED_KRANSX
    )
    if not versions_ok:
        print("VERSION-MISMATCH")
        sys.exit(2)

    recs = generate_corpus()
    digest = hashlib.sha256(b"".join(recs)).hexdigest()
    print(f"corpus_sha256={digest} expected={CORPUS_SHA256}")
    if digest != CORPUS_SHA256 or len(recs) != N_RECORDS:
        print("CORPUS-MISMATCH")
        sys.exit(2)

    dict_obj = train_dict(recs[:N_TRAIN], dict_size=DICT_SIZE)

    c19 = zstd.ZstdCompressor(level=19)
    b1_lens = [len(c19.compress(r)) for r in recs]
    s_base = sum(n + 29 for n in b1_lens)

    sealed = [seal(r, KEY, dict_obj=dict_obj) for r in recs]
    s_kransx = sum(len(e) for e in sealed)
    ratio = s_kransx / s_base

    # Context-only baselines (do not decide the claim).
    lzma_sum = sum(len(lzma.compress(r, preset=6)) for r in recs)
    bz2_sum = sum(len(bz2.compress(r)) for r in recs)
    raw_sum = sum(len(r) for r in recs)
    print(f"raw_sum={raw_sum} b1_sum={sum(b1_lens)} lzma_sum={lzma_sum} bz2_sum={bz2_sum}")
    print(f"s_kransx={s_kransx} s_base={s_base} ratio={ratio:.4f} gate={GATE}")

    roundtrips_ok = True
    for env, rec in zip(sealed, recs, strict=True):
        if open_data(env, KEY, dict_obj=dict_obj) != rec:
            roundtrips_ok = False
            break
    print(f"roundtrips_all_5000={'ok' if roundtrips_ok else 'FAIL'}")

    # Mismatched dictionary must fail closed with InvalidTag.
    rng_w = random.Random(0xC1A1D)
    wrong_samples = [bytes(rng_w.randrange(256) for _ in range(100)) for _ in range(500)]
    wrong_dict = train_dict(wrong_samples, dict_size=DICT_SIZE)
    dicts_differ = dict_obj.as_bytes() != wrong_dict.as_bytes()
    wrong_ok = dicts_differ
    if wrong_ok:
        step = N_RECORDS // WRONG_DICT_SAMPLE
        for env in sealed[::step][:WRONG_DICT_SAMPLE]:
            try:
                open_data(env, KEY, dict_obj=wrong_dict)
                wrong_ok = False
                break
            except InvalidTag:
                pass
    print(f"wrong_dict={'ok' if wrong_ok else 'FAIL'} "
          f"(dicts_differ={dicts_differ}, checked={WRONG_DICT_SAMPLE})")

    # Latency side-column (informational only): min-of-5 over 100-record sample.
    sample = recs[:100]
    sample_sealed = sealed[:100]
    t_seal = timed(lambda: [seal(r, KEY, dict_obj=dict_obj) for r in sample]) * 1000
    t_open = timed(lambda: [open_data(e, KEY, dict_obj=dict_obj) for e in sample_sealed]) * 1000
    print(f"latency_100rec seal_ms={t_seal:.2f} open_ms={t_open:.2f} (min-of-5, informational)")

    out = Path(__file__).resolve().parent / "results_c1.tsv"
    header = ("n\ttrain\tdict_size\traw_sum\tb1_sum\tlzma_sum\tbz2_sum\ts_kransx\ts_base"
              "\tratio\tgate\troundtrips\twrong_dict\tseal_ms_100\topen_ms_100")
    row = (f"{N_RECORDS}\t{N_TRAIN}\t{DICT_SIZE}\t{raw_sum}\t{sum(b1_lens)}\t{lzma_sum}\t"
           f"{bz2_sum}\t{s_kransx}\t{s_base}\t{ratio:.4f}\t{GATE}\t"
           f"{'ok' if roundtrips_ok else 'FAIL'}\t{'ok' if wrong_ok else 'FAIL'}\t"
           f"{t_seal:.2f}\t{t_open:.2f}")
    versions_line = (f"# kransx={KRANSX_VERSION} python={sys.version} "
                     f"zstandard={zstd.__version__} ZSTD_VERSION={zstd.ZSTD_VERSION} "
                     f"cryptography={cryptography.__version__} machine={platform.machine()} "
                     f"corpus_sha256={CORPUS_SHA256}")
    out.write_text(versions_line + "\n" + header + "\n" + row + "\n")
    print(f"wrote {out}")

    if ratio <= GATE and roundtrips_ok and wrong_ok:
        print(f"CLAIM-C1-HOLDS ratio={ratio:.4f}")
    else:
        print(f"CLAIM-C1-BROKEN ratio={ratio:.4f} "
              f"roundtrips={'ok' if roundtrips_ok else 'FAIL'} "
              f"wrong_dict={'ok' if wrong_ok else 'FAIL'}")
        sys.exit(1)


if __name__ == "__main__":
    main()
