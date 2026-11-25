import random
import time

from cryptography.exceptions import InvalidTag
import zstandard as zstd

from kransx import open_data, seal, train_dict

_KEY = bytes(range(32))
_DICT = train_dict([f"record:{index}:compressed payload".encode() for index in range(200)], 2_048)
_LIMITS = (1, 64, 4096, 64 * 1024, 64 * 1024 * 1024)


def _mutate(blob: bytes, rng: random.Random) -> bytes:
    if not blob:
        return rng.randbytes(rng.randrange(1, 32))
    position = rng.randrange(len(blob))
    operation = rng.randrange(4)
    if operation == 0:
        changed = bytes([blob[position] ^ (1 << rng.randrange(8))])
        return blob[:position] + changed + blob[position + 1 :]
    if operation == 1:
        return blob[:position]
    if operation == 2:
        return blob[:position] + rng.randbytes(1) + blob[position:]
    return blob + rng.randbytes(rng.randrange(1, 16))


def _assert_safe_open(
    blob: bytes, key: bytes, dict_obj: zstd.ZstdCompressionDict | None, aad: bytes, limit: int
) -> None:
    started = time.monotonic()
    try:
        opened = open_data(blob, key, dict_obj=dict_obj, aad=aad, max_output_size=limit)
    except (InvalidTag, ValueError):
        return
    assert len(opened) <= limit
    assert time.monotonic() - started < 2.0


def test_deterministic_fuzz() -> None:
    rng = random.Random(0x4B52414E53)
    for _ in range(600):
        key = _KEY if rng.random() < 0.8 else rng.randbytes(32)
        aad = rng.randbytes(rng.randrange(32))
        limit = rng.choice(_LIMITS)
        dict_obj = _DICT if rng.random() < 0.5 else None
        if rng.random() < 0.4:
            blob = rng.randbytes(rng.randrange(4096))
        else:
            if rng.random() < 0.5:
                data = b"A" * rng.randrange(4096)
            else:
                data = rng.randbytes(rng.randrange(4096))
            blob = seal(
                data,
                _KEY,
                dict_obj=dict_obj,
                aad=aad,
                compress=rng.random() < 0.8,
                level=rng.choice((1, 3, 9, 19)),
            )
            for _ in range(rng.randrange(1, 4)):
                blob = _mutate(blob, rng)
        _assert_safe_open(blob, key, dict_obj, aad, limit)
