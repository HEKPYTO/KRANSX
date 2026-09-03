"""v0.2 codec-tournament tests: guarantee, lzma dispatch, v0.1 compat."""

import hashlib
import lzma

import pytest
import zstandard as zstd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from kransx import open_data, seal
from test_kransx import COMPRESSED_ENVELOPE, COMPRESSED_AAD, COMPRESSED_DATA
from test_kransx import RAW_AAD, RAW_DATA, RAW_ENVELOPE

MASTER_KEY = bytes(range(32))
CORPORA = [
    b'{"user":1,"action":"login"}\n' * 500,
    b"The quick brown fox. " * 2000,
    bytes(range(256)) * 400,
    b"\x00" * 9000 + b"\xff" * 9000,
    bytes((i * 37) % 256 for i in range(30_000)),
]


def _aead_key() -> bytes:
    return HKDF(hashes.SHA256(), 32, None, b"kransx/v0.1/aead/aes-256-gcm-siv").derive(MASTER_KEY)


def _lzma_envelope(payload: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    binding = hashlib.sha256(b"kransx/v0.1/zstd-dictionary/" + b"none").digest()
    ct = AESGCMSIV(_aead_key()).encrypt(nonce, payload, bytes([0x23]) + binding + aad)
    return b"\x23" + nonce + ct


def test_tournament_never_exceeds_best_single_plus_overhead() -> None:
    for data in CORPORA:
        env = seal(data, MASTER_KEY)
        best = min(
            len(zstd.ZstdCompressor(level=19).compress(data)),
            len(lzma.compress(data, preset=6)),
            len(data),
        )
        assert len(env) <= best + 29
        assert open_data(env, MASTER_KEY) == data


def test_seal_selects_lzma_when_zstd_expands(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExpandingCompressor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def compress(self, data: bytes) -> bytes:
            return data + b"\x00"

    monkeypatch.setattr("kransx.core.zstd.ZstdCompressor", ExpandingCompressor)
    data = b"\x00" * 1000
    env = seal(data, MASTER_KEY)
    assert env[0] == 0x23
    assert open_data(env, MASTER_KEY) == data


def test_lzma_envelope_round_trip() -> None:
    payload = lzma.compress(b"lzma conformance payload " * 40, preset=6)
    env = _lzma_envelope(payload, bytes.fromhex("aabbcceedd11223344556677"))
    assert open_data(env, MASTER_KEY) == b"lzma conformance payload " * 40


def test_lzma_bomb_truncation_and_trailing_rejected() -> None:
    big = lzma.compress(b"\x00" * 1_000_000, preset=6)
    nonce = bytes.fromhex("00112233445566778899aabb")
    env = _lzma_envelope(big, nonce)
    with pytest.raises(ValueError, match="max_output_size"):
        open_data(env, MASTER_KEY, max_output_size=1000)
    with pytest.raises(ValueError):
        open_data(_lzma_envelope(big + b"junk", nonce), MASTER_KEY)
    with pytest.raises(ValueError):
        open_data(_lzma_envelope(big[:10], nonce), MASTER_KEY)


def test_lzma_cross_chunk_trailing_rejected() -> None:
    import random
    rng = random.Random(7)
    payload = lzma.compress(bytes(rng.randrange(256) for _ in range(200_000)), preset=6)
    assert len(payload) > 65536
    nonce = bytes.fromhex("ffeeddccbbaa998877665544")
    env = _lzma_envelope(payload + b"junk-after-boundary", nonce)
    with pytest.raises(ValueError, match="trailing"):
        open_data(env, MASTER_KEY)


def test_suite_flip_to_other_valid_suite_fails() -> None:
    import random
    rng = random.Random(0xBEAC)
    data = bytes(rng.randrange(256) for _ in range(100))
    env = bytearray(seal(data, MASTER_KEY))
    assert env[0] == 0x22
    env[0] ^= 0x01
    assert env[0] == 0x23
    with pytest.raises(InvalidTag):
        open_data(bytes(env), MASTER_KEY)


def test_lzma_tamper_fails_authentication() -> None:
    payload = lzma.compress(b"tamper me " * 100, preset=6)
    env = bytearray(_lzma_envelope(payload, bytes.fromhex("102132435465768798a9bacb")))
    env[20] ^= 1
    with pytest.raises(InvalidTag):
        open_data(bytes(env), MASTER_KEY)


def test_v01_vectors_still_open() -> None:
    assert open_data(RAW_ENVELOPE, MASTER_KEY, aad=RAW_AAD) == RAW_DATA
    assert open_data(COMPRESSED_ENVELOPE, MASTER_KEY, aad=COMPRESSED_AAD) == COMPRESSED_DATA
