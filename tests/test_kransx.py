import os
import subprocess
import sys
from pathlib import Path

import pytest
import zstandard as zstd
from cryptography.exceptions import InvalidTag

import kransx.core as core
from kransx import load_dict, open_data, save_dict, seal, train_dict


MASTER_KEY = bytes(range(32))
RAW_DATA = b"raw conformance"
RAW_AAD = b"context/raw"
RAW_ENVELOPE = bytes.fromhex(
    "22000102030405060708090a0b2713d344ba60e715b1ba535c474736a1dea83de5477abfb43c9279028f2ecc"
)
COMPRESSED_DATA = b"KRANS-X compressed conformance payload.\n" * 12
COMPRESSED_AAD = b"context/compressed"
COMPRESSED_ENVELOPE = bytes.fromhex(
    "21f0f1f2f3f4f5f6f7f8f9fafb92b8e0e2b9e90d7542e553cd2fa9a999cde676f96f0878097cb71fdebe05d19ee7561c6d1fc2bd6f7f61ac1184a49abd6d6c85fa522132cddb3f0b2287be72d50214ee6ebcfd853fcdcaba"
)
UNKNOWN_SIZE_COMPRESSED_ENVELOPE = bytes.fromhex(
    "2100112233445566778899aabbe311494f3b244bb769c9838c91ab7cfd2e4c57d82389a345f2336ab42cc201ca273c"
)
_REFERENCE_ZSTD = ("0.25.0", (1, 5, 7))


def _authenticated_compressed_payload(payload: bytes) -> bytes:
    nonce, aad = bytes.fromhex("102132435465768798a9bacb"), b"trailing-frame"
    ciphertext = core.AESGCMSIV(core._aead_key(MASTER_KEY)).encrypt(
        nonce, payload, core._compressed_aad(0x21, aad, None)
    )
    return b"\x21" + nonce + ciphertext


def _skippable_frame(data: bytes = b"") -> bytes:
    return b"\x50\x2a\x4d\x18" + len(data).to_bytes(4, "little") + data


def test_raw_conformance_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixed nonces are test-only and document the construction."""
    monkeypatch.setattr("kransx.core.os.urandom", lambda size: bytes(range(12)))
    assert seal(RAW_DATA, MASTER_KEY, aad=RAW_AAD, compress=False) == RAW_ENVELOPE
    assert open_data(RAW_ENVELOPE, MASTER_KEY, aad=RAW_AAD) == RAW_DATA


def test_compressed_conformance_vector_opens_on_all_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert open_data(COMPRESSED_ENVELOPE, MASTER_KEY, aad=COMPRESSED_AAD) == COMPRESSED_DATA
    if (zstd.__version__, zstd.ZSTD_VERSION) != _REFERENCE_ZSTD:
        return
    monkeypatch.setattr("kransx.core.os.urandom", lambda size: bytes(range(0xF0, 0xFC)))
    assert seal(COMPRESSED_DATA, MASTER_KEY, aad=COMPRESSED_AAD) == COMPRESSED_ENVELOPE


def test_round_trip_for_both_suites() -> None:
    assert RAW_ENVELOPE[0] == 0x22
    assert COMPRESSED_ENVELOPE[0] == 0x21
    assert open_data(RAW_ENVELOPE, MASTER_KEY, aad=RAW_AAD) == RAW_DATA
    assert open_data(COMPRESSED_ENVELOPE, MASTER_KEY, aad=COMPRESSED_AAD) == COMPRESSED_DATA


def test_adaptive_raw_and_forced_raw_round_trip() -> None:
    data = os.urandom(2_048)
    adaptive = seal(data, MASTER_KEY)
    forced = seal(data, MASTER_KEY, compress=False)
    assert adaptive[0] == 0x22
    assert forced[0] == 0x22
    assert open_data(adaptive, MASTER_KEY) == data
    assert open_data(forced, MASTER_KEY) == data


@pytest.mark.parametrize("region", [0, 1, 13, -1])
def test_every_envelope_region_is_authenticated(region: int) -> None:
    tampered = bytearray(COMPRESSED_ENVELOPE)
    if region == 0:
        tampered[region] = 0x22
    else:
        tampered[region] ^= 1
    with pytest.raises(InvalidTag):
        open_data(bytes(tampered), MASTER_KEY, aad=COMPRESSED_AAD)


@pytest.mark.parametrize("size", range(len(RAW_ENVELOPE)))
def test_truncation_boundaries_fail(size: int) -> None:
    expected_error = ValueError if size < 29 else InvalidTag
    with pytest.raises(expected_error):
        open_data(RAW_ENVELOPE[:size], MASTER_KEY, aad=RAW_AAD)


def test_wrong_key_aad_and_dictionary_fail_authentication() -> None:
    with pytest.raises(InvalidTag):
        open_data(COMPRESSED_ENVELOPE, bytes(reversed(MASTER_KEY)), aad=COMPRESSED_AAD)
    with pytest.raises(InvalidTag):
        open_data(COMPRESSED_ENVELOPE, MASTER_KEY, aad=b"other")
    wrong_dict = zstd.ZstdCompressionDict(
        b"different dictionary", dict_type=zstd.DICT_TYPE_RAWCONTENT
    )
    with pytest.raises(InvalidTag):
        open_data(COMPRESSED_ENVELOPE, MASTER_KEY, dict_obj=wrong_dict, aad=COMPRESSED_AAD)


def test_raw_size_is_rejected_before_decryption(monkeypatch: pytest.MonkeyPatch) -> None:
    class MustNotDecrypt:
        def __init__(self, _: bytes) -> None:
            raise AssertionError("raw output limit must precede AEAD construction")

    oversized = b"\x22" + bytes(12 + 10 + 16)
    monkeypatch.setattr(core, "AESGCMSIV", MustNotDecrypt)
    with pytest.raises(ValueError, match="raw data"):
        open_data(oversized, MASTER_KEY, max_output_size=9)


def test_decompression_limits_known_and_unknown_size_frames() -> None:
    with pytest.raises(ValueError, match="max_output_size"):
        open_data(COMPRESSED_ENVELOPE, MASTER_KEY, aad=COMPRESSED_AAD, max_output_size=99)
    with pytest.raises(ValueError, match="oversized"):
        open_data(
            UNKNOWN_SIZE_COMPRESSED_ENVELOPE, MASTER_KEY, aad=b"unknown-size", max_output_size=99
        )
    assert (
        open_data(UNKNOWN_SIZE_COMPRESSED_ENVELOPE, MASTER_KEY, aad=b"unknown-size") == b"Z" * 4096
    )


@pytest.mark.parametrize(
    "trailer", [b"junk", zstd.ZstdCompressor().compress(b"second frame")]
)
def test_compressed_trailing_data_is_rejected(trailer: bytes) -> None:
    payload = zstd.ZstdCompressor().compress(b"first frame") + trailer
    with pytest.raises(ValueError, match="invalid or oversized"):
        open_data(_authenticated_compressed_payload(payload), MASTER_KEY, aad=b"trailing-frame")


@pytest.mark.parametrize(
    "payload",
    [
        _skippable_frame() + zstd.ZstdCompressor().compress(b"ordinary frame"),
        _skippable_frame() + b"junk",
    ],
)
def test_compressed_skippable_frame_is_rejected(payload: bytes) -> None:
    with pytest.raises(ValueError, match="ordinary Zstandard"):
        open_data(_authenticated_compressed_payload(payload), MASTER_KEY, aad=b"trailing-frame")


def test_validation_and_unknown_suite() -> None:
    with pytest.raises(ValueError, match="32 random"):
        seal(b"x", b"short")
    with pytest.raises(TypeError, match="data"):
        seal("x", MASTER_KEY)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="aad"):
        seal(b"x", MASTER_KEY, aad="header")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="compress"):
        seal(b"x", MASTER_KEY, compress=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="level"):
        seal(b"x", MASTER_KEY, level=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="shorter"):
        open_data(b"", MASTER_KEY)
    with pytest.raises(ValueError, match="unknown"):
        open_data(bytes([0x99]) + bytes(28), MASTER_KEY)
    with pytest.raises(TypeError, match="max_output_size"):
        open_data(RAW_ENVELOPE, MASTER_KEY, max_output_size=True)
    with pytest.raises(ValueError, match="positive"):
        open_data(RAW_ENVELOPE, MASTER_KEY, max_output_size=0)


def test_dictionary_save_load_round_trip_and_mismatch(tmp_path: Path) -> None:
    samples = [f'{{"user":{index},"action":"login","ok":true}}'.encode() for index in range(300)]
    dictionary = train_dict(samples, 2_048)
    path = tmp_path / "model.dict"
    save_dict(dictionary, path)
    loaded = load_dict(path)
    data = samples[42]
    blob = seal(data, MASTER_KEY, dict_obj=loaded)
    assert open_data(blob, MASTER_KEY, dict_obj=loaded) == data
    other_samples = [b"different sample data " + bytes([index % 256]) * 30 for index in range(300)]
    other = train_dict(other_samples, 2_048)
    with pytest.raises(InvalidTag):
        open_data(blob, MASTER_KEY, dict_obj=other)


def test_raw_content_dictionary_substitution_fails_authentication() -> None:
    raw_good = b"0123456789abcdef" * 128
    raw_bad = b"fedcba9876543210" * 128
    data = raw_good[-512:] + b"!"
    good = zstd.ZstdCompressionDict(raw_good, dict_type=zstd.DICT_TYPE_RAWCONTENT)
    substitute = zstd.ZstdCompressionDict(raw_bad, dict_type=zstd.DICT_TYPE_RAWCONTENT)
    blob = seal(data, MASTER_KEY, dict_obj=good)
    assert blob[0] == 0x21
    assert open_data(blob, MASTER_KEY, dict_obj=good) == data
    with pytest.raises(InvalidTag):
        open_data(blob, MASTER_KEY)
    with pytest.raises(InvalidTag):
        open_data(blob, MASTER_KEY, dict_obj=substitute)


def test_cli_key_file_round_trip_and_expected_errors(tmp_path: Path) -> None:
    key, source, sealed, opened = (tmp_path / name for name in ("key", "in", "sealed", "out"))
    source.write_bytes(b"cli data" * 100)
    result = subprocess.run(
        [sys.executable, "-m", "kransx.cli", "keygen", str(key)], text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr
    if os.name != "nt":
        assert key.stat().st_mode & 0o777 == 0o600
    result = subprocess.run(
        [sys.executable, "-m", "kransx.cli", "keygen", str(key)], text=True, capture_output=True
    )
    assert result.returncode == 2
    assert "File exists" in result.stderr
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kransx.cli",
            "seal",
            str(source),
            str(sealed),
            "--key-file",
            str(key),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kransx.cli",
            "open",
            str(sealed),
            str(opened),
            "--key-file",
            str(key),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert opened.read_bytes() == source.read_bytes()
    wrong_key = tmp_path / "wrong-key"
    wrong_key.write_bytes(bytes(32))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kransx.cli",
            "open",
            str(sealed),
            str(opened),
            "--key-file",
            str(wrong_key),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "authentication failed" in result.stderr
    assert "Traceback" not in result.stderr
    existing_output = tmp_path / "existing-output"
    existing_output.write_bytes(b"do not replace")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kransx.cli",
            "seal",
            str(source),
            str(existing_output),
            "--key-file",
            str(key),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "File exists" in result.stderr
    assert "Traceback" not in result.stderr
    assert existing_output.read_bytes() == b"do not replace"
    if not hasattr(os, "link"):
        return
    key_alias = tmp_path / "key-alias"
    try:
        os.link(key, key_alias)
    except OSError:
        pytest.skip("hard links are unavailable")
    original_key = key.read_bytes()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kransx.cli",
            "seal",
            str(source),
            str(key_alias),
            "--key-file",
            str(key),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert key.read_bytes() == original_key
