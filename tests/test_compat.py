import pytest
from cryptography.exceptions import InvalidTag

from kransx import open_data, seal, train_dict

_KEY = bytes(range(32))
_LZMA_DATA = b"KRANS-X lzma compat smoke\n" * 8
_LZMA_AAD = b"compat/lzma"
_LZMA_ENVELOPE = bytes.fromhex(
    "23000102030405060708090a0b5332acc777326d4da58d4360157bc494df50c2756ef112727e796a"
    "ea094cc234fc8387ba08eee0a122b8fe3276692d6e0a0724b390efb3133d11f56bcfb7d46c4b128"
    "bbdccdf78db53ea20d9ee7c6cbff87765641c3b5e77528f0e5b404e340c27cf555b7c41b4c4b5e2"
    "da402b9db8efc586edf0"
)


def test_raw_envelope_with_supported_floor_api() -> None:
    data = b"raw compat payload"
    blob = seal(data, _KEY, aad=b"ctx", compress=False)
    assert blob[0] == 0x22
    assert len(blob) == len(data) + 29
    assert open_data(blob, _KEY, aad=b"ctx") == data
    with pytest.raises(InvalidTag):
        open_data(blob, _KEY, aad=b"wrong")


def test_zstd_envelope_with_supported_floor_api() -> None:
    data = b"zstd compat payload\n" * 100
    blob = seal(data, _KEY, aad=b"ctx", level=3)
    assert blob[0] == 0x21
    assert open_data(blob, _KEY, aad=b"ctx") == data
    with pytest.raises(InvalidTag):
        open_data(blob, bytes(range(32, 64)), aad=b"ctx")


def test_lzma_envelope_with_supported_floor_api() -> None:
    assert _LZMA_ENVELOPE[0] == 0x23
    assert open_data(_LZMA_ENVELOPE, _KEY, aad=_LZMA_AAD) == _LZMA_DATA
    with pytest.raises(InvalidTag):
        open_data(_LZMA_ENVELOPE, _KEY, aad=b"wrong")


def test_dictionary_envelope_with_supported_floor_api() -> None:
    samples = [f'{{"user":{index},"action":"login"}}'.encode() for index in range(200)]
    dictionary = train_dict(samples, 2_048)
    data = b"".join(samples[7:20])
    blob = seal(data, _KEY, dict_obj=dictionary, aad=b"ctx")
    assert blob[0] == 0x21
    assert open_data(blob, _KEY, dict_obj=dictionary, aad=b"ctx") == data
    with pytest.raises(InvalidTag):
        open_data(blob, _KEY, aad=b"ctx")
