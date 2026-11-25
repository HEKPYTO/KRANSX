from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
import pytest

from kransx import open_data, seal, train_dict

_KEY = st.binary(min_size=32, max_size=32)
_LEVELS = st.sampled_from((1, 3, 9, 19))
_AAD = st.binary(max_size=128)
_DATA = st.binary(max_size=64 * 1024)
_TAMPER_DATA = st.binary(max_size=16 * 1024)
_DICT = train_dict([f"record:{index}:payload".encode() for index in range(200)], 2_048)
_SETTINGS = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=(HealthCheck.data_too_large, HealthCheck.too_slow),
)


@_SETTINGS
@given(
    data=_DATA,
    key=_KEY,
    aad=_AAD,
    compress=st.booleans(),
    level=_LEVELS,
    use_dict=st.booleans(),
)
@example(
    data=b"large" * (64 * 1024 // 5),
    key=bytes(range(32)),
    aad=b"large",
    compress=True,
    level=19,
    use_dict=False,
)
def test_round_trip_overhead_and_suite(
    data: bytes, key: bytes, aad: bytes, compress: bool, level: int, use_dict: bool
) -> None:
    dict_obj = _DICT if use_dict else None
    blob = seal(data, key, dict_obj=dict_obj, aad=aad, compress=compress, level=level)
    assert blob[0] in (0x21, 0x22, 0x23)
    assert 29 <= len(blob) <= len(data) + 29
    assert open_data(blob, key, dict_obj=dict_obj, aad=aad) == data
    tight = open_data(blob, key, dict_obj=dict_obj, aad=aad, max_output_size=max(len(data), 1))
    assert tight == data


@_SETTINGS
@given(
    data=_TAMPER_DATA,
    key=_KEY,
    aad=_AAD,
    compress=st.booleans(),
    level=_LEVELS,
    use_dict=st.booleans(),
)
@example(
    data=b"large" * (16 * 1024 // 5),
    key=bytes(range(32)),
    aad=b"large",
    compress=True,
    level=19,
    use_dict=False,
)
def test_byte_flip_and_truncation_fail_closed(
    data: bytes, key: bytes, aad: bytes, compress: bool, level: int, use_dict: bool
) -> None:
    dict_obj = _DICT if use_dict else None
    blob = seal(data, key, dict_obj=dict_obj, aad=aad, compress=compress, level=level)
    middle = len(blob) // 2
    flipped = blob[:middle] + bytes([blob[middle] ^ 0x01]) + blob[middle + 1 :]
    suite_flipped = bytes([blob[0] ^ 0x01]) + blob[1:]
    with pytest.raises((InvalidTag, ValueError)):
        open_data(flipped, key, dict_obj=dict_obj, aad=aad)
    with pytest.raises((InvalidTag, ValueError)):
        open_data(suite_flipped, key, dict_obj=dict_obj, aad=aad)
    with pytest.raises((InvalidTag, ValueError)):
        open_data(blob[:-1], key, dict_obj=dict_obj, aad=aad)
