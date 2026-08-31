from kransx import open_data, seal


def test_raw_envelope_round_trip() -> None:
    key = bytes(range(32))
    blob = seal(b"hello", key, compress=False)
    assert blob[0] == 0x22
    assert open_data(blob, key) == b"hello"


def test_adaptive_compression_round_trip() -> None:
    key = bytes(range(32))
    blob = seal(b"A" * 10_000, key)
    assert blob[0] == 0x21
    assert open_data(blob, key) == b"A" * 10_000
