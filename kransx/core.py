"""Version 0.2 compress-then-encrypt envelope with codec tournament."""

import hashlib
import lzma
import os

import zstandard as zstd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12
_TAG_SIZE = 16
_FIXED_OVERHEAD = 1 + _NONCE_SIZE + _TAG_SIZE
_SUITES = {0x21: "zstd", 0x22: None, 0x23: "lzma"}
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DICT_BINDING_PREFIX = b"kransx/v0.1/zstd-dictionary/"
_NO_DICT_BINDING = hashlib.sha256(_DICT_BINDING_PREFIX + b"none").digest()


def _require_bytes(name: str, value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def _validate_key(key: object) -> bytes:
    key = _require_bytes("key", key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 random bytes")
    return key


def _aead_key(key: bytes) -> bytes:
    return HKDF(
        hashes.SHA256(),
        32,
        None,
        b"kransx/v0.1/aead/aes-256-gcm-siv",
    ).derive(key)


def _compressed_aad(suite: int, aad: bytes, dict_obj: zstd.ZstdCompressionDict | None) -> bytes:
    binding = _NO_DICT_BINDING
    if dict_obj is not None:
        binding = hashlib.sha256(_DICT_BINDING_PREFIX + b"bytes\0" + dict_obj.as_bytes()).digest()
    return bytes([suite]) + binding + aad


def _decompress(payload: bytes, dict_obj: zstd.ZstdCompressionDict | None, limit: int) -> bytes:
    if not payload.startswith(_ZSTD_MAGIC):
        raise ValueError("compressed payload must start with an ordinary Zstandard frame")
    try:
        advertised_size = zstd.frame_content_size(payload)
        if advertised_size == zstd.CONTENTSIZE_ERROR:
            raise ValueError("invalid Zstandard frame")
        if advertised_size != zstd.CONTENTSIZE_UNKNOWN and advertised_size > limit:
            raise ValueError("decompressed data exceeds max_output_size")
        return zstd.ZstdDecompressor(
            dict_data=dict_obj, max_window_size=max(1, (limit + 1023) // 1024)
        ).decompress(payload, max_output_size=limit, allow_extra_data=False)
    except zstd.ZstdError as error:
        raise ValueError("invalid or oversized Zstandard payload") from error


def _decompress_lzma(payload: bytes, limit: int) -> bytes:
    decoder = lzma.LZMADecompressor()
    out = bytearray()
    pos = 0
    try:
        while not decoder.eof:
            if decoder.needs_input:
                if pos >= len(payload):
                    raise ValueError("truncated LZMA payload")
                feed = payload[pos : min(len(payload), pos + 65536)]
                pos += len(feed)
            else:
                feed = b""
            out += decoder.decompress(feed, max_length=limit - len(out) + 1)
            if len(out) > limit:
                raise ValueError("decompressed data exceeds max_output_size")
    except lzma.LZMAError as error:
        raise ValueError("invalid or oversized LZMA payload") from error
    if decoder.unused_data or pos < len(payload):
        raise ValueError("trailing data after LZMA payload")
    return bytes(out)


def seal(
    data: bytes,
    key: bytes,
    *,
    dict_obj: zstd.ZstdCompressionDict | None = None,
    aad: bytes = b"",
    compress: bool = True,
    level: int = 3,
) -> bytes:
    """Compress *data* when smaller, then encrypt it in a envelope."""
    data = _require_bytes("data", data)
    key = _validate_key(key)
    aad = _require_bytes("aad", aad)
    if not isinstance(compress, bool):
        raise TypeError("compress must be bool")
    if isinstance(level, bool) or not isinstance(level, int):
        raise TypeError("level must be an integer")

    payload = data
    suite = 0x22
    used_dict: zstd.ZstdCompressionDict | None = None
    if compress:
        contenders: list[tuple[bytes, int, zstd.ZstdCompressionDict | None]] = [
            (zstd.ZstdCompressor(level=level, dict_data=dict_obj).compress(data), 0x21, dict_obj),
            (zstd.ZstdCompressor(level=19, dict_data=dict_obj).compress(data), 0x21, dict_obj),
            (lzma.compress(data, preset=6), 0x23, None),
        ]
        for blob_candidate, suite_candidate, dict_candidate in contenders:
            if len(blob_candidate) < len(payload):
                payload, suite, used_dict = blob_candidate, suite_candidate, dict_candidate
    compressed = suite != 0x22
    nonce = os.urandom(_NONCE_SIZE)
    authenticated_data = bytes([suite]) + aad
    if compressed:
        authenticated_data = _compressed_aad(suite, aad, used_dict if suite == 0x21 else None)
    ciphertext = AESGCMSIV(_aead_key(key)).encrypt(
        nonce, payload, authenticated_data
    )
    return bytes([suite]) + nonce + ciphertext


def open_data(
    blob: bytes,
    key: bytes,
    *,
    dict_obj: zstd.ZstdCompressionDict | None = None,
    aad: bytes = b"",
    max_output_size: int = 64 * 1024 * 1024,
) -> bytes:
    """Authenticate and open a envelope, enforcing an output limit."""
    blob = _require_bytes("blob", blob)
    key = _validate_key(key)
    aad = _require_bytes("aad", aad)
    if isinstance(max_output_size, bool) or not isinstance(max_output_size, int):
        raise TypeError("max_output_size must be an integer")
    if max_output_size <= 0:
        raise ValueError("max_output_size must be positive")
    if len(blob) < _FIXED_OVERHEAD:
        raise ValueError("blob is shorter than the 29-byte envelope overhead")

    suite = blob[0]
    try:
        codec = _SUITES[suite]
    except KeyError as error:
        raise ValueError(f"unknown suite byte: {suite:#x}") from error
    if codec is None and len(blob) - _FIXED_OVERHEAD > max_output_size:
        raise ValueError("raw data exceeds max_output_size")
    authenticated_data = bytes([suite]) + aad
    if codec is not None:
        authenticated_data = _compressed_aad(suite, aad, dict_obj if codec == "zstd" else None)
    payload = AESGCMSIV(_aead_key(key)).decrypt(
        blob[1 : 1 + _NONCE_SIZE], blob[1 + _NONCE_SIZE :], authenticated_data
    )
    if codec is None:
        return payload
    if codec == "lzma":
        return _decompress_lzma(payload, max_output_size)
    return _decompress(payload, dict_obj, max_output_size)
