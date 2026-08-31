"""Compress-then-encrypt envelope."""

import hashlib
import os

import zstandard as zstd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12
_TAG_SIZE = 16
_FIXED_OVERHEAD = 1 + _NONCE_SIZE + _TAG_SIZE
_SUITES = {0x21: True, 0x22: False}
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DICT_BINDING_PREFIX = b"kransx/v1/zstd-dictionary/"
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
        b"kransx/v1/aead/aes-256-gcm-siv",
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


def seal(
    data: bytes,
    key: bytes,
    *,
    dict_obj: zstd.ZstdCompressionDict | None = None,
    aad: bytes = b"",
    compress: bool = True,
    level: int = 3,
) -> bytes:
    """Compress *data* when smaller, then encrypt it in an envelope."""
    data = _require_bytes("data", data)
    key = _validate_key(key)
    aad = _require_bytes("aad", aad)
    if not isinstance(compress, bool):
        raise TypeError("compress must be bool")
    if isinstance(level, bool) or not isinstance(level, int):
        raise TypeError("level must be an integer")

    payload = data
    compressed = False
    if compress:
        candidate = zstd.ZstdCompressor(level=level, dict_data=dict_obj).compress(data)
        if len(candidate) < len(data):
            payload, compressed = candidate, True
    suite = 0x21 if compressed else 0x22
    nonce = os.urandom(_NONCE_SIZE)
    authenticated_data = bytes([suite]) + aad
    if compressed:
        authenticated_data = _compressed_aad(suite, aad, dict_obj)
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
    """Authenticate and open an envelope, enforcing an output limit."""
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
        compressed = _SUITES[suite]
    except KeyError as error:
        raise ValueError(f"unknown suite byte: {suite:#x}") from error
    if not compressed and len(blob) - _FIXED_OVERHEAD > max_output_size:
        raise ValueError("raw data exceeds max_output_size")
    authenticated_data = bytes([suite]) + aad
    if compressed:
        authenticated_data = _compressed_aad(suite, aad, dict_obj)
    payload = AESGCMSIV(_aead_key(key)).decrypt(
        blob[1 : 1 + _NONCE_SIZE], blob[1 + _NONCE_SIZE :], authenticated_data
    )
    if compressed:
        return _decompress(payload, dict_obj, max_output_size)
    return payload
