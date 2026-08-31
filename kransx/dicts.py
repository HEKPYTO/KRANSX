"""Zstandard dictionary helpers; dictionaries are shared compression models."""

import os
from collections.abc import Iterable
from pathlib import Path

import zstandard as zstd


def train_dict(samples: Iterable[bytes], dict_size: int = 16_384) -> zstd.ZstdCompressionDict:
    """Train a Zstandard dictionary, propagating training errors to the caller."""
    if isinstance(dict_size, bool) or not isinstance(dict_size, int) or dict_size <= 0:
        raise ValueError("dict_size must be a positive integer")
    sample_list: list[bytes | bytearray | memoryview[int]] = list(samples)
    if any(not isinstance(sample, bytes) for sample in sample_list):
        raise TypeError("samples must contain bytes")
    return zstd.train_dictionary(dict_size, sample_list)


def save_dict(dict_obj: zstd.ZstdCompressionDict, path: str | os.PathLike[str]) -> None:
    """Save a dictionary's public bytes to *path*."""
    Path(path).write_bytes(dict_obj.as_bytes())


def load_dict(path: str | os.PathLike[str]) -> zstd.ZstdCompressionDict:
    """Load an ordinary Zstandard dictionary from *path*."""
    return zstd.ZstdCompressionDict(Path(path).read_bytes())
