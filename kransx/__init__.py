"""KRANSX authenticated encryption-envelope reference implementation."""

from .core import open_data, seal
from .dicts import load_dict, save_dict, train_dict

__version__ = "0.3.0"
SPEC_VERSION = "0.2"

__all__ = [
    "seal",
    "open_data",
    "train_dict",
    "save_dict",
    "load_dict",
    "__version__",
    "SPEC_VERSION",
]
