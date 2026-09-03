"""Command-line interface for KRANSX."""

import argparse
import glob
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import zstandard as zstd
from cryptography.exceptions import InvalidTag

from .core import open_data, seal
from .dicts import load_dict, train_dict


def _hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value) if value else b""
    except ValueError as error:
        raise ValueError("AAD must be hexadecimal") from error


def _key(path: str) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError("key file must contain exactly 32 raw bytes")
    return key


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def _seal(args: argparse.Namespace) -> None:
    source, target = Path(args.infile), Path(args.outfile)
    dictionary = load_dict(args.dictionary) if args.dictionary else None
    result = seal(
        source.read_bytes(),
        _key(args.key_file),
        dict_obj=dictionary,
        aad=_hex(args.aad),
        compress=not args.no_compress,
        level=args.level,
    )
    _write_new(target, result)
    print(f"sealed {source.stat().st_size} -> {len(result)} bytes")


def _open(args: argparse.Namespace) -> None:
    source, target = Path(args.infile), Path(args.outfile)
    dictionary = load_dict(args.dictionary) if args.dictionary else None
    result = open_data(
        source.read_bytes(),
        _key(args.key_file),
        dict_obj=dictionary,
        aad=_hex(args.aad),
        max_output_size=args.max_output_size,
    )
    _write_new(target, result)
    print(f"opened {source.stat().st_size} -> {len(result)} bytes")


def _train(args: argparse.Namespace) -> None:
    paths = sorted(
        {Path(path) for pattern in args.samples for path in glob.glob(pattern, recursive=True)}
    )
    samples = [path.read_bytes() for path in paths if path.is_file()]
    if not samples:
        raise ValueError("no sample files matched")
    dictionary = train_dict(samples, args.size)
    _write_new(Path(args.outfile), dictionary.as_bytes())
    print(f"trained {len(samples)} samples -> {args.outfile} ({len(dictionary.as_bytes())} bytes)")


def _keygen(args: argparse.Namespace) -> None:
    path = Path(args.key_file)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(os.urandom(32))
    print(f"wrote 32-byte key to {path}")


def _bench(_: argparse.Namespace) -> None:
    root = Path(__file__).resolve().parent.parent
    for script in ("bench/bench_a.py", "bench/bench_b.py"):
        target = root / script
        if not target.is_file():
            raise OSError(f"{script} ships with the repo checkout, not the wheel")
        proc = subprocess.run([sys.executable, str(target)], check=False)
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kransx")
    commands = parser.add_subparsers(dest="command", required=True)
    seal_parser = commands.add_parser("seal", help="compress then encrypt")
    seal_parser.add_argument("infile")
    seal_parser.add_argument("outfile")
    seal_parser.add_argument("--key-file", required=True)
    seal_parser.add_argument("--dict", dest="dictionary")
    seal_parser.add_argument("--aad", default="", help="hexadecimal associated data")
    seal_parser.add_argument("--no-compress", action="store_true")
    seal_parser.add_argument("--level", type=int, default=3)
    seal_parser.set_defaults(handler=_seal)
    open_parser = commands.add_parser("open", help="authenticate then decrypt")
    open_parser.add_argument("infile")
    open_parser.add_argument("outfile")
    open_parser.add_argument("--key-file", required=True)
    open_parser.add_argument("--dict", dest="dictionary")
    open_parser.add_argument("--aad", default="", help="hexadecimal associated data")
    open_parser.add_argument("--max-output-size", type=int, default=64 * 1024 * 1024)
    open_parser.set_defaults(handler=_open)
    train_parser = commands.add_parser("train", help="train a Zstandard dictionary")
    train_parser.add_argument("samples", nargs="+")
    train_parser.add_argument("-o", "--output", dest="outfile", required=True)
    train_parser.add_argument("--size", type=int, default=16_384)
    train_parser.set_defaults(handler=_train)
    keygen_parser = commands.add_parser("keygen", help="create a new raw 32-byte key file")
    keygen_parser.add_argument("key_file")
    keygen_parser.set_defaults(handler=_keygen)
    bench_parser = commands.add_parser("bench", help="run the A+B claim gates")
    bench_parser.set_defaults(handler=_bench)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    handler: Callable[[argparse.Namespace], None] = args.handler
    try:
        handler(args)
    except InvalidTag:
        parser.error("authentication failed")
    except (OSError, ValueError, zstd.ZstdError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
