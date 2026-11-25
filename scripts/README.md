# Scripts

`normalize_sdist.py` rewrites a source distribution so repeated builds hash identically. It fixes tar member mtimes, ownership, and the gzip header from `SOURCE_DATE_EPOCH`; setuptools does not apply that variable to sdist members.

```bash
SOURCE_DATE_EPOCH=1700000000 uv build --out-dir dist
SOURCE_DATE_EPOCH=1700000000 uv run python scripts/normalize_sdist.py \
  dist/*.tar.gz dist/kransx.tar.gz
```

CI builds twice and compares the normalized sdist and the wheel hashes.
