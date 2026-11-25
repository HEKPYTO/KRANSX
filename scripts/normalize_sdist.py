import gzip
import io
import os
import sys
import tarfile


def normalize(source: str, destination: str) -> None:
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    raw = io.BytesIO()
    with (
        tarfile.open(source, "r:gz") as archive,
        tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as output,
    ):
        for member in archive.getmembers():
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            content = archive.extractfile(member) if member.isfile() else None
            output.addfile(member, content)
    with (
        open(destination, "wb") as target,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=target, mtime=epoch, compresslevel=9
        ) as compressed,
    ):
        compressed.write(raw.getvalue())


if __name__ == "__main__":
    normalize(sys.argv[1], sys.argv[2])
