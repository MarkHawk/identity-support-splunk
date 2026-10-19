#!/usr/bin/env python3
"""Package the identity_support app as dist/identity_support-<version>.tgz.

Only what a Splunk app ships: default/, lookups/, metadata/default.meta,
static/ and README files. Anything a running Splunk writes (local/,
metadata/local.meta) and Python caches are left out. Entries are owned by
nobody and sorted, so the same source always gives the same archive.

    python3 scripts/package_app.py          # prints the archive's path
"""

import configparser
import gzip
import io
import pathlib
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "identity_support"
SHIPPED = ("default", "lookups", "metadata", "static", "README", "README.md", "LICENSE")
LEFT_OUT = ("local", "local.meta", "__pycache__")


def version():
    conf = configparser.RawConfigParser()
    conf.read(APP / "default" / "app.conf", encoding="utf-8")
    return conf["id"]["version"]


def app_files():
    files = []
    for path in sorted(APP.rglob("*")):
        rel = path.relative_to(APP)
        if not path.is_file() or rel.parts[0] not in SHIPPED or set(rel.parts) & set(LEFT_OUT):
            continue
        files.append(path)
    return files


def build(dest=None):
    dest = pathlib.Path(dest or ROOT / "dist" / f"{APP.name}-{version()}.tgz")
    dest.parent.mkdir(parents=True, exist_ok=True)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        dirs = sorted({d for p in app_files() for d in p.parents if d == APP or APP in d.parents})
        for path in dirs + app_files():
            info = tar.gettarinfo(path, arcname=str(pathlib.Path(APP.name) / path.relative_to(APP)))
            info.uid = info.gid = 0
            info.uname = info.gname = "nobody"
            info.mtime = 0
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_dir():
                tar.addfile(info)
            else:
                with path.open("rb") as f:
                    tar.addfile(info, f)
    # No file name or time in the gzip header either.
    with dest.open("wb") as f, gzip.GzipFile(filename="", fileobj=f, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return dest


if __name__ == "__main__":
    print(build(sys.argv[1] if len(sys.argv) > 1 else None))
