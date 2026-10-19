#!/usr/bin/env python3
"""Check that files contain nothing private before they are committed.

The same approach as token-inspector and rate-limit-probe. Generic patterns:
private (RFC 1918) IPv4 addresses, home directory paths other than /home/pi,
email addresses outside the reserved example domains, and private key blocks.
Extra personal strings (a name, a hostname) come from a local, gitignored
.personal-patterns file: one string per line, matched as a whole word and
case-sensitively; lines starting with "re:" are regular expressions, so
"re:(?i)..." ignores case; "#" starts a comment. The committed
.personal-patterns.example is deliberately empty.

Base64 can hide any of these, so the checker also scans decoded base64 and
JWT segments.

    python scripts/sanitise.py --check samples      # exit 1 if anything is found
"""

import argparse
import base64
import binascii
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PERSONAL_FILE = ROOT / ".personal-patterns"

RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.])"
)
HOME_DIR = re.compile(r"/home/(?!pi(?![A-Za-z0-9_.-]))[A-Za-z_][A-Za-z0-9_.-]*")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
# Reserved for documentation (RFC 2606: example.com/org/net and the .example
# top-level domain the lab's users live in), or a no-reply address.
EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])(?!noreply@)[A-Za-z0-9._%+-]+@"
    r"(?!(?:[A-Za-z0-9-]+\.)*example(?:\.(?:com|org|net))?\b)(?!localhost\b)"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)

_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")


def load_personal_patterns(path=PERSONAL_FILE):
    """Compiled patterns from the local file; an absent file means none."""
    path = pathlib.Path(path)
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            patterns.append(re.compile(line[3:]))
        else:
            patterns.append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(line) + r"(?![A-Za-z0-9])"))
    return patterns


def find_problems(text, personal=()):
    """Names of the pattern kinds found; never the matched values themselves."""
    found = []
    if RFC1918.search(text):
        found.append("private IPv4 address")
    if HOME_DIR.search(text):
        found.append("home directory path")
    if EMAIL.search(text):
        found.append("email address")
    if PRIVATE_KEY.search(text):
        found.append("private key")
    if any(p.search(text) for p in personal):
        found.append("personal pattern from .personal-patterns")
    return found


def _b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decoded_views(text):
    """The text plus decoded forms of any base64 or JWT content inside it."""
    views = [text]
    for blob in _B64_BLOB.findall(text):
        for decoder in (base64.b64decode, _b64url_decode):
            try:
                raw = decoder(blob + "=" * (-len(blob) % 4)) if decoder is base64.b64decode else decoder(blob)
            except (binascii.Error, ValueError):
                continue
            try:
                views.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                pass
    for token in re.findall(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", text):
        for segment in token.split(".")[:2]:
            try:
                views.append(_b64url_decode(segment).decode("utf-8"))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass
    return views


def _files(root):
    root = pathlib.Path(root)
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def check_paths(paths, personal=None):
    """Return a list of (file, problem kind) for everything under paths."""
    personal = load_personal_patterns() if personal is None else personal
    problems = []
    for root in paths:
        for f in _files(root):
            text = f.read_bytes().decode("utf-8", errors="replace")
            kinds = set()
            for view in decoded_views(text):
                kinds.update(find_problems(view, personal))
            problems += [(str(f), k) for k in sorted(kinds)]
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check files contain nothing private before committing them.")
    parser.add_argument("--check", nargs="+", metavar="PATH", required=True, help="files or directories to scan")
    args = parser.parse_args(argv)
    problems = check_paths(args.check)
    for path, kind in problems:
        print(f"sanitise: {path}: contains a {kind}", file=sys.stderr)
    if problems:
        print("sanitise: refusing: fix or delete the files above before committing", file=sys.stderr)
        return 1
    print(f"sanitise: clean ({', '.join(args.check)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
