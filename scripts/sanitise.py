#!/usr/bin/env python3
"""Make lab captures safe to commit, and check that they are.

The same approach as token-inspector and rate-limit-probe. Generic patterns:
private (RFC 1918) IPv4 addresses, home directory paths other than /home/pi,
email addresses outside the reserved example domains, and private key blocks.
Extra personal strings (a name, a hostname) come from a local, gitignored
.personal-patterns file: one string per line, matched as a whole word and
case-sensitively; lines starting with "re:" are regular expressions, so
"re:(?i)..." ignores case; "#" starts a comment. The committed
.personal-patterns.example is deliberately empty.

Base64 can hide any of these, so the checker also scans decoded base64 and
JWT segments, URL-decoded text, and deflated base64 (a SAML redirect-binding
SAMLRequest in a proxy's access log).

Sanitising rewrites rather than deletes, so the samples still tell the story:
each private address becomes its own documentation address (192.0.2.10,
192.0.2.11, ...) the same way in every file, so a source address still
correlates across Keycloak, RADIUS and the directory; each email address
outside the example domains becomes userN@example.com; home directories
become "~"; personal strings become "redacted" (a GitHub account in a
github.com URL is kept, as the hygiene test allows). A private key anywhere
stops the run. Noise is trimmed: health-check requests, and directory
connections that only made an anonymous bind (the lab's health check).
The output is checked again before the run reports success.

    python scripts/sanitise.py --in captures/raw --out samples
    python scripts/sanitise.py --check samples      # exit 1 if anything is found
"""

import argparse
import base64
import binascii
import json
import pathlib
import shutil
import re
import sys
import urllib.parse
import zlib

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

HOME_REPLACEMENT = "~"
PERSONAL_REPLACEMENT = "redacted"
GITHUB_ACCOUNT = re.compile(r"github\.com/[A-Za-z0-9-]+")
# Health checks every few seconds would bury the scenario in the samples.
NOISE = re.compile(r'"(?:GET|HEAD) /healthz[ ?]')
SLAPD_CONN = re.compile(r"\sconn=(\d+)\s")
SLAPD_KEEP = re.compile(r'\sBIND dn="[^"]|\sRESULT .*\berr=(?!0\b)\d+')


class UnsafeContent(ValueError):
    """Content that must never be written, such as a private key."""


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


def _inflate(raw):
    """Raw DEFLATE data decompressed, or None."""
    try:
        return zlib.decompress(raw, -zlib.MAX_WBITS)
    except zlib.error:
        return None


def decoded_views(text):
    """The text plus decoded forms of any URL-encoded, base64 (also deflated)
    or JWT content inside it."""
    views = [text]
    unquoted = urllib.parse.unquote(text) if "%" in text else text
    if unquoted != text:
        views.append(unquoted)
    for blob in _B64_BLOB.findall(unquoted):
        for decoder in (base64.b64decode, _b64url_decode):
            try:
                raw = decoder(blob + "=" * (-len(blob) % 4)) if decoder is base64.b64decode else decoder(blob)
            except (binascii.Error, ValueError):
                continue
            for data in (raw, _inflate(raw)):
                try:
                    views.append(data.decode("utf-8"))
                except (AttributeError, UnicodeDecodeError):
                    pass
    for token in re.findall(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", text):
        for segment in token.split(".")[:2]:
            try:
                views.append(_b64url_decode(segment).decode("utf-8"))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass
    return views


class Sanitiser:
    """Rewrites text consistently across every file of one capture."""

    def __init__(self, personal=()):
        self.personal = list(personal)
        self.addresses = {}
        self.emails = {}

    def _address(self, match):
        ip = match.group(0)
        if ip not in self.addresses:
            n = len(self.addresses)
            # 192.0.2.10-254, then 198.51.100.10-254 (both RFC 5737)
            block = "192.0.2" if n < 245 else "198.51.100"
            self.addresses[ip] = f"{block}.{10 + n % 245}"
        return self.addresses[ip]

    def _email(self, match):
        address = match.group(0)
        if address not in self.emails:
            self.emails[address] = f"user{len(self.emails) + 1}@example.com"
        return self.emails[address]

    def text(self, text):
        """Return text with every private pattern rewritten."""
        if any(PRIVATE_KEY.search(view) for view in decoded_views(text)):
            raise UnsafeContent("content contains a private key; refusing to write it")
        text = RFC1918.sub(self._address, text)
        text = EMAIL.sub(self._email, text)
        text = HOME_DIR.sub(HOME_REPLACEMENT, text)
        if self.personal:
            # Keep github.com/<account> as it is; mask personal strings elsewhere.
            pieces, last = [], 0
            for m in GITHUB_ACCOUNT.finditer(text):
                pieces += [self._personal(text[last:m.start()]), m.group(0)]
                last = m.end()
            text = "".join(pieces + [self._personal(text[last:])])
        return text

    def _personal(self, text):
        for p in self.personal:
            text = p.sub(PERSONAL_REPLACEMENT, text)
        return text

    def json_value(self, value):
        """Sanitise every string (keys included) in decoded JSON."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.json_value(v) for v in value]
        if isinstance(value, dict):
            return {self.text(k): self.json_value(v) for k, v in value.items()}
        return value


def trim_log(name, lines):
    """Drop health-check noise. For the directory, keep only connections that
    bound with a DN or got a non-zero result: the rest is the health check's
    anonymous bind, every few seconds."""
    lines = [line for line in lines if not NOISE.search(line)]
    if name.startswith(("ldap", "slapd")):
        keep = {m.group(1) for line in lines if SLAPD_KEEP.search(line) and (m := SLAPD_CONN.search(line))}
        lines = [line for line in lines if (m := SLAPD_CONN.search(line)) is None or m.group(1) in keep]
    return lines


def sanitise_tree(src, dest, personal=None):
    """Write a sanitised copy of every file under src into dest (replaced).
    Returns the number of files written."""
    src, dest = pathlib.Path(src), pathlib.Path(dest)
    s = Sanitiser(load_personal_patterns() if personal is None else personal)
    outputs = {}
    for f in _files(src):
        rel = f.relative_to(src)
        raw = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix == ".json":
            out = json.dumps(s.json_value(json.loads(raw)), indent=2, ensure_ascii=False) + "\n"
        else:
            lines = trim_log(f.stem, raw.splitlines())
            if not lines:
                continue  # nothing left once the noise is trimmed
            out = "".join(s.text(line) + "\n" for line in lines)
        outputs[rel] = out
    if dest.exists():
        shutil.rmtree(dest)
    for rel, out in outputs.items():
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        (dest / rel).write_text(out, encoding="utf-8")
    return len(outputs)


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
    parser = argparse.ArgumentParser(description="Make lab captures safe to commit, and check that they are.")
    parser.add_argument("--check", nargs="+", metavar="PATH", help="files or directories to scan")
    parser.add_argument("--in", dest="src", metavar="DIR", help="raw capture to sanitise")
    parser.add_argument("--out", metavar="DIR", help="where to write the sanitised copy (replaced)")
    args = parser.parse_args(argv)
    if args.src or args.out:
        if not (args.src and args.out) or args.check:
            parser.error("use --in and --out together, or --check on its own")
        try:
            count = sanitise_tree(args.src, args.out)
        except UnsafeContent as exc:
            print(f"sanitise: {exc}", file=sys.stderr)
            return 1
        print(f"sanitise: wrote {count} files to {args.out}")
        args.check = [args.out]
    elif not args.check:
        parser.error("give --check PATH..., or --in DIR --out DIR")
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
