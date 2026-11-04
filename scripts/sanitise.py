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
github.com URL is kept, as the hygiene test allows). Single-use login values
in URLs (authorisation codes, state, nonce, Keycloak's session codes, SAML
requests and responses, signatures) become masked-<name>-N, again the same
value the same way everywhere, so a state still links the authorisation
request to its callback. Tokens are credentials until they expire:
access_token, id_token, refresh_token and id_token_hint values (in a query,
a fragment, a form body or as a JSON key) become masked-<name>-N, and
anything shaped like a JWT (eyJ....eyJ...., signed or not) masked-jwt-N.
MFA values are masked the same way: otpauth:// URIs, Keycloak's OTP form
fields (otp, totp, totpSecret...), a 6 to 8 digit code next to a name that
says it is one, base32 secrets after a secret-like name or in Keycloak's
grouped setup-key form, and credential IDs (masked-credential-N, so a
user's code failures still share one). A caller can also pass the lab's
known TOTP secrets (capture_lab.py reads them from the lab's .env, in
memory only): they are masked in any case or grouping, and the check fails
on any left. The host's network names are replaced too: a Tailscale
MagicDNS name (*.ts.net) becomes tailnet.example, and a DNS search domain
from the host's resolv.conf (as Squid logs it) search.example. A private
key anywhere
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

# Query parameters whose values are single-use login secrets or carry one
# (Keycloak's client_data holds the state). Names are matched exactly, so
# code_challenge_method=S256 and response_type=code stay.
ONE_TIME_PARAMS = ("code", "session_code", "session_state", "state", "nonce", "code_challenge", "client_data",
                   "SAMLRequest", "SAMLResponse", "Signature")
ONE_TIME_VALUE = re.compile(r"(?<=[?&])(" + "|".join(ONE_TIME_PARAMS) + r")=([^&\s\"]+)")
MASKED = "masked-"
# identity-lab masks code, state, session_state and the SAML messages
# itself, as ***; those stay as they are (numbering them would claim every
# *** was the same value).
LAB_MASKED = "***"
# What the checker counts as unmasked: a value long enough to be real.
UNMASKED_VALUE = re.compile(r"(?<=[?&])(?:" + "|".join(ONE_TIME_PARAMS) + r")=(?!" + MASKED + r")[^&\s\"]{8,}")

# OAuth tokens: in a query or fragment (#access_token=... in the implicit
# flow), a form body, or after a space. id_token_hint carries a whole ID
# token on logout.
TOKEN_PARAMS = ("access_token", "id_token", "refresh_token", "id_token_hint")
TOKEN_VALUE = re.compile(r"(?<![\w-])(" + "|".join(TOKEN_PARAMS) + r")=([^&\s\"'#]+)")
# Tokens are base64url, base64 or form-encoded; the checker counts a value of
# 8 or more of those characters.
UNMASKED_TOKEN = re.compile(r"(?<![\w-])(?:" + "|".join(TOKEN_PARAMS) + r")=(?!" + MASKED + r")[A-Za-z0-9._~+/%=-]{8,}")
# A JWT: a base64url JSON header and payload (both start {" so eyJ), and a
# signature, empty for an unsigned token.
JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")

# MFA (TOTP) values. An otpauth:// URI carries the secret itself.
OTPAUTH_URI = re.compile(r"otpauth(?:-migration)?://[a-z]+[/?][^\s\"'<>]*")
# Keycloak's login and setup forms: otp (the code at login), totp (the code
# at setup), and totpSecret, totpSecretEncoded and totpSecretQrCode (the
# secret, the setup key as shown, and its QR code), in a query, a form body
# or key=value text.
MFA_FORM_PARAMS = ("otp", "totp", "totpSecret", "totpSecretEncoded", "totpSecretQrCode")
MFA_FORM_VALUE = re.compile(r"(?<![\w-])(" + "|".join(MFA_FORM_PARAMS) + r")=([^&\s\"'#]+)")
# What the checker counts as unmasked: a code of 6 to 8 digits in otp or
# totp, and 16 or more base32, base64 or URL-encoded characters in the rest.
UNMASKED_MFA_CODE = re.compile(r"(?<![\w-])t?otp=\d{6,8}(?!\d)")
UNMASKED_MFA_SECRET = re.compile(r"(?<![\w-])totpSecret(?:Encoded|QrCode)?=[A-Za-z0-9+/%=]{16,}")
# A one-time code (6 to 8 digits) next to a name that says it is one:
# otp=<digits>, "totp_code": "<digits>", one-time code: <digits>.
OTP_CODE_NAME = r"(?i:\b(?:t?otp|one[ _-]?time[ _-]?code|t?otp[_-]?code|mfa[_-]?code|verification[_-]?code))"
OTP_CODE = re.compile(r"(" + OTP_CODE_NAME + r"[\"']?\s*[:=]\s*[\"']?)(\d{6,8})(?!\d)")
# A base32 secret after a name that says it is one: secret=..., setup key:
# ..., GRACE_TOTP_SECRET=... (16 or more base32 characters, either case).
SECRET_NAME = r"(?i:\b(?:[a-z_]*totp_?secret|secret|setup[ _-]?key))"
BASE32_SECRET = re.compile(r"(" + SECRET_NAME + r"[\"']?\s*[:=]\s*[\"']?)([A-Za-z2-7]{16,}=*)(?![A-Za-z0-9])")
# Keycloak's setup page shows the secret as groups of four base32 characters
# (ABCD EFGH 2JKL ...). Four or more groups, at least one digit among them,
# so ordinary capitals ("THIS WILL NOT WORK") don't count.
SETUP_KEY = re.compile(r"(?<![A-Za-z0-9])(?=[A-Z2-7 ]*[2-7])[A-Z2-7]{4}(?: [A-Z2-7]{4}){3,}(?: [A-Z2-7]{1,3})?(?![A-Za-z0-9])")
# Keycloak's credential IDs (the authenticator the user picked, in a code
# failure's selected_credential_id), masked the same value the same way.
CREDENTIAL_ID = re.compile(r"(?i:\b(selected_credential_id|credential_?id))([\"']?\s*[:=]\s*[\"']?)"
                           r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

# ... and in an Admin REST API path (an admin event's resourcePath):
# users/<user id>/credentials/<credential id>.
CREDENTIAL_PATH = re.compile(r"(?<![\w-])(credentials/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
# The same values under their own JSON keys, whatever their shape: key ->
# the name they are masked under.
JSON_MFA_KEYS = {**{k: k for k in MFA_FORM_PARAMS}, "secret": "totp-secret", "credentialId": "credential",
                 "credential_id": "credential", "selected_credential_id": "credential"}

# The host's network, as containers see it: a Tailscale MagicDNS name
# (<tailnet>.ts.net), and the DNS search domain Squid reads from the
# resolv.conf Docker copies in from the host. Both name the machine's
# network, not the lab.
TAILNET = re.compile(r"(?i)(?<![A-Za-z0-9.-])(?:[a-z0-9-]+\.)+ts\.net\b")
TAILNET_REPLACEMENT = "tailnet.example"
RESOLV_DOMAIN = re.compile(r"(Adding domain )(\S+)( from /etc/resolv\.conf)")
RESOLV_REPLACEMENT = "search.example"

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


def secret_pattern(secret):
    """A base32 TOTP secret as it can appear: either case, with or without
    its = padding, run together or in Keycloak's groups of four."""
    chars = secret.replace(" ", "").rstrip("=")
    groups = [re.escape(chars[i:i + 4]) for i in range(0, len(chars), 4)]
    return re.compile(r"(?i)(?<![A-Za-z0-9])" + " ?".join(groups) + r"(?:=*)(?![A-Za-z0-9])")


def find_problems(text, personal=(), secrets=()):
    """Names of the pattern kinds found; never the matched values themselves.
    secrets are patterns for known TOTP secrets (secret_pattern)."""
    found = []
    if RFC1918.search(text):
        found.append("private IPv4 address")
    if HOME_DIR.search(text):
        found.append("home directory path")
    if EMAIL.search(text):
        found.append("email address")
    if PRIVATE_KEY.search(text):
        found.append("private key")
    if UNMASKED_VALUE.search(text):
        found.append("single-use login value")
    if UNMASKED_TOKEN.search(text):
        found.append("OAuth token parameter")
    if JWT.search(text):
        found.append("JWT")
    if (OTPAUTH_URI.search(text) or any(not m.group(2).startswith(MASKED) for m in BASE32_SECRET.finditer(text))
            or any(p.search(text) for p in secrets)):
        found.append("TOTP secret")
    if UNMASKED_MFA_CODE.search(text) or OTP_CODE.search(text):
        found.append("one-time code")
    if SETUP_KEY.search(text) or UNMASKED_MFA_SECRET.search(text):
        found.append("Keycloak setup key")
    if CREDENTIAL_ID.search(text) or CREDENTIAL_PATH.search(text):
        found.append("credential ID")
    if TAILNET.search(text) or any(m.group(2) not in (".", RESOLV_REPLACEMENT, TAILNET_REPLACEMENT)
                                   for m in RESOLV_DOMAIN.finditer(text)):
        found.append("host network name")
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

    def __init__(self, personal=(), secrets=()):
        self.personal = list(personal)
        self.secrets = list(secrets)
        self.addresses = {}
        self.emails = {}
        self.one_time = {}

    def _address(self, match):
        ip = match.group(0)
        if ip not in self.addresses:
            n = len(self.addresses)
            # 192.0.2.10-254, then 198.51.100.10-254 (both RFC 5737)
            block = "192.0.2" if n < 245 else "198.51.100"
            self.addresses[ip] = f"{block}.{10 + n % 245}"
        return self.addresses[ip]

    def _one_time(self, match):
        name, value = match.groups()
        if value.startswith(MASKED) or value == LAB_MASKED:
            return match.group(0)
        return f"{name}={self._masked(name, value)}"

    def _masked(self, name, value):
        if (name, value) not in self.one_time:
            n = sum(1 for k in self.one_time if k[0] == name) + 1
            self.one_time[(name, value)] = f"{MASKED}{name}-{n}"
        return self.one_time[(name, value)]

    def _token(self, match):
        name, value = match.groups()
        if value.startswith(MASKED) or value == LAB_MASKED:
            return match.group(0)
        return f"{name}={self._masked(name, value)}"

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
        text = ONE_TIME_VALUE.sub(self._one_time, text)
        text = TOKEN_VALUE.sub(self._token, text)
        text = JWT.sub(lambda m: self._masked("jwt", m.group(0)), text)
        text = self.mfa(text)
        text = TAILNET.sub(TAILNET_REPLACEMENT, text)
        text = RESOLV_DOMAIN.sub(lambda m: m.group(0) if m.group(2) in (".", TAILNET_REPLACEMENT)
                                 else m.group(1) + RESOLV_REPLACEMENT + m.group(3), text)
        if self.personal:
            # Keep github.com/<account> as it is; mask personal strings elsewhere.
            pieces, last = [], 0
            for m in GITHUB_ACCOUNT.finditer(text):
                pieces += [self._personal(text[last:m.start()]), m.group(0)]
                last = m.end()
            text = "".join(pieces + [self._personal(text[last:])])
        return text

    def mfa(self, text):
        """Mask TOTP secrets, setup keys, one-time codes and credential IDs."""
        for p in self.secrets:
            text = p.sub(lambda m: self._masked("totp-secret", m.group(0).replace(" ", "").upper().rstrip("=")), text)
        text = OTPAUTH_URI.sub(lambda m: self._masked("otpauth", m.group(0)), text)
        text = MFA_FORM_VALUE.sub(self._one_time, text)
        text = OTP_CODE.sub(lambda m: m.group(1) + self._masked("otp-code", m.group(2)), text)
        text = BASE32_SECRET.sub(lambda m: m.group(1) + self._masked("totp-secret", m.group(2).upper().rstrip("=")), text)
        text = SETUP_KEY.sub(lambda m: self._masked("totp-secret", m.group(0).replace(" ", "")), text)
        text = CREDENTIAL_ID.sub(lambda m: m.group(1) + m.group(2) + self._masked("credential", m.group(3).lower()), text)
        return CREDENTIAL_PATH.sub(lambda m: m.group(1) + self._masked("credential", m.group(2).lower()), text)

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
            return {self.text(k): self._json_item(k, v) for k, v in value.items()}
        return value

    def _json_item(self, key, value):
        """A token under its own key ({"access_token": "..."}) is masked whatever its shape."""
        if key in TOKEN_PARAMS and isinstance(value, str) and value not in ("", LAB_MASKED) and not value.startswith(MASKED):
            return self._masked(key, value)
        if key in JSON_MFA_KEYS and isinstance(value, str) and value not in ("", LAB_MASKED) and not value.startswith(MASKED):
            name = JSON_MFA_KEYS[key]
            return self._masked(name, value.lower() if name == "credential" else value)
        return self.json_value(value)


def trim_log(name, lines):
    """Drop health-check noise. For the directory, keep only connections that
    bound with a DN or got a non-zero result: the rest is the health check's
    anonymous bind, every few seconds."""
    lines = [line for line in lines if not NOISE.search(line)]
    if name.startswith(("ldap", "slapd")):
        keep = {m.group(1) for line in lines if SLAPD_KEEP.search(line) and (m := SLAPD_CONN.search(line))}
        lines = [line for line in lines if (m := SLAPD_CONN.search(line)) is None or m.group(1) in keep]
    return lines


def sanitise_tree(src, dest, personal=None, secrets=()):
    """Write a sanitised copy of every file under src into dest (replaced).
    secrets: known TOTP secrets (plain base32 strings), masked wherever they
    appear. Returns the number of files written."""
    src, dest = pathlib.Path(src), pathlib.Path(dest)
    s = Sanitiser(load_personal_patterns() if personal is None else personal, [secret_pattern(x) for x in secrets])
    outputs = {}
    for f in _files(src):
        rel = f.relative_to(src)
        raw = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix == ".json":
            out = json.dumps(s.json_value(json.loads(raw)), indent=2, ensure_ascii=False) + "\n"
        elif f.suffix == ".jsonl":
            out = "".join(json.dumps(s.json_value(json.loads(line)), ensure_ascii=False) + "\n"
                          for line in raw.splitlines() if line.strip())
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


def check_paths(paths, personal=None, secrets=()):
    """Return a list of (file, problem kind) for everything under paths.
    secrets: known TOTP secrets, which must appear nowhere."""
    personal = load_personal_patterns() if personal is None else personal
    secrets = [secret_pattern(x) for x in secrets]
    problems = []
    for root in paths:
        for f in _files(root):
            text = f.read_bytes().decode("utf-8", errors="replace")
            kinds = set()
            for view in decoded_views(text):
                kinds.update(find_problems(view, personal, secrets))
            problems += [(str(f), k) for k in sorted(kinds)]
    return problems


def main(argv=None, secrets=()):
    """The command line. secrets (known TOTP secrets) come only from a
    caller such as capture_lab.py, never from argv, so they are never on a
    command line."""
    parser = argparse.ArgumentParser(description="Make lab captures safe to commit, and check that they are.")
    parser.add_argument("--check", nargs="+", metavar="PATH", help="files or directories to scan")
    parser.add_argument("--in", dest="src", metavar="DIR", help="raw capture to sanitise")
    parser.add_argument("--out", metavar="DIR", help="where to write the sanitised copy (replaced)")
    args = parser.parse_args(argv)
    if args.src or args.out:
        if not (args.src and args.out) or args.check:
            parser.error("use --in and --out together, or --check on its own")
        try:
            count = sanitise_tree(args.src, args.out, secrets=secrets)
        except UnsafeContent as exc:
            print(f"sanitise: {exc}", file=sys.stderr)
            return 1
        print(f"sanitise: wrote {count} files to {args.out}")
        args.check = [args.out]
    elif not args.check:
        parser.error("give --check PATH..., or --in DIR --out DIR")
    problems = check_paths(args.check, secrets=secrets)
    for path, kind in problems:
        print(f"sanitise: {path}: contains a {kind}", file=sys.stderr)
    if problems:
        print("sanitise: refusing: fix or delete the files above before committing", file=sys.stderr)
        return 1
    print(f"sanitise: clean ({', '.join(args.check)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
