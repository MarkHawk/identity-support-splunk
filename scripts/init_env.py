#!/usr/bin/env python3
"""Create or complete .env for the reviewer stack, without printing secrets.

Starts from .env.example when .env does not exist, then fills only the keys
that are empty:

    SPLUNK_PASSWORD   a random admin password for the demo Splunk
    DEMO_HEC_TOKEN    a random HEC token the demo Splunk creates at start
    HEC_URL, HEC_TOKEN  pointed at the demo Splunk, so the sender works
                      against it straight away (change them for your own Splunk)

Existing values are never changed. The file is written readable by you only.
The values are not printed: read the admin password from .env yourself.

    python3 scripts/init_env.py
"""

import os
import pathlib
import secrets
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMO_HEC_URL = "https://127.0.0.1:18088"


def generated(key, values):
    if key == "SPLUNK_PASSWORD":
        # Splunk wants at least 8 characters; url-safe keeps it shell- and YAML-safe.
        return secrets.token_urlsafe(18)
    if key == "DEMO_HEC_TOKEN":
        return str(uuid.uuid4())
    if key == "HEC_URL":
        return DEMO_HEC_URL
    if key == "HEC_TOKEN":
        return values.get("DEMO_HEC_TOKEN")
    return None


def fill(lines):
    """Return (new lines, keys filled). Order: keys others depend on first."""
    values = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    filled = []
    for key in ("SPLUNK_PASSWORD", "DEMO_HEC_TOKEN", "HEC_URL", "HEC_TOKEN"):
        if not values.get(key):
            value = generated(key, values)
            if value:
                values[key] = value
                filled.append(key)
    out, written = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in filled:
            out.append(f"{key}={values[key]}")
            written.add(key)
        else:
            out.append(line)
    out += [f"{k}={values[k]}" for k in filled if k not in written]
    return out, filled


def main(root=ROOT, out=sys.stdout):
    env, example = root / ".env", root / ".env.example"
    source = env if env.exists() else example
    lines, filled = fill(source.read_text(encoding="utf-8").splitlines())
    fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(env, 0o600)
    if filled:
        print(f"init_env: set {', '.join(filled)} in {env.name} (values not shown)", file=out)
    else:
        print(f"init_env: {env.name} already complete; nothing changed", file=out)
    print("init_env: the Splunk admin password is SPLUNK_PASSWORD in .env", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
