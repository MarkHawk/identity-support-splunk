#!/usr/bin/env python3
"""Connect the sender to a Splunk running in a local Docker container.

For a container started from the splunk/splunk image (named "splunk" by
default) that already has the identity_support app installed:

    1. creates a HEC token for the identity_support index in the container
       (or reuses the token of that name if it already exists)
    2. saves HEC_URL, HEC_TOKEN and HEC_INDEX in .env (readable by you only)
    3. copies Splunk's CA certificate to splunk-ca.pem (gitignored)
    4. sends one test report, verifying HEC's certificate with that CA

The token is never printed: not on success, not in an error. Commands run
inside the container as the splunk user; nothing in it is restarted or
reconfigured beyond adding the token.

    python3 scripts/connect_local_splunk.py
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sender"))

import hec_send  # noqa: E402

SPLUNK = "/opt/splunk/bin/splunk"
CA_IN_CONTAINER = "/opt/splunk/etc/auth/cacert.pem"
# Splunk's default certificate names no host, only this.
DEFAULT_CERT_NAME = "SplunkServerDefaultCert"
UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


class StepFailed(Exception):
    """A step that did not work, with a message safe to print."""


def masked(text):
    """Anything shaped like a HEC token, hidden: CLI output can contain them."""
    return UUID.sub("<token hidden>", text.strip())


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def token_from_cli(output, name):
    """The token of the http://<name> stanza in `http-event-collector` output."""
    stanza = re.search(rf"^http://{re.escape(name)}\s*$(.*?)(?=^\S|\Z)", output, re.M | re.S)
    if stanza:
        m = re.search(r"^\s*token=(\S+)\s*$", stanza.group(1), re.M)
        if m:
            return m.group(1)
    return None


def create_token(args, runner):
    exec_ = ["docker", "exec", "-u", "splunk", args.container, SPLUNK, "http-event-collector"]
    common = ["-uri", "https://localhost:8089"]
    out = runner(exec_ + ["create", args.token_name, *common, "-description", "identity_support app",
                          "-index", args.index, "-indexes", args.index])
    token = token_from_cli(out.stdout, args.token_name)
    if token:
        return token, "created"
    if "already exists" in (out.stdout + out.stderr).lower():
        listed = runner(exec_ + ["list", *common, "-name", args.token_name])
        token = token_from_cli(listed.stdout, args.token_name)
        if token:
            return token, "already existed, reused"
    detail = masked(out.stderr or out.stdout) or f"exit status {out.returncode}"
    raise StepFailed(f"could not create the HEC token in container {args.container!r}: {detail}")


def save_env(path, values):
    """Set keys in .env (from .env.example if new), keeping everything else."""
    path = pathlib.Path(path)
    example = ROOT / ".env.example"
    source = path if path.exists() else example
    lines = source.read_text(encoding="utf-8").splitlines() if source.exists() else []
    done = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in values:
            lines[i] = f"{key}={values[key]}"
            done.add(key)
    lines += [f"{k}={v}" for k, v in values.items() if k not in done]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def copy_ca(args, runner):
    out = runner(["docker", "cp", f"{args.container}:{CA_IN_CONTAINER}", str(args.ca_out)])
    if out.returncode != 0 or not pathlib.Path(args.ca_out).exists():
        raise StepFailed(f"could not copy {CA_IN_CONTAINER} from {args.container!r}: {masked(out.stderr)}")


def build_parser():
    p = argparse.ArgumentParser(description="Create a HEC token in a local Splunk container and point the sender at it.")
    p.add_argument("--container", default="splunk", help="container name (default: splunk)")
    p.add_argument("--hec-url", default="https://127.0.0.1:8088", help="HEC as seen from this machine")
    p.add_argument("--token-name", default="identity-support", help="name of the HEC token")
    p.add_argument("--index", default="identity_support", help="index the token writes to")
    p.add_argument("--env-file", type=pathlib.Path, default=ROOT / ".env")
    p.add_argument("--ca-out", type=pathlib.Path, default=ROOT / "splunk-ca.pem")
    p.add_argument("--tls-server-name", default=DEFAULT_CERT_NAME, help="name in HEC's certificate")
    p.add_argument("--report", type=pathlib.Path, default=ROOT / "samples/reports/rate-limit-probe-penalty.json",
                   help="report to send as the test")
    return p


def step(n, title, success, out):
    print(f"\n[{n}/4] {title}", file=out)
    print(f"      success looks like: {success}", file=out)


def main(argv=None, out=sys.stdout, runner=None):
    args = build_parser().parse_args(argv)
    runner = runner or run
    try:
        step(1, f"Create a HEC token {args.token_name!r} for index {args.index} in container {args.container!r}",
             "\"token created\" (or reused, if it already exists). The token itself is never shown.", out)
        token, how = create_token(args, runner)
        print(f"      ok: token {how}", file=out)

        step(2, f"Save HEC_URL, HEC_TOKEN and HEC_INDEX in {args.env_file.name}",
             f"\"saved\"; {args.env_file.name} is readable by you only and stays out of git.", out)
        save_env(args.env_file, {"HEC_URL": args.hec_url, "HEC_TOKEN": token, "HEC_INDEX": args.index})
        print(f"      ok: saved (HEC_URL={args.hec_url})", file=out)

        step(3, f"Copy Splunk's CA certificate to {args.ca_out.name}",
             "\"copied\"; the sender trusts HEC's self-signed certificate through it.", out)
        copy_ca(args, runner)
        print("      ok: copied", file=out)

        step(4, f"Send {args.report.name} as a test, verifying TLS with that CA",
             "\"sent ... as rate_limit_probe:report\". In Splunk: index=identity_support host=connect-check", out)
        code = hec_send.main(["--env-file", str(args.env_file), "--cacert", str(args.ca_out),
                              "--tls-server-name", args.tls_server_name, "--host", "connect-check",
                              "report", str(args.report)], out=out)
        if code != 0:
            raise StepFailed("the test report was not accepted (see the message above)")
    except StepFailed as exc:
        print(f"      failed: {exc}", file=out)
        return 1
    print("\nDone. Ship the lab's logs with:", file=out)
    print(f"    python3 sender/hec_send.py --cacert {args.ca_out.name} --tls-server-name {args.tls_server_name} "
          "docker --since 30m", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
