#!/usr/bin/env python3
"""Capture sample data from a real identity-lab run, then sanitise it.

This script never changes the lab: it does not break, fix or log in. You run
identity-lab's own end-to-end test, which breaks and fixes every scenario;
this script records when that run started and ended and collects what the
lab logged in between.

    python3 scripts/capture_lab.py
        records the start time, prints the command to run in identity-lab,
        waits for you to press Enter when it has finished, then collects

    python3 scripts/capture_lab.py --since 2026-10-19T18:00:00Z --until 2026-10-19T18:40:00Z
        collects a run you have already done

It collects, into captures/raw/ (gitignored, unsanitised):

    logs/<service>.log     `docker logs --timestamps` of each lab container
                           for the run, both streams in time order
    events/keycloak-admin.jsonl
                           the realm's admin events (a realm or user changed)
                           in the window, from Keycloak's Admin REST API:
                           they never reach Keycloak's log. Read-only (see
                           scripts/keycloak_admin.py), with the admin
                           credentials from the lab's .env, held in memory
    reports/*.json         token-inspector --json on its own lab samples, and
                           rate-limit-probe demo --json (local test server
                           only), each with a .meta.json giving the run's
                           end as the time the report was made
    capture.json           the window, project and tool versions

then writes the sanitised copy to samples/ (replaced) with
scripts/sanitise.py, and checks it. The lab's TOTP secrets (*_TOTP_SECRET in
its .env) are passed to the sanitiser in memory: masked wherever they
appear, and the check fails on any left. Review `git diff samples/` before
committing.

The lab's test.log (identity-lab/test-results/) is never read: it records
the RADIUS test password in plain text.
"""

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sender"))
sys.path.insert(0, str(ROOT / "scripts"))

import hec_send  # noqa: E402
import keycloak_admin  # noqa: E402
import sanitise  # noqa: E402

HOME = pathlib.Path.home()
# identity-lab checked out beside this repo, e.g. ~/projects/identity-lab.
DEFAULT_LAB = ROOT.parent / "identity-lab"
# Where a token-inspector checkout usually is; the first with samples wins.
DEFAULT_TOKEN_INSPECTORS = (HOME / "token-inspector", HOME / "projects" / "token-inspector")
DEFAULT_RATE_LIMIT_PROBE = HOME / "projects" / "rate-limit-probe"
# Behaviours whose reports show a misbehaving limiter, plus one that is fine.
RATE_LIMIT_DEMOS = ("fixed-seconds", "lying", "penalty", "block")


def utc_now():
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


def iso(t):
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value):
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 time: {value}") from None
    if t.tzinfo is None:
        raise argparse.ArgumentTypeError(f"give a time zone, e.g. {value}Z")
    return t


def run(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)


def wait_for_run(lab, out=sys.stdout, ask=input):
    """Print the command, wait for the user, and return the (since, until) window."""
    since = utc_now()
    print(f"Capture started at {iso(since)}.\n", file=out)
    print("In another terminal, run identity-lab's end-to-end test (it breaks and fixes", file=out)
    print("every scenario, and takes several minutes):\n", file=out)
    print(f"    cd {lab} && scripts/test.sh\n", file=out)
    print("Do not use --fresh unless you mean to delete the lab's volumes.", file=out)
    ask("Press Enter here when it has finished (Ctrl-C to abandon): ")
    return since, utc_now()


def collect_logs(project, since, until, raw, runner=None):
    """Write logs/<service>.log for each running lab container; return line counts."""
    containers = hec_send.compose_containers(project, runner=runner)
    if not containers:
        raise hec_send.SenderError(f"no running containers for compose project {project!r}")
    counts = {}
    (raw / "logs").mkdir(parents=True, exist_ok=True)
    for service, name in sorted(containers.items()):
        lines = hec_send.container_lines(name, iso(since), iso(until), runner=runner)
        counts[service] = len(lines)
        if lines:
            (raw / "logs" / f"{service}.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return counts


def lab_env(lab):
    """The lab's .env settings; a missing file is an error naming what to do."""
    path = lab / ".env"
    if not path.exists():
        raise hec_send.SenderError(f"no .env in {lab}: pass --lab with your identity-lab checkout, "
                                   "or --no-admin-events")
    return hec_send.read_env_file(path)


def totp_secrets(env):
    """The lab's TOTP secrets (GRACE_TOTP_SECRET=...), for the sanitiser only."""
    return [v for k, v in env.items() if k.endswith("_TOTP_SECRET") and v]


def lab_admin(lab, env):
    """A read-only client for the lab's Keycloak: 127.0.0.1 on its port,
    checked against the lab CA under LAB_HOST, as identity-lab's kc_curl does."""
    missing = [k for k in ("LAB_HOST", "KC_PORT", "KC_ADMIN_USER", "KC_ADMIN_PASSWORD") if not env.get(k)]
    if missing:
        raise hec_send.SenderError(f"{lab / '.env'} has no {', '.join(missing)}")
    return keycloak_admin.ReadOnlyAdmin("127.0.0.1", env["KC_PORT"], env["KC_ADMIN_USER"], env["KC_ADMIN_PASSWORD"],
                                        cafile=str(lab / "certs" / "ca.crt"), tls_server_name=env["LAB_HOST"])


def collect_admin_events(client, realm, since, until, raw):
    """Write events/keycloak-admin.jsonl (when there are any); return how many."""
    try:
        events = client.admin_events(realm, since, until)
    except keycloak_admin.AdminError as exc:
        raise hec_send.SenderError(f"Keycloak admin events: {exc}") from None
    if events:
        (raw / "events").mkdir(parents=True, exist_ok=True)
        (raw / "events" / "keycloak-admin.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events),
                                                            encoding="utf-8")
    return len(events)


def write_report(raw, name, stdout, when):
    report = json.loads(stdout)  # fail loudly on anything that is not a report
    (raw / "reports").mkdir(parents=True, exist_ok=True)
    (raw / "reports" / f"{name}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (raw / "reports" / f"{name}.meta.json").write_text(json.dumps({"time": iso(when)}) + "\n", encoding="utf-8")


def token_inspector_samples(root):
    """The samples in a token-inspector checkout's samples/lab, by their .meta.json."""
    return sorted((root / "samples" / "lab").glob("*/*.meta.json"))


def token_inspector_reports(roots, raw, when, runner=None):
    """token-inspector --json on each sample in its samples/lab, with the
    arguments recorded in the sample's .meta.json, from the first of roots
    that has samples. Returns report names; finding none is an error, so a
    capture never silently leaves the reports out."""
    root = next((r for r in roots if token_inspector_samples(r)), None)
    if root is None:
        looked = ", ".join(str(r / "samples" / "lab") for r in roots)
        raise hec_send.SenderError(f"no token-inspector samples in {looked}: pass --token-inspector "
                                   "with the path of your token-inspector checkout, or --no-tools to skip the reports")
    exe = root / "venv" / "bin" / "token-inspector"
    names = []
    for meta in token_inspector_samples(root):
        sample = meta.with_name(meta.name[: -len(".meta.json")])
        args = [a.replace("{dir}", str(sample.parent)) for a in json.loads(meta.read_text())["args"]]
        out = (runner or run)([str(exe), "--json", *args, str(sample)])
        if not out.stdout.strip():
            raise hec_send.SenderError(f"token-inspector gave no report for {sample.name}: {out.stderr.strip()}")
        name = f"token-inspector-{sample.parent.name}-{sample.name.split('.')[0]}"
        write_report(raw, name, out.stdout, when)
        names.append(name)
    return names


def rate_limit_probe_reports(root, raw, when, runner=None):
    exe = root / "venv" / "bin" / "rate-limit-probe"
    names = []
    for demo in RATE_LIMIT_DEMOS:
        out = (runner or run)([str(exe), "demo", demo, "--json"])
        if not out.stdout.strip():
            raise hec_send.SenderError(f"rate-limit-probe demo {demo} gave no report: {out.stderr.strip()}")
        name = f"rate-limit-probe-{demo}"
        write_report(raw, name, out.stdout, when)
        names.append(name)
    return names


def build_parser():
    parser = argparse.ArgumentParser(description="Capture sample data from an identity-lab test run, then sanitise it.")
    parser.add_argument("--lab", type=pathlib.Path, default=DEFAULT_LAB,
                        help="identity-lab checkout (default: identity-lab beside this repo)")
    parser.add_argument("--project", default="identity-lab", help="its compose project name")
    parser.add_argument("--since", type=parse_time, help="start of a run already done (ISO 8601 with zone)")
    parser.add_argument("--until", type=parse_time, help="end of that run (default: now)")
    parser.add_argument("--token-inspector", type=pathlib.Path,
                        help="token-inspector checkout (its venv and samples/lab); default: the first of "
                             + " and ".join(str(p).replace(str(HOME), "~") for p in DEFAULT_TOKEN_INSPECTORS)
                             + " that has samples")
    parser.add_argument("--rate-limit-probe", type=pathlib.Path, default=DEFAULT_RATE_LIMIT_PROBE,
                        help="rate-limit-probe checkout (its venv)")
    parser.add_argument("--no-tools", action="store_true", help="no token-inspector or rate-limit-probe reports")
    parser.add_argument("--no-admin-events", action="store_true", help="don't fetch Keycloak's admin events")
    parser.add_argument("--realm", default="idlab", help="the realm whose admin events to fetch (default: idlab)")
    parser.add_argument("--raw", type=pathlib.Path, default=ROOT / "captures" / "raw", help=argparse.SUPPRESS)
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "samples", help=argparse.SUPPRESS)
    return parser


def main(argv=None, out=sys.stdout, ask=input, runner=None, admin=None):
    """admin(lab, env) makes the read-only Keycloak client (default lab_admin)."""
    args = build_parser().parse_args(argv)
    if args.until and not args.since:
        print("capture_lab: --until needs --since", file=sys.stderr)
        return 2
    try:
        if args.since:
            since, until = args.since, args.until or utc_now()
        else:
            since, until = wait_for_run(args.lab, out, ask)
    except (KeyboardInterrupt, EOFError):
        print("\ncapture_lab: abandoned, nothing collected", file=sys.stderr)
        return 1
    if until < since:
        print("capture_lab: --until must be after --since", file=sys.stderr)
        return 2

    raw = args.raw
    if raw.exists():
        for f in sorted(raw.rglob("*"), reverse=True):
            f.unlink() if f.is_file() else f.rmdir()
    raw.mkdir(parents=True, exist_ok=True)
    secrets, admin_events = [], None
    try:
        counts = collect_logs(args.project, since, until, raw, runner)
        if not args.no_admin_events:
            env = lab_env(args.lab)
            secrets = totp_secrets(env)
            admin_events = collect_admin_events((admin or lab_admin)(args.lab, env), args.realm, since, until, raw)
        reports = []
        if not args.no_tools:
            roots = [args.token_inspector] if args.token_inspector else DEFAULT_TOKEN_INSPECTORS
            reports += token_inspector_reports(roots, raw, until, runner)
            reports += rate_limit_probe_reports(args.rate_limit_probe, raw, until, runner)
    except (hec_send.SenderError, OSError, ValueError) as exc:
        print(f"capture_lab: {exc}", file=sys.stderr)
        return 1
    (raw / "capture.json").write_text(json.dumps({
        "since": iso(since), "until": iso(until), "project": args.project,
        "lines": counts, "reports": reports,
        **({"admin_events": admin_events} if admin_events is not None else {}),
    }, indent=2) + "\n", encoding="utf-8")

    for service, n in counts.items():
        print(f"collected {n} lines from {service}", file=out)
    if admin_events is not None:
        print(f"collected {admin_events} Keycloak admin events", file=out)
    print(f"collected {len(reports)} tool reports", file=out)
    print(f"sanitising {raw.relative_to(ROOT) if raw.is_relative_to(ROOT) else raw} into {args.out}", file=out)
    return sanitise.main(["--in", str(raw), "--out", str(args.out)], secrets=secrets)


if __name__ == "__main__":
    sys.exit(main())
