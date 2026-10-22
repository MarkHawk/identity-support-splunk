#!/usr/bin/env python3
"""Ship identity-lab container logs and the tools' JSON reports to Splunk HEC.

    hec_send.py docker [--project identity-lab] [--since 15m] [--until TIME]
    hec_send.py report FILE...           token-inspector / rate-limit-probe --json output
    hec_send.py replay DIR [--shift-to-now]   a samples/ folder: logs/*.log and reports/*.json

Container logs go to the raw endpoint (/services/collector/raw), so the app's
props.conf breaks lines and reads timestamps exactly as it would for a
monitored file. Reports go to the event endpoint with an explicit time.

The directory's routine search lines (each SRCH request and its successful
SEARCH RESULT) are dropped by default and counted in the output; binds,
failed results and connections are always sent. --keep-ldap-searches sends
everything.

Settings come from the environment, or from .env next to the repository root
(the environment wins): HEC_URL (e.g. https://localhost:8088), HEC_TOKEN and
HEC_INDEX (default identity_support). The token is never printed: not in
output, errors or --dry-run.

TLS is verified. For Splunk's self-signed certificate, prefer --cacert with
the CA that signed it (and --tls-server-name if the certificate does not name
the host you connect to). Splunk's default certificates lack extensions that
Python 3.13+ demands in its strict mode, so with --cacert (and only then)
the strict flag is cleared; chain and hostname checks stay on. In
production, give HEC a properly issued certificate. --insecure turns
verification off and is accepted only when HEC_URL's host is localhost or
127.0.0.1.

Standard library only.
"""

import argparse
import datetime as dt
import http.client
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_ENV_FILE = ROOT / ".env"
DEFAULT_INDEX = "identity_support"
INSECURE_HOSTS = ("localhost", "127.0.0.1")
BATCH_BYTES = 512 * 1024

# Compose service name -> sourcetype. Postgres and the test runner are not shipped.
SERVICES = {
    "keycloak": "idlab:keycloak",
    "saml-sp": "idlab:sp",
    "oidc-rp": "idlab:sp",
    "saml-sp-proxied": "idlab:sp",
    "oidc-rp-proxied": "idlab:sp",
    "oidc-rp-egress": "idlab:sp",
    # nginx access and error logs in one stream; props.conf types each line.
    "proxy": "idlab:nginx",
    # Squid's access log (stdout) and cache.log (stderr); props.conf types each event.
    "squid": "idlab:squid",
    "radius": "idlab:radius",
    "nas": "idlab:nas",
    "ldap": "idlab:slapd",
}
TOOLS = {"token-inspector": "token_inspector:report", "rate-limit-probe": "rate_limit_probe:report"}
# The IdP's routine directory lookups: a search request (SRCH lines) and its
# successful result. Binds, failed results and connections are always kept.
ROUTINE_LDAP_SEARCH = re.compile(r" conn=\d+ op=\d+ (?:SRCH |SEARCH RESULT .*\berr=0\b)")

# Every line from `docker logs --timestamps` starts with this.
DOCKER_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z "
_DOCKER_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{9})Z ")
# Where a new event starts, per sourcetype. These must match the lookahead in
# each LINE_BREAKER in props.conf (a test checks), so a batch never ends in the
# middle of an event such as a Keycloak stack trace.
EVENT_START = {
    "idlab:keycloak": DOCKER_TS + r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} ",
    "idlab:sp": DOCKER_TS + r"(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} |\[\d{4}-\d{2}-\d{2} |\S+ - \S+ \[)",
    "idlab:radius": DOCKER_TS,
    "idlab:nas": DOCKER_TS,
    "idlab:slapd": DOCKER_TS,
    "idlab:nginx": DOCKER_TS,
    # An access line starts with epoch seconds, a cache.log message with its
    # own date; cache.log's indented detail lines stay with the message.
    "idlab:squid": DOCKER_TS + r"(?:\d{10}\.\d{3} |\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\| )",
}


class SenderError(Exception):
    """A problem to report in one line, with exit status 1."""


class Secret:
    """Holds the HEC token so that printing or logging it shows nothing."""

    def __init__(self, value):
        self._value = value

    def reveal(self):
        return self._value

    def __bool__(self):
        return bool(self._value)

    def __repr__(self):
        return "Secret('***')"

    __str__ = __repr__


def read_env_file(path):
    """KEY=VALUE lines; '#' comments and blank lines skipped; quotes stripped."""
    values = {}
    path = pathlib.Path(path)
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


class Config:
    def __init__(self, url, token, index, insecure=False, cacert=None, tls_server_name=None):
        self.url, self.token, self.index = url, token, index
        self.insecure, self.cacert, self.tls_server_name = insecure, cacert, tls_server_name
        parsed = urllib.parse.urlsplit(url or "")
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise SenderError("HEC_URL must be http:// or https:// with a host, e.g. https://localhost:8088")
        self.scheme, self.host = parsed.scheme, parsed.hostname
        self.port = parsed.port or 8088
        self.base_path = parsed.path.rstrip("/")
        if insecure and self.host not in INSECURE_HOSTS:
            raise SenderError(
                f"--insecure is only allowed for localhost or 127.0.0.1, not {self.host}. "
                "Use --cacert with the CA that signed Splunk's certificate instead."
            )
        if insecure and self.scheme != "https":
            raise SenderError("--insecure only applies to https:// URLs")
        if (cacert or tls_server_name) and self.scheme != "https":
            raise SenderError("--cacert and --tls-server-name only apply to https:// URLs")
        if cacert and insecure:
            raise SenderError("use --cacert or --insecure, not both")

    @classmethod
    def load(cls, args, environ=None):
        environ = os.environ if environ is None else environ
        file_values = read_env_file(args.env_file)

        def setting(name, default=None):
            return environ.get(name) or file_values.get(name) or default

        token = setting("HEC_TOKEN")
        if not token:
            raise SenderError(f"HEC_TOKEN is not set (environment or {args.env_file})")
        return cls(setting("HEC_URL"), Secret(token), setting("HEC_INDEX", DEFAULT_INDEX),
                   insecure=args.insecure, cacert=args.cacert, tls_server_name=args.tls_server_name)

    def ssl_context(self):
        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        try:
            ctx = ssl.create_default_context(cafile=self.cacert)
        except (OSError, ssl.SSLError) as exc:
            raise SenderError(f"cannot load --cacert {self.cacert}: {exc}") from None
        if self.cacert:
            # Splunk's default self-signed certificates lack extensions (such
            # as the Authority Key Identifier) that Python 3.13+ requires in its
            # default strict mode. Only for a CA named explicitly with --cacert,
            # clear that one flag: the chain is still verified against that CA
            # and the hostname (or --tls-server-name) is still checked.
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        return ctx


class _HTTPSConnection(http.client.HTTPSConnection):
    """Verifies the certificate against tls_server_name instead of the URL's host."""

    def __init__(self, *args, tls_server_name=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._tls_server_name = tls_server_name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_server_name or self.host)


class HEC:
    def __init__(self, config, timeout=30):
        self.config, self.timeout = config, timeout
        self.channel = str(uuid.uuid4())

    def _connection(self):
        c = self.config
        if c.scheme == "http":
            return http.client.HTTPConnection(c.host, c.port, timeout=self.timeout)
        return _HTTPSConnection(c.host, c.port, timeout=self.timeout, context=c.ssl_context(),
                                tls_server_name=c.tls_server_name)

    def post(self, path, body, query=None):
        c = self.config
        url = c.base_path + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {
            "Authorization": "Splunk " + c.token.reveal(),
            "X-Splunk-Request-Channel": self.channel,
            "Content-Type": "application/json" if path.endswith("/event") else "text/plain; charset=utf-8",
        }
        conn = self._connection()
        try:
            conn.request("POST", url, body=body.encode("utf-8"), headers=headers)
            response = conn.getresponse()
            text = response.read().decode("utf-8", errors="replace")
        except ssl.SSLCertVerificationError as exc:
            raise SenderError(
                f"TLS certificate not trusted for {c.host}: {exc.verify_message.rstrip('.')}. "
                "Pass --cacert with the CA that signed it (and --tls-server-name if it names another host)."
            ) from None
        except (OSError, http.client.HTTPException) as exc:
            raise SenderError(f"cannot reach HEC at {c.scheme}://{c.host}:{c.port}: {exc}") from None
        finally:
            conn.close()
        if response.status != 200:
            raise SenderError(f"HEC refused the batch: HTTP {response.status} {_hec_text(text)}")
        return text

    def send_raw(self, events, sourcetype, source, host):
        """Send already-grouped events (each one or more lines) in batches."""
        query = {"sourcetype": sourcetype, "source": source, "host": host, "index": self.config.index}
        for batch in batches(events):
            self.post("/services/collector/raw", batch, query)

    def send_event(self, event, time, sourcetype, source, host):
        payload = {"time": time, "host": host, "source": source, "sourcetype": sourcetype,
                   "index": self.config.index, "event": event}
        self.post("/services/collector/event", json.dumps(payload))


def _hec_text(body):
    try:
        reply = json.loads(body)
        return f"(code {reply.get('code')}: {reply.get('text')})"
    except (ValueError, AttributeError):
        return ""


def drop_routine_searches(lines):
    """(kept lines, number skipped): slapd lines minus routine searches."""
    kept = [line for line in lines if not ROUTINE_LDAP_SEARCH.search(line)]
    return kept, len(lines) - len(kept)


def prepare(lines, sourcetype, args):
    """Group lines into events, first dropping routine LDAP searches unless
    --keep-ldap-searches. Returns (events, a note for the summary line)."""
    note = ""
    if sourcetype == "idlab:slapd" and not args.keep_ldap_searches:
        lines, skipped = drop_routine_searches(lines)
        if skipped:
            note = f" (skipped {skipped} routine LDAP search lines; --keep-ldap-searches keeps them)"
    return group_events(lines, sourcetype), note


def group_events(lines, sourcetype):
    """Join continuation lines onto the line that started their event."""
    start = re.compile(EVENT_START[sourcetype])
    events = []
    for line in lines:
        if events and not start.match(line):
            events[-1] += "\n" + line
        else:
            events.append(line)
    return events


def batches(events, limit=BATCH_BYTES):
    """Newline-joined batches of whole events, each under limit bytes where possible."""
    batch, size = [], 0
    for event in events:
        n = len(event.encode("utf-8")) + 1
        if batch and size + n > limit:
            yield "\n".join(batch) + "\n"
            batch, size = [], 0
        batch.append(event)
        size += n
    if batch:
        yield "\n".join(batch) + "\n"


def docker_ts(line):
    m = _DOCKER_TS.match(line)
    if not m:
        return None
    base = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.UTC)
    return base + dt.timedelta(microseconds=int(m.group(2)) // 1000)


def shift_line(line, delta):
    ts = docker_ts(line)
    if ts is None:
        return line
    nanos = line[20:29]
    shifted = (ts + delta).strftime("%Y-%m-%dT%H:%M:%S.") + f"{(ts + delta).microsecond:06d}" + nanos[6:]
    return shifted + line[29:]


def parse_time(value):
    """ISO 8601 (Z or offset) -> aware datetime."""
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def compose_containers(project, runner=None):
    """{service: container name} for running containers of a compose project."""
    out = (runner or run)(["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
                  "--format", '{{.Names}}\t{{.Label "com.docker.compose.service"}}'])
    if out.returncode != 0:
        raise SenderError(f"docker ps failed: {out.stderr.strip()}")
    found = {}
    for row in out.stdout.splitlines():
        name, _, service = row.partition("\t")
        if service in SERVICES:
            found[service] = name
    return found


def container_lines(name, since, until=None, runner=None):
    """Both streams of `docker logs --timestamps`, merged in time order."""
    cmd = ["docker", "logs", "--timestamps", "--since", since]
    if until:
        cmd += ["--until", until]
    out = (runner or run)(cmd + [name])
    if out.returncode != 0:
        raise SenderError(f"docker logs {name} failed: {out.stderr.strip()}")
    lines = [line for line in (out.stdout + out.stderr).splitlines() if line]
    epoch = dt.datetime.min.replace(tzinfo=dt.UTC)
    return sorted(lines, key=lambda line: docker_ts(line) or epoch)


def report_sourcetype(report, path):
    tool = report.get("tool") if isinstance(report, dict) else None
    if tool not in TOOLS:
        raise SenderError(f"{path}: not a token-inspector or rate-limit-probe --json report")
    return TOOLS[tool]


def report_time(report, path, override=None):
    """When the report was made: a FILE.meta.json "time" (written by capture,
    when the tool was run against the lab), else checked_at (token-inspector,
    which a captured sample may set to the token's own time with --now), else
    override, else now."""
    path = pathlib.Path(path)
    meta = path.with_name(path.name[: -len(".json")] + ".meta.json")
    for value in (json.loads(meta.read_text()).get("time") if meta.exists() else None,
                  report.get("checked_at"),
                  override):
        if value:
            return parse_time(value)
    return dt.datetime.now(dt.UTC)


def load_report(path):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SenderError(f"{path}: cannot read JSON report: {exc}") from None


def cmd_docker(args, hec, out):
    containers = compose_containers(args.project)
    wanted = args.service or sorted(containers)
    missing = [s for s in wanted if s not in containers]
    if missing:
        raise SenderError(f"no running {args.project} container for: {', '.join(missing)}")
    for service in wanted:
        sourcetype = SERVICES[service]
        events, note = prepare(container_lines(containers[service], args.since, args.until), sourcetype, args)
        if not args.dry_run:
            hec.send_raw(events, sourcetype, f"docker:{service}", args.host)
        print(f"{'would send' if args.dry_run else 'sent'} {len(events)} events from {service} as {sourcetype}{note}",
              file=out)


def cmd_report(args, hec, out):
    for path in args.files:
        report = load_report(path)
        sourcetype = report_sourcetype(report, path)
        when = report_time(report, path, args.time)
        if not args.dry_run:
            hec.send_event(report, when.timestamp(), sourcetype, f"report:{pathlib.Path(path).name}", args.host)
        print(f"{'would send' if args.dry_run else 'sent'} {path} as {sourcetype} at {when.isoformat()}", file=out)


def replay_plan(folder):
    """[(kind, path)] for a samples folder: logs/<service>.log and reports/*.json."""
    folder = pathlib.Path(folder)
    logs = sorted((folder / "logs").glob("*.log"))
    reports = sorted(p for p in (folder / "reports").glob("*.json") if not p.name.endswith(".meta.json"))
    if not logs and not reports:
        raise SenderError(f"{folder}: no logs/*.log or reports/*.json to replay")
    unknown = [p.name for p in logs if p.stem not in SERVICES]
    if unknown:
        raise SenderError(f"{folder}/logs: no sourcetype for {', '.join(unknown)} (known: {', '.join(SERVICES)})")
    return logs, reports


def latest_time(logs, reports):
    times = [t for p in logs for line in p.read_text(encoding="utf-8").splitlines() if (t := docker_ts(line))]
    times += [report_time(load_report(p), p) for p in reports]
    return max(times)


def cmd_replay(args, hec, out):
    logs, reports = replay_plan(args.folder)
    delta = dt.timedelta(0)
    if args.shift_to_now:
        # The newest sample lands a minute ago, so "last 15 minutes" panels have data.
        delta = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1) - latest_time(logs, reports)
    for path in logs:
        sourcetype = SERVICES[path.stem]
        lines = [shift_line(line, delta) for line in path.read_text(encoding="utf-8").splitlines() if line]
        events, note = prepare(lines, sourcetype, args)
        if not args.dry_run:
            hec.send_raw(events, sourcetype, f"docker:{path.stem}", args.host)
        print(f"{'would send' if args.dry_run else 'sent'} {len(events)} events from {path.name} as {sourcetype}{note}",
              file=out)
    for path in reports:
        report = load_report(path)
        sourcetype = report_sourcetype(report, path)
        when = report_time(report, path) + delta
        if not args.dry_run:
            hec.send_event(report, when.timestamp(), sourcetype, f"report:{path.name}", args.host)
        print(f"{'would send' if args.dry_run else 'sent'} {path.name} as {sourcetype}", file=out)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hec_send.py",
        description="Ship identity-lab logs and token-inspector / rate-limit-probe reports to Splunk HEC.",
    )
    parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE), help="settings file (default: .env)")
    parser.add_argument("--cacert", metavar="FILE",
                        help="trust this PEM CA for HEC's certificate (preferred); also accepts Splunk's "
                             "default certificates, which fail Python 3.13+ strict mode")
    parser.add_argument("--tls-server-name", metavar="NAME", help="name the certificate is checked against")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification; only for localhost or 127.0.0.1")
    parser.add_argument("--host", default="identity-lab", help="Splunk host field (default: identity-lab)")
    parser.add_argument("--dry-run", action="store_true", help="read and count, send nothing")
    parser.add_argument("--keep-ldap-searches", action="store_true",
                        help="also send the directory's routine search lines (dropped by default)")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("docker", help="ship identity-lab container logs")
    d.add_argument("--project", default="identity-lab", help="compose project name (default: identity-lab)")
    d.add_argument("--service", action="append", choices=sorted(SERVICES), help="only this service; repeatable")
    d.add_argument("--since", default="15m", help="as docker logs --since (default: 15m)")
    d.add_argument("--until", help="as docker logs --until")
    d.set_defaults(func=cmd_docker)

    r = sub.add_parser("report", help="ship token-inspector or rate-limit-probe --json reports")
    r.add_argument("files", nargs="+", metavar="FILE")
    r.add_argument("--time", help="ISO 8601 time for reports that carry none (default: now)")
    r.set_defaults(func=cmd_report)

    p = sub.add_parser("replay", help="ship a samples folder (logs/*.log, reports/*.json)")
    p.add_argument("folder")
    p.add_argument("--shift-to-now", action="store_true", help="move all times so the newest is a minute ago")
    p.set_defaults(func=cmd_replay)
    return parser


def main(argv=None, out=sys.stdout, environ=None):
    args = build_parser().parse_args(argv)
    try:
        hec = None if args.dry_run else HEC(Config.load(args, environ))
        args.func(args, hec, out)
    except SenderError as exc:
        print(f"hec_send: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
