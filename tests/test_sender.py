import datetime as dt
import io
import json
import socket
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import load_module
from tls_helpers import make_ca_and_server, server_context

hec_send = load_module("sender/hec_send.py")

TOKEN = "11111111-2222-3333-4444-555555555555"


class FakeHEC:
    """A loopback HEC that records what it receives and replies with status."""

    def __init__(self, tls=None, status=200):
        self.requests, self.status = [], status
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"])).decode()
                fake.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                reply = {"text": "Success", "code": 0} if fake.status == 200 else {"text": "Invalid token", "code": 4}
                data = json.dumps(reply).encode()
                self.send_response(fake.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def query(self, i=0):
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.requests[i]["path"]).query))


@pytest.fixture
def fake_hec():
    servers = []

    def start(**kwargs):
        servers.append(FakeHEC(**kwargs))
        return servers[-1]

    yield start
    for s in servers:
        s.close()


def env(url, **extra):
    return {"HEC_URL": url, "HEC_TOKEN": TOKEN, **extra}


def send(argv, environ, tmp_path, capfd):
    out = io.StringIO()
    code = hec_send.main(["--env-file", str(tmp_path / "absent.env"), *argv], out=out, environ=environ)
    captured = capfd.readouterr()
    text = out.getvalue() + captured.out + captured.err
    assert TOKEN not in text, "the HEC token was printed"
    return code, text


def write_samples(folder, keycloak_lines=None, report=None):
    (folder / "logs").mkdir(parents=True)
    (folder / "reports").mkdir()
    (folder / "logs/keycloak.log").write_text("\n".join(keycloak_lines or KEYCLOAK) + "\n")
    (folder / "reports/token-inspector-x.json").write_text(json.dumps(report or TI_REPORT))


KEYCLOAK = [
    "2026-10-19T17:40:01.000000001Z 2026-10-19 17:40:01,000 WARN  [org.keycloak.storage.UserStorageManager] "
    "(executor-thread-5) User storage provider idlab-ldap failed during federated user validation",
    "2026-10-19T17:40:01.000000002Z Caused by: javax.naming.AuthenticationException: "
    "[LDAP: error code 49 - Invalid Credentials]",
    "2026-10-19T17:40:01.000000003Z \tat java.naming/com.sun.jndi.ldap.LdapCtx.mapErrorCode(LdapCtx.java:3261)",
    '2026-10-19T17:40:02.500000000Z 2026-10-19 17:40:02,500 WARN  [org.keycloak.events] (executor-thread-5) '
    'type="LOGIN_ERROR", realmName="idlab", clientId="oidc-rp", userId="null", error="user_not_found", username="dave"',
]
TI_REPORT = {"tool": "token-inspector", "checked_at": "2026-10-19T17:41:00Z", "summary": {"fail": 1}}


# --- the token stays secret -------------------------------------------------

def test_secret_never_shows_its_value():
    s = hec_send.Secret(TOKEN)
    assert TOKEN not in repr(s) and TOKEN not in str(s) and TOKEN not in f"{s}"
    assert s.reveal() == TOKEN


def test_token_sent_only_in_the_authorization_header(fake_hec, tmp_path, capfd):
    hec = fake_hec()
    write_samples(tmp_path / "s")
    code, _ = send(["replay", str(tmp_path / "s")], env(f"http://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 0
    for r in hec.requests:
        assert r["headers"]["Authorization"] == f"Splunk {TOKEN}"
        assert TOKEN not in r["path"] and TOKEN not in r["body"]


def test_refused_token_is_reported_without_the_token(fake_hec, tmp_path, capfd):
    hec = fake_hec(status=403)
    write_samples(tmp_path / "s")
    code, text = send(["replay", str(tmp_path / "s")], env(f"http://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 1
    assert "HTTP 403" in text and "Invalid token" in text


def test_unreachable_hec_is_reported_without_the_token(tmp_path, capfd):
    write_samples(tmp_path / "s")
    code, text = send(["replay", str(tmp_path / "s")], env("http://127.0.0.1:9"), tmp_path, capfd)
    assert code == 1 and "cannot reach HEC" in text


def test_dry_run_needs_no_token_and_sends_nothing(tmp_path, capfd):
    write_samples(tmp_path / "s")
    code, text = send(["--dry-run", "replay", str(tmp_path / "s")], {}, tmp_path, capfd)
    assert code == 0 and "would send 2 events from keycloak.log" in text


def test_missing_token_is_a_clear_error(tmp_path, capfd):
    write_samples(tmp_path / "s")
    code, text = send(["replay", str(tmp_path / "s")], {"HEC_URL": "http://127.0.0.1:1"}, tmp_path, capfd)
    assert code == 1 and "HEC_TOKEN is not set" in text


def test_env_file_is_read_and_environment_wins(tmp_path):
    f = tmp_path / ".env"
    f.write_text("# c\nHEC_URL=https://localhost:8088\nHEC_TOKEN='from-file'\nHEC_INDEX=\n")
    args = hec_send.build_parser().parse_args(["--env-file", str(f), "report", "x.json"])
    c = hec_send.Config.load(args, environ={"HEC_URL": "https://127.0.0.1:18088"})
    assert (c.host, c.port, c.token.reveal(), c.index) == ("127.0.0.1", 18088, "from-file", "identity_support")


# --- TLS ---------------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://splunk.example.net:8088", "https://192.0.2.10:8088", "https://[::1]:8088"])
def test_insecure_refused_unless_localhost(url):
    with pytest.raises(hec_send.SenderError, match="only allowed for localhost or 127.0.0.1.*--cacert"):
        hec_send.Config(url, hec_send.Secret(TOKEN), "i", insecure=True)


@pytest.mark.parametrize("url", ["https://localhost:8088", "https://127.0.0.1:18088"])
def test_insecure_allowed_for_localhost(url):
    assert hec_send.Config(url, hec_send.Secret(TOKEN), "i", insecure=True).insecure


def test_insecure_refused_through_the_cli(tmp_path, capfd):
    write_samples(tmp_path / "s")
    code, text = send(["--insecure", "replay", str(tmp_path / "s")],
                      env("https://splunk.example.net:8088"), tmp_path, capfd)
    assert code == 1 and "only allowed for localhost or 127.0.0.1" in text


@pytest.mark.parametrize("url", ["ftp://localhost", "localhost:8088", "https://"])
def test_bad_urls_refused(url):
    with pytest.raises(hec_send.SenderError, match="HEC_URL must be"):
        hec_send.Config(url, hec_send.Secret(TOKEN), "i")


@pytest.fixture
def tls_hec(tmp_path, fake_hec):
    paths = make_ca_and_server(tmp_path, names=("hec.test",), ips=("127.0.0.1",))
    return fake_hec(tls=server_context(paths)), paths


def test_https_with_cacert(tls_hec, tmp_path, capfd):
    hec, paths = tls_hec
    write_samples(tmp_path / "s")
    code, _ = send(["--cacert", str(paths["ca"]), "replay", str(tmp_path / "s")],
                   env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 0 and len(hec.requests) == 2


def test_https_untrusted_certificate_points_at_cacert(tls_hec, tmp_path, capfd):
    hec, _ = tls_hec
    write_samples(tmp_path / "s")
    code, text = send(["replay", str(tmp_path / "s")], env(f"https://localhost:{hec.port}"), tmp_path, capfd)
    assert code == 1 and "not trusted" in text and "--cacert" in text
    assert not hec.requests


def test_https_tls_server_name(tls_hec, tmp_path, capfd):
    hec, paths = tls_hec
    write_samples(tmp_path / "s")
    # The certificate names hec.test, not localhost: refused, then accepted by name.
    code, text = send(["--cacert", str(paths["ca"]), "replay", str(tmp_path / "s")],
                      env(f"https://localhost:{hec.port}"), tmp_path, capfd)
    assert code == 1 and "--tls-server-name" in text
    code, _ = send(["--cacert", str(paths["ca"]), "--tls-server-name", "hec.test", "replay", str(tmp_path / "s")],
                   env(f"https://localhost:{hec.port}"), tmp_path, capfd)
    assert code == 0


def test_https_insecure_on_localhost(tls_hec, tmp_path, capfd):
    hec, _ = tls_hec
    write_samples(tmp_path / "s")
    code, _ = send(["--insecure", "replay", str(tmp_path / "s")],
                   env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 0


# --- what is sent ------------------------------------------------------------

def test_raw_logs_go_to_the_raw_endpoint_with_metadata(fake_hec, tmp_path, capfd):
    hec = fake_hec()
    write_samples(tmp_path / "s")
    send(["replay", str(tmp_path / "s")], env(f"http://127.0.0.1:{hec.port}", HEC_INDEX="idx"), tmp_path, capfd)
    raw = hec.requests[0]
    assert raw["path"].startswith("/services/collector/raw?")
    assert hec.query(0) == {"sourcetype": "idlab:keycloak", "source": "docker:keycloak",
                            "host": "identity-lab", "index": "idx"}
    assert raw["headers"]["X-Splunk-Request-Channel"]
    assert raw["body"] == "\n".join(KEYCLOAK) + "\n"


def test_reports_go_to_the_event_endpoint_with_their_time(fake_hec, tmp_path, capfd):
    hec = fake_hec()
    write_samples(tmp_path / "s")
    send(["replay", str(tmp_path / "s")], env(f"http://127.0.0.1:{hec.port}"), tmp_path, capfd)
    event = hec.requests[1]
    assert event["path"] == "/services/collector/event"
    payload = json.loads(event["body"])
    assert payload["sourcetype"] == "token_inspector:report"
    assert payload["time"] == dt.datetime(2026, 10, 19, 17, 41, tzinfo=dt.UTC).timestamp()
    assert payload["event"] == TI_REPORT


def test_keycloak_stack_trace_stays_one_event():
    events = hec_send.group_events(KEYCLOAK, "idlab:keycloak")
    assert len(events) == 2
    assert "error code 49" in events[0] and events[0].count("\n") == 2


def test_sp_events_start_at_app_gunicorn_and_access_lines():
    lines = [
        "2026-10-08T16:55:12.805000000Z 2026-10-08 17:05:12,804 WARNING saml-sp event=saml_login_failed",
        "2026-10-08T16:55:12.806000000Z Traceback (most recent call last):",
        '2026-10-08T16:55:12.806000001Z   File "/app/app.py", line 1, in x',
        "2026-10-19T17:26:03.000000000Z [2026-10-19 17:26:03 +0000] [1] [INFO] Starting gunicorn 26.2.0",
        '2026-10-19T17:32:17.000671924Z 127.0.0.1 - - [19/Oct/2026:17:32:17 +0000] "GET /x HTTP/1.1" 200 16',
    ]
    assert [e.count("\n") for e in hec_send.group_events(lines, "idlab:sp")] == [2, 0, 0]


def test_batches_never_split_an_event():
    events = ["a" * 40 + "\n" + "b" * 40, "c" * 60, "d" * 10]
    out = list(hec_send.batches(events, limit=100))
    assert out == [events[0] + "\n", events[1] + "\n" + events[2] + "\n"]
    assert "".join(out) == "\n".join(events) + "\n"


def test_shift_moves_the_docker_timestamp_only():
    line = "2026-10-19T17:40:01.123456789Z 2026-10-19 17:40:01,123 WARN x"
    out = hec_send.shift_line(line, dt.timedelta(days=1, seconds=30))
    assert out == "2026-10-20T17:40:31.123456789Z 2026-10-19 17:40:01,123 WARN x"
    assert hec_send.shift_line("no timestamp", dt.timedelta(1)) == "no timestamp"


def test_replay_shift_to_now_puts_the_newest_event_a_minute_ago(fake_hec, tmp_path, capfd):
    hec = fake_hec()
    write_samples(tmp_path / "s")
    before = dt.datetime.now(dt.UTC)
    send(["replay", "--shift-to-now", str(tmp_path / "s")], env(f"http://127.0.0.1:{hec.port}"), tmp_path, capfd)
    lines = hec.requests[0]["body"].splitlines()
    newest = max(hec_send.docker_ts(line) for line in lines if hec_send.docker_ts(line))
    report_time = json.loads(hec.requests[1]["body"])["time"]
    # The report is the newest item in the sample, so it lands a minute ago...
    expected = before - dt.timedelta(minutes=1)
    assert abs(report_time - expected.timestamp()) < 5
    # ...and stays 57.5 s after the last log line, as in the sample.
    assert abs(report_time - newest.timestamp() - 57.5) < 0.01


def test_replay_rejects_unknown_log_names(tmp_path, capfd):
    (tmp_path / "s/logs").mkdir(parents=True)
    (tmp_path / "s/logs/postgres.log").write_text("x\n")
    code, text = send(["--dry-run", "replay", str(tmp_path / "s")], {}, tmp_path, capfd)
    assert code == 1 and "no sourcetype for postgres.log" in text


def test_report_time_prefers_sidecar_then_checked_at_then_option(tmp_path):
    p = tmp_path / "token-inspector-x.json"
    option = "2026-01-01T00:00:00Z"
    assert hec_send.report_time({}, p, option) == dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    assert hec_send.report_time(TI_REPORT, p, option) == dt.datetime(2026, 10, 19, 17, 41, tzinfo=dt.UTC)
    (tmp_path / "token-inspector-x.meta.json").write_text('{"time": "2026-10-19T18:00:00+00:00"}')
    assert hec_send.report_time(TI_REPORT, p, option) == dt.datetime(2026, 10, 19, 18, tzinfo=dt.UTC)


def test_report_command_rejects_other_json(tmp_path, capfd):
    (tmp_path / "x.json").write_text('{"tool": "something-else"}')
    code, text = send(["--dry-run", "report", str(tmp_path / "x.json")], {}, tmp_path, capfd)
    assert code == 1 and "not a token-inspector or rate-limit-probe" in text


# --- docker ------------------------------------------------------------------

def fake_docker(calls):
    def runner(cmd):
        calls.append(cmd)
        if cmd[1] == "ps":
            out = "identity-lab-keycloak-1\tkeycloak\nidentity-lab-postgres-1\tpostgres\nidentity-lab-nas-1\tnas\n"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        # stdout and stderr interleave by time
        return subprocess.CompletedProcess(cmd, 0, KEYCLOAK[0] + "\n" + KEYCLOAK[3] + "\n",
                                           KEYCLOAK[1] + "\n" + KEYCLOAK[2] + "\n")
    return runner


def test_compose_containers_keeps_known_services():
    assert hec_send.compose_containers("identity-lab", runner=fake_docker([])) == {
        "keycloak": "identity-lab-keycloak-1", "nas": "identity-lab-nas-1"}


def test_container_lines_merges_streams_in_time_order():
    calls = []
    lines = hec_send.container_lines("identity-lab-keycloak-1", "15m", "2026-10-19T18:00:00Z",
                                     runner=fake_docker(calls))
    assert lines == KEYCLOAK
    assert calls[0] == ["docker", "logs", "--timestamps", "--since", "15m", "--until", "2026-10-19T18:00:00Z",
                        "identity-lab-keycloak-1"]


def test_docker_command_ships_each_service(fake_hec, tmp_path, capfd, monkeypatch):
    monkeypatch.setattr(hec_send, "run", fake_docker([]))
    hec = fake_hec()
    code, text = send(["docker", "--service", "keycloak"], env(f"http://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 0 and "sent 2 events from keycloak" in text
    assert hec.query(0)["sourcetype"] == "idlab:keycloak"


def test_docker_command_names_missing_services(tmp_path, capfd, monkeypatch):
    monkeypatch.setattr(hec_send, "run", fake_docker([]))
    code, text = send(["--dry-run", "docker", "--service", "radius"], {}, tmp_path, capfd)
    assert code == 1 and "no running identity-lab container for: radius" in text


# --- Splunk's default certificate and Python's strict mode -------------------

STRICT_BY_DEFAULT = bool(ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT)


@pytest.fixture
def no_aki_hec(tmp_path, fake_hec):
    """A HEC whose certificate, like Splunk's older default ones, has no
    Authority Key Identifier and names no host we connect to."""
    paths = make_ca_and_server(tmp_path, names=("SplunkServerDefaultCert",), ips=(), authority_key_id=False)
    return fake_hec(tls=server_context(paths)), paths


@pytest.mark.skipif(not STRICT_BY_DEFAULT, reason="this Python does not verify strictly by default")
def test_strict_mode_really_rejects_a_certificate_without_aki(no_aki_hec):
    """Proves the fixture reproduces the problem: Python's own default
    context, given the right CA and name, still refuses this certificate."""
    hec, paths = no_aki_hec
    ctx = ssl.create_default_context(cafile=str(paths["ca"]))
    with socket.create_connection(("127.0.0.1", hec.port)) as sock:
        with pytest.raises(ssl.SSLCertVerificationError, match="Authority Key Identifier"):
            ctx.wrap_socket(sock, server_hostname="SplunkServerDefaultCert")


def test_certificate_without_aki_fails_without_cacert(no_aki_hec, tmp_path, capfd):
    hec, _ = no_aki_hec
    write_samples(tmp_path / "s")
    code, text = send(["--tls-server-name", "SplunkServerDefaultCert", "replay", str(tmp_path / "s")],
                      env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 1 and "not trusted" in text and not hec.requests


def test_certificate_without_aki_passes_with_cacert(no_aki_hec, tmp_path, capfd):
    hec, paths = no_aki_hec
    write_samples(tmp_path / "s")
    code, _ = send(["--cacert", str(paths["ca"]), "--tls-server-name", "SplunkServerDefaultCert",
                    "replay", str(tmp_path / "s")], env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 0 and len(hec.requests) == 2


def test_hostname_is_still_checked_with_cacert(no_aki_hec, tmp_path, capfd):
    hec, paths = no_aki_hec
    write_samples(tmp_path / "s")
    for name in ([], ["--tls-server-name", "wrong.example.net"]):
        code, text = send(["--cacert", str(paths["ca"]), *name, "replay", str(tmp_path / "s")],
                          env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
        assert code == 1 and "not trusted" in text and "mismatch" in text
    assert not hec.requests


def test_chain_is_still_verified_with_cacert(no_aki_hec, tmp_path, capfd):
    hec, _ = no_aki_hec
    (tmp_path / "other").mkdir()
    other = make_ca_and_server(tmp_path / "other")
    write_samples(tmp_path / "s")
    code, text = send(["--cacert", str(other["ca"]), "--tls-server-name", "SplunkServerDefaultCert",
                       "replay", str(tmp_path / "s")], env(f"https://127.0.0.1:{hec.port}"), tmp_path, capfd)
    assert code == 1 and "not trusted" in text and not hec.requests


def test_only_the_strict_flag_is_cleared_and_only_with_cacert(tmp_path):
    default = ssl.create_default_context()
    plain = hec_send.Config("https://127.0.0.1:8088", hec_send.Secret(TOKEN), "i").ssl_context()
    assert plain.verify_flags == default.verify_flags          # untouched without --cacert
    paths = make_ca_and_server(tmp_path)
    ctx = hec_send.Config("https://127.0.0.1:8088", hec_send.Secret(TOKEN), "i", cacert=str(paths["ca"])).ssl_context()
    assert ctx.verify_flags == default.verify_flags & ~ssl.VERIFY_X509_STRICT
    assert ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED
