import io
import json
import subprocess

import pytest

from conftest import load_script

capture = load_script("capture_lab")

# Built at run time so the hygiene test never sees a private address here.
LAB_IP = "172.30" + ".181.10"
KEYCLOAK_LOG = (
    "2026-10-19T18:30:00.200000000Z 2026-10-19 18:30:00,200 WARN  [org.keycloak.events] (t) "
    f'type="LOGIN_ERROR", clientId="oidc-rp", ipAddress="{LAB_IP}", error="user_not_found", username="dave"\n'
)
LDAP_LOG = (
    "2026-10-19T18:30:01.000000000Z x y conn=7 op=0 BIND dn=\"\" method=128\n"
    "2026-10-19T18:30:01.000100000Z x y conn=7 op=0 RESULT tag=97 err=0 qtime=0 etime=0 text=\n"
)

# The proxy's access log is on stdout and its error log on stderr.
PROXY_OUT = (f'2026-10-19T18:31:00.000100000Z {LAB_IP} "GET / HTTP/1.1" 502 552 host=rp.idlab.example:8185 '
             "upstream=192.0.2.32:8182 upstream_status=502 request_time=0.002 upstream_time=0.002\n")
PROXY_ERR = ("2026-10-19T18:31:00.000000000Z 2026/10/19 18:31:00 [error] 184#184: *69 upstream prematurely closed "
             f'connection while reading response header from upstream, client: {LAB_IP}, server: , request: "GET / HTTP/1.1"\n')

# Squid's access log is on stdout; cache.log, with its indented detail
# lines, on stderr.
SQUID_OUT = (f"2026-10-19T18:32:00.000000000Z 1792434720.000     25 {LAB_IP} NONE_NONE/200 0 CONNECT keycloak:8180 "
             f"- HIER_DIRECT/{LAB_IP} -\n")
SQUID_ERR = ("2026-10-19T18:32:00.001000000Z 2026/10/19 18:32:00| ERROR: Cannot accept a TLS connection\n"
             "2026-10-19T18:32:00.001100000Z     error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000418+TLS_IO_ERR=1\n")

# The RP behind the proxy's :8187 route, and the API it calls.
EDGE_LOG = ("2026-10-22T08:44:57.240000000Z 2026-10-22 08:44:57,240 INFO oidc-rp event=force_https path=/ "
            "scheme=http x_forwarded_proto=-\n"
            f'2026-10-22T08:44:57.240100000Z {LAB_IP} - - [22/Oct/2026:08:44:57 +0000] "GET / HTTP/1.1" 302 235 "-" "curl/8.18.0"\n')
API_LOG = ("2026-10-22T08:51:43.568000000Z 2026-10-22 08:51:43,568 WARNING api event=api_token_rejected "
           "error=invalid_token error_description='The access token expired at 2026-10-22T08:52:26Z' "
           "sub=e52e5f3f-8b98-4f7d-935e-3fa7bbacb59f azp=oidc-rp aud='idlab-api account' "
           "iss=https://idlab.home:8180/realms/idlab exp=2026-10-22T08:52:26Z\n"
           f'2026-10-22T08:51:43.568100000Z {LAB_IP} - - [22/Oct/2026:08:51:43 +0000] "GET /v1/whoami HTTP/1.1" 401 97 "-" "python-requests/2.34.2"\n')


class FakeSystem:
    """Answers docker, token-inspector and rate-limit-probe; records every command."""

    def __init__(self):
        self.calls = []

    def __call__(self, cmd, cwd=None):
        self.calls.append(cmd)
        ok = lambda out, err="": subprocess.CompletedProcess(cmd, 0, out, err)  # noqa: E731
        if cmd[:2] == ["docker", "ps"]:
            return ok("identity-lab-keycloak-1\tkeycloak\nidentity-lab-ldap-1\tldap\n"
                      "identity-lab-nas-1\tnas\nidentity-lab-postgres-1\tpostgres\n"
                      "identity-lab-proxy-1\tproxy\nidentity-lab-saml-sp-proxied-1\tsaml-sp-proxied\n"
                      "identity-lab-squid-1\tsquid\nidentity-lab-oidc-rp-egress-1\toidc-rp-egress\n"
                      "identity-lab-oidc-rp-edge-1\toidc-rp-edge\nidentity-lab-api-1\tapi\n")
        if cmd[:2] == ["docker", "logs"] and cmd[-1] == "identity-lab-proxy-1":
            return ok(PROXY_OUT, PROXY_ERR)
        if cmd[:2] == ["docker", "logs"] and cmd[-1] == "identity-lab-squid-1":
            return ok(SQUID_OUT, SQUID_ERR)
        if cmd[:2] == ["docker", "logs"]:
            return ok({"identity-lab-keycloak-1": KEYCLOAK_LOG, "identity-lab-ldap-1": LDAP_LOG,
                       "identity-lab-oidc-rp-edge-1": EDGE_LOG, "identity-lab-api-1": API_LOG}.get(cmd[-1], ""))
        if cmd[0].endswith("token-inspector"):
            return subprocess.CompletedProcess(cmd, 1, json.dumps({"tool": "token-inspector", "args": cmd[2:]}), "")
        if cmd[0].endswith("rate-limit-probe"):
            return ok(json.dumps({"tool": "rate-limit-probe", "demo": cmd[2]}))
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(capture.sanitise, "PERSONAL_FILE", tmp_path / "absent")
    ti = tmp_path / "token-inspector"
    (ti / "samples/lab/baseline").mkdir(parents=True)
    (ti / "samples/lab/baseline/saml-response.xml").write_text("<x/>")
    (ti / "samples/lab/baseline/saml-response.xml.meta.json").write_text(
        json.dumps({"args": ["--metadata", "{dir}/idp-metadata.xml", "--now", "2026-10-17T11:29:17Z"]}))
    return {
        "argv": ["--token-inspector", str(ti), "--rate-limit-probe", str(tmp_path / "rlp"),
                 "--raw", str(tmp_path / "raw"), "--out", str(tmp_path / "samples")],
        "tmp": tmp_path, "ti": ti,
    }


def test_interactive_run_prints_the_command_and_waits(setup):
    system, out, asked = FakeSystem(), io.StringIO(), []
    code = capture.main(setup["argv"], out=out, ask=lambda prompt: asked.append(prompt), runner=system)
    assert code == 0
    text = out.getvalue()
    assert "scripts/test.sh" in text and "identity-lab" in text and "--fresh" in text
    assert asked and "Press Enter" in asked[0]
    meta = json.loads((setup["tmp"] / "samples/capture.json").read_text())
    assert meta["since"] <= meta["until"]


def test_never_changes_the_lab(setup):
    system = FakeSystem()
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--until", "2026-10-19T19:00:00Z"],
                 out=io.StringIO(), runner=system)
    kinds = {tuple(c[:2]) if c[0] == "docker" else (c[0].rsplit("/", 1)[-1],) for c in system.calls}
    assert kinds == {("docker", "ps"), ("docker", "logs"), ("token-inspector",), ("rate-limit-probe",)}
    for cmd in system.calls:
        assert not any(word in " ".join(cmd) for word in ("break", "fix.sh", "test.sh", "exec", "nas-auth"))


def test_window_goes_to_docker_logs(setup):
    system = FakeSystem()
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--until", "2026-10-19T19:00:00+00:00"],
                 out=io.StringIO(), runner=system)
    logs = [c for c in system.calls if c[:2] == ["docker", "logs"]]
    assert logs and all(c[4:8] == ["2026-10-19T18:00:00Z", "--until", "2026-10-19T19:00:00Z", c[-1]] for c in logs)
    assert "identity-lab-postgres-1" not in {c[-1] for c in logs}


def test_samples_are_sanitised_and_empty_logs_skipped(setup):
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z"], out=io.StringIO(), runner=FakeSystem())
    samples = setup["tmp"] / "samples"
    keycloak = (samples / "logs/keycloak.log").read_text()
    assert LAB_IP not in keycloak and 'ipAddress="192.0.2.10"' in keycloak
    assert not (samples / "logs/nas.log").exists()          # nothing logged
    assert not (samples / "logs/ldap.log").exists()         # only health-check binds, trimmed away
    assert LAB_IP in (setup["tmp"] / "raw/logs/keycloak.log").read_text()  # raw stays raw, and gitignored


def test_proxy_logs_both_streams_in_time_order(setup):
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--no-tools"], out=io.StringIO(), runner=FakeSystem())
    proxy = (setup["tmp"] / "samples/logs/proxy.log").read_text().splitlines()
    assert "[error]" in proxy[0] and " 502 " in proxy[1]
    assert LAB_IP not in "".join(proxy)
    meta = json.loads((setup["tmp"] / "samples/capture.json").read_text())
    assert meta["lines"]["proxy"] == 2 and meta["lines"]["saml-sp-proxied"] == 0


def test_squid_logs_both_streams_in_time_order(setup):
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--no-tools"], out=io.StringIO(), runner=FakeSystem())
    squid = (setup["tmp"] / "samples/logs/squid.log").read_text().splitlines()
    assert "NONE_NONE/200" in squid[0] and "ERROR: Cannot accept" in squid[1] and "A000418" in squid[2]
    assert LAB_IP not in "".join(squid)
    meta = json.loads((setup["tmp"] / "samples/capture.json").read_text())
    assert meta["lines"]["squid"] == 3 and meta["lines"]["oidc-rp-egress"] == 0


def test_edge_rp_and_api_are_collected(setup):
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--no-tools"], out=io.StringIO(), runner=FakeSystem())
    edge = (setup["tmp"] / "samples/logs/oidc-rp-edge.log").read_text()
    api = (setup["tmp"] / "samples/logs/api.log").read_text()
    assert "event=force_https" in edge and "event=api_token_rejected" in api
    assert LAB_IP not in edge + api
    meta = json.loads((setup["tmp"] / "samples/capture.json").read_text())
    assert meta["lines"]["oidc-rp-edge"] == 2 and meta["lines"]["api"] == 2


def test_tool_reports_with_their_arguments_and_time(setup):
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--until", "2026-10-19T19:00:00Z"],
                 out=io.StringIO(), runner=FakeSystem())
    reports = setup["tmp"] / "samples/reports"
    ti = json.loads((reports / "token-inspector-baseline-saml-response.json").read_text())
    sample_dir = str(setup["ti"] / "samples/lab/baseline")
    # the {dir} placeholder was filled in; the sanitiser then rewrites the home directory
    assert ti["args"][:2] == ["--metadata", capture.sanitise.HOME_DIR.sub("~", sample_dir) + "/idp-metadata.xml"]
    assert json.loads((reports / "token-inspector-baseline-saml-response.meta.json").read_text()) == {
        "time": "2026-10-19T19:00:00Z"}
    assert sorted(p.name for p in reports.glob("rate-limit-probe-*.json") if "meta" not in p.name) == [
        f"rate-limit-probe-{d}.json" for d in sorted(capture.RATE_LIMIT_DEMOS)]


def test_no_tools_collects_logs_only(setup):
    system = FakeSystem()
    capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z", "--no-tools"], out=io.StringIO(), runner=system)
    assert all(c[0] == "docker" for c in system.calls)
    assert not (setup["tmp"] / "samples/reports").exists()


def test_abandoning_collects_nothing(setup, capsys):
    def interrupt(prompt):
        raise KeyboardInterrupt
    system = FakeSystem()
    assert capture.main(setup["argv"], out=io.StringIO(), ask=interrupt, runner=system) == 1
    assert not system.calls and "nothing collected" in capsys.readouterr().err


@pytest.mark.parametrize("extra, message", [
    (["--until", "2026-10-19T19:00:00Z"], "--until needs --since"),
    (["--since", "2026-10-19T19:00:00Z", "--until", "2026-10-19T18:00:00Z"], "must be after"),
])
def test_bad_windows(setup, capsys, extra, message):
    assert capture.main(setup["argv"] + extra, out=io.StringIO(), runner=FakeSystem()) == 2
    assert message in capsys.readouterr().err


def test_time_needs_a_zone(setup):
    with pytest.raises(SystemExit):
        capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00"], out=io.StringIO(), runner=FakeSystem())


def test_no_lab_running_is_a_clear_error(setup, capsys):
    def nothing(cmd, cwd=None):
        return subprocess.CompletedProcess(cmd, 0, "", "")
    assert capture.main(setup["argv"] + ["--since", "2026-10-19T18:00:00Z"], out=io.StringIO(), runner=nothing) == 1
    assert "no running containers" in capsys.readouterr().err
