"""Checks that need a real Splunk: timestamps, line breaking after indexing,
calculated fields, eventtypes, tags, the causes lookup and the macros.

Skipped unless these point at a local test Splunk with the app installed
(the reviewer stack, or any throwaway instance; never a production one):

    SUPPORT_SPLUNK_MGMT=https://127.0.0.1:18089   management port
    SUPPORT_SPLUNK_PASSWORD=...                    admin password
    SUPPORT_HEC_URL=https://127.0.0.1:18088
    SUPPORT_HEC_TOKEN=...                          allowed to write identity_support

Only loopback addresses are accepted, and TLS verification is off for that
reason alone. The fixtures are replayed under a unique host each run, so
runs never see each other's events.
"""

import base64
import json
import os
import ssl
import time
import urllib.parse
import urllib.request
import uuid

import pytest

from conftest import ROOT, is_loopback, load_module

hec_send = load_module("sender/hec_send.py")

MGMT = os.environ.get("SUPPORT_SPLUNK_MGMT")
NEEDED = ("SUPPORT_SPLUNK_MGMT", "SUPPORT_SPLUNK_PASSWORD", "SUPPORT_HEC_URL", "SUPPORT_HEC_TOKEN")
pytestmark = pytest.mark.skipif(not all(os.environ.get(n) for n in NEEDED),
                                reason="no local test Splunk (set " + ", ".join(NEEDED) + ")")

# Events the fixtures should produce once indexed: the healthz line is dropped.
# The proxy's lines are all typed access or error at index time.
EXPECTED = {"idlab:keycloak": 6, "idlab:sp": 16, "idlab:radius": 7, "idlab:nas": 4, "idlab:slapd": 6,
            "idlab:nginx:access": 7, "idlab:nginx:error": 7,
            "token_inspector:report": 1, "rate_limit_probe:report": 1}


def search(spl):
    """Run a search to completion; return its result rows."""
    host = urllib.parse.urlsplit(MGMT).hostname
    assert is_loopback(host), "live tests only talk to a local Splunk"
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    auth = base64.b64encode(f"admin:{os.environ['SUPPORT_SPLUNK_PASSWORD']}".encode()).decode()
    body = urllib.parse.urlencode({"search": "search " + spl, "output_mode": "json", "exec_mode": "oneshot",
                                   "earliest_time": "0", "latest_time": "+7d", "count": "0"}).encode()
    req = urllib.request.Request(MGMT + "/services/search/jobs", data=body,
                                 headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
        return json.loads(r.read())["results"]


@pytest.fixture(scope="module")
def host():
    """Replay the fixtures once, under a fresh host, and wait for them."""
    name = f"live-test-{uuid.uuid4().hex[:8]}"
    environ = {"HEC_URL": os.environ["SUPPORT_HEC_URL"], "HEC_TOKEN": os.environ["SUPPORT_HEC_TOKEN"]}
    code = hec_send.main(["--env-file", "/nonexistent", "--insecure", "--host", name,
                          "replay", str(ROOT / "tests/fixtures/lab")], environ=environ)
    assert code == 0
    deadline = time.time() + 120
    while time.time() < deadline:
        rows = search(f"`support_index` host={name} | stats count by sourcetype")
        if {r["sourcetype"]: int(r["count"]) for r in rows} == EXPECTED:
            return name
        time.sleep(3)
    pytest.fail(f"indexed events never matched {EXPECTED}: {rows}")


def one(host, spl):
    # An event search over the REST API only returns the fields it names: table them all.
    rows = search(f"`support_index` host={host} {spl} | table *")
    assert len(rows) == 1, rows
    return rows[0]


def test_time_is_dockers_timestamp(host):
    row = one(host, 'sourcetype=idlab:slapd conn=1027 "RESULT tag=97" | eval t=strftime(_time, "%Y-%m-%dT%H:%M:%S.%6N")')
    assert row["t"] == "2026-10-19T18:30:00.000200"


def test_stack_trace_indexed_as_one_event(host):
    row = one(host, "sourcetype=idlab:keycloak UserStorageManager | eval lines=mvcount(split(_raw, \"\n\"))")
    assert row["lines"] == "4" and row["ldap_result_code"] == "49"


def test_keycloak_ldap_error_cause(host):
    row = one(host, "eventtype=idlab_keycloak_ldap_error")
    assert (row["signature"], row["runbook"]) == ("ldap_bind_49", "04-ldap-bind-failure")


def test_keycloak_login_error_is_cim_authentication(host):
    row = one(host, 'tag=authentication sourcetype=idlab:keycloak kc_error=user_not_found')
    assert (row["action"], row["app"], row["user"], row["src"], row["dest"]) == (
        "failure", "oidc-rp", "dave", "192.0.2.10", "keycloak")
    assert row["signature"] == "kc_user_not_found" and row["runbook"] == "04-ldap-bind-failure"


def test_redirect_uri_cause(host):
    row = one(host, "signature=kc_invalid_redirect_uri")
    assert row["runbook"] == "03-redirect-uri-mismatch" and "user" not in row


@pytest.mark.parametrize("contains, signature, runbook", [
    ("idp_cert_expired", "saml_idp_cert_expired", "01-expired-signing-cert"),
    ("validate timestamp", "saml_clock_skew", "02-clock-skew"),
])
def test_sp_failure_causes(host, contains, signature, runbook):
    row = one(host, f'sourcetype=idlab:sp "{contains}"')
    assert (row["action"], row["app"], row["signature"], row["runbook"]) == ("failure", "saml-sp", signature, runbook)
    assert row["runbook_url"].endswith(f"/runbooks/{runbook}.md")


def test_sp_failure_without_a_known_cause_keeps_its_reason(host):
    row = one(host, "sourcetype=idlab:sp source=docker:oidc-rp event=oidc_login_failed")
    assert row["signature"] == "oidc-rp:token_validation_failed" and "cause" not in row


def test_sp_login_ok_user(host):
    rows = search(f"`support_index` host={host} tag=authentication action=success sourcetype=idlab:sp | sort user app | table app user")
    assert [(r["app"], r["user"]) for r in rows] == [
        ("saml-sp", "alice@idlab.example"), ("saml-sp-proxied", "alice@idlab.example"), ("oidc-rp", "dave@idlab.example")]


def test_proxied_app_failure_names_the_proxied_copy(host):
    row = one(host, "sourcetype=idlab:sp source=docker:oidc-rp-proxied event=oidc_login_failed")
    assert (row["action"], row["app"], row["dest"], row["signature"]) == (
        "failure", "oidc-rp-proxied", "oidc-rp-proxied", "oidc-rp:token_exchange_failed")


def test_radius_reject_versus_no_reply(host):
    rows = search(f"`support_index` host={host} (sourcetype=idlab:radius OR sourcetype=idlab:nas) "
                  "| stats count by sourcetype radius_outcome")
    got = {(r["sourcetype"], r["radius_outcome"]): r["count"] for r in rows}
    assert got == {("idlab:radius", "Access-Accept"): "1", ("idlab:radius", "Access-Reject"): "1",
                   ("idlab:radius", "no reply"): "4", ("idlab:nas", "no reply"): "1", ("idlab:nas", "Access-Reject"): "1"}


def test_radius_dropped_packets_point_at_the_shared_secret(host):
    rows = search(f"`support_index` host={host} eventtype=idlab_radius_no_reply | stats count by signature runbook")
    got = {r["signature"]: (r["count"], r["runbook"]) for r in rows}
    assert got["radius_bad_shared_secret"] == ("3", "05-radius-shared-secret-mismatch")
    assert got["radius_unknown_client"][0] == "1" and got["nas_no_reply"][0] == "1"


def test_every_radius_failure_has_an_app(host):
    rows = search(f"`support_index` host={host} (eventtype=idlab_radius_no_reply OR eventtype=idlab_radius_auth) "
                  "| fillnull value=MISSING app | stats count by sourcetype app")
    assert {(r["sourcetype"], r["app"]) for r in rows} == {("idlab:radius", "radius"), ("idlab:nas", "radius")}


def test_ldap_result_49_is_an_authentication_failure(host):
    rows = search(f"`support_index` host={host} tag=authentication sourcetype=idlab:slapd | table action err signature")
    assert [(r["action"], r["err"], r["signature"]) for r in rows] == [("failure", "49", "ldap_bind_49")] * 2


def test_failures_macro(host):
    rows = search(f"`support_failures` host={host} | stats count by signature")
    assert {r["signature"] for r in rows} == {
        "kc_invalid_redirect_uri", "ldap_bind_49", "kc_user_not_found", "kc_invalid_user_credentials",
        "saml_idp_cert_expired", "saml_clock_skew", "oidc-rp:token_validation_failed",
        "radius_reject_bad_password", "radius_bad_shared_secret", "radius_unknown_client", "nas_no_reply",
        "oidc-rp:token_exchange_failed", "kc_invalid_destination", "proxy_upstream_closed", "proxy_upstream_timeout",
        "proxy_rate_limited", "proxy_header_too_large"}


def test_proxy_access_is_cim_web(host):
    row = one(host, 'tag=web status=504')
    assert (row["sourcetype"], row["src"], row["http_method"], row["uri_path"], row["dest"]) == (
        "idlab:nginx:access", "192.0.2.10", "GET", "/auth/callback", "proxy")
    assert (row["duration"], row["upstream_response_time"]) == ("5.005", "5.004")


def test_proxy_upstream_time_is_the_last_upstream_tried(host):
    row = one(host, 'sourcetype=idlab:nginx:access "upstream_status=502, 200"')
    assert (row["upstream_status"], row["upstream_response_time"]) == ("502, 200", "0.011")
    row = one(host, "sourcetype=idlab:nginx:access status=429")
    assert row["upstream"] == "-" and "upstream_response_time" not in row


def test_proxy_error_causes(host):
    rows = search(f"`support_index` host={host} eventtype=idlab_proxy_error | stats count by signature runbook app")
    got = {r["signature"]: (r["runbook"], r["app"]) for r in rows}
    assert got == {
        "proxy_upstream_closed": ("06-proxy-bad-gateway", "proxy rp.idlab.example:8185"),
        "proxy_upstream_timeout": ("07-proxy-gateway-timeout", "proxy rp.idlab.example:8185"),
        "proxy_rate_limited": ("08-proxy-rate-limit", "proxy idp.idlab.example:8183"),
        # nginx cut this line before its host
        "proxy_header_too_large": ("10-proxy-header-too-large", "proxy"),
    }
    assert all(r["count"] == "1" for r in rows)


def test_proxy_notices_are_not_failures(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:nginx:error log_level=notice | stats count(signature) as n count")
    assert rows == [{"n": "0", "count": "3"}]


def test_forwarded_headers_point_at_the_proxy(host):
    row = one(host, "signature=kc_invalid_destination")
    assert (row["action"], row["kc_reason"], row["runbook"]) == ("failure", "invalid_destination", "09-proxy-forwarded-headers")
    assert row["cause"].startswith("Reverse proxy is the likely cause")


def alert_query(host, name, threshold=None):
    """A saved search's SPL limited to this run's host (the alert's own time window is not applied)."""
    from splunk_conf import read_conf
    spl = read_conf("savedsearches.conf")[name]["search"].replace("`support_index`", f"`support_index` host={host}", 1)
    return spl.replace(">= 3", f">= {threshold}") if threshold else spl


def test_proxy_spike_alert(host):
    [row] = search(alert_query(host, "Reverse proxy 502/504 spike"))
    assert row["responses"] == "3" and set(row["statuses"]) == {"502", "504"}
    assert {u.rsplit("/", 1)[-1] for u in row["runbook_url"]} == {
        "06-proxy-bad-gateway.md", "07-proxy-gateway-timeout.md", "10-proxy-header-too-large.md"}
    assert set(row["routes"]) == {"rp.idlab.example:8185", "idp.idlab.example:8183"}


def test_proxy_spike_alert_quiet_below_its_threshold(host):
    assert search(alert_query(host, "Reverse proxy 502/504 spike", threshold=4)) == []


def test_proxy_rate_limit_alert(host):
    assert search(alert_query(host, "Reverse proxy rate limiting logins")) == []  # one 429 is not enough
    [row] = search(alert_query(host, "Reverse proxy rate limiting logins", threshold=1))
    assert (row["count"], row["clients"], row["zones"], row["routes"]) == ("1", "1", "kc_login", "idp.idlab.example:8183")
    assert row["runbook_url"].endswith("/08-proxy-rate-limit.md")


def test_token_inspector_report_fields(host):
    row = one(host, "eventtype=idlab_token_inspector")
    assert row["verdict"].startswith("1 problem to fix")
    assert row["likely_cause"] == "the IdP rotated its signing key"
    assert row["runbook_url"].endswith("/01-expired-signing-cert.md")


def test_rate_limit_probe_report_fields(host):
    row = one(host, "eventtype=idlab_rate_limit_probe")
    assert (row["status_429"], row["likely_cause"]) == ("2", "requests during the wait restart it")


def overview_query(host, name):
    """A Support overview data source as the dashboard runs it, limited to this run's host."""
    import xml.etree.ElementTree as ET
    view = ROOT / "identity_support/default/data/ui/views/support_overview.xml"
    sources = json.loads(ET.parse(view).getroot().findtext("definition"))["dataSources"]

    def full(n):
        s = sources[n]
        return full(s["options"]["extend"]) + " " + s["options"]["query"] if s["type"] == "ds.chain" else s["options"]["query"]
    q = full(name)
    q = q.replace("(`support_failures`)", f"(`support_failures` host={host})", 1)
    q = q.replace("(`support_index` sourcetype=idlab:slapd", f"(`support_index` host={host} sourcetype=idlab:slapd", 1)
    if f"host={host}" not in q:
        q = q.replace("`support_index`", f"`support_index` host={host}", 1)
    return q


def test_overview_names_who_is_affected(host):
    rows = search(overview_query(host, "ds_by_cause"))

    def affected(cause_start):
        [row] = [r for r in rows if r["cause"].startswith(cause_start)]
        return row["affected"]
    assert affected("LDAP bind rejected with result 49") == "service account (keycloak-svc)"
    assert affected("Directory rejected a user's own password") == "1 user"
    assert affected("Clock skew between IdP and SP") == "not in log"
    assert affected("Unknown user at the IdP") == "1 user"
    who = {(r["who"], r["app"]) for r in search(overview_query(host, "ds_who"))}
    assert ("service account (keycloak-svc)", "ldap") in who and ("dave", "ldap") in who
    assert not any(w.startswith("service account (dave") for w, _ in who)


def test_overview_chart_buckets_follow_the_data(host):
    rows = search(overview_query(host, "ds_over_time"))
    # the fixtures span 18:05-18:50, so 1-minute buckets, filled continuously
    assert len(rows) == 46
    assert not any("gap" in key for r in rows for key in r)


def test_overview_proxy_panels(host):
    rows = search(overview_query(host, "ds_proxy_causes"))
    assert [r["runbook"] for r in rows] == [
        "06-proxy-bad-gateway", "07-proxy-gateway-timeout", "08-proxy-rate-limit", "10-proxy-header-too-large"]
    assert all(r["_runbook_url"].endswith(r["runbook"] + ".md") for r in rows)
    series = {k for r in search(overview_query(host, "ds_proxy_status")) for k in r if not k.startswith("_")}
    assert series == {"2xx", "3xx", "400", "429", "502", "504"}


def test_overview_when_did_it_start_lists_the_proxy_causes(host):
    runbooks = {r.get("runbook") for r in search(overview_query(host, "ds_by_cause"))}
    assert {"06-proxy-bad-gateway", "07-proxy-gateway-timeout", "08-proxy-rate-limit",
            "09-proxy-forwarded-headers", "10-proxy-header-too-large"} <= runbooks
