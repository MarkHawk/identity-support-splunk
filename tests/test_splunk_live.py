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
EXPECTED = {"idlab:keycloak": 5, "idlab:sp": 9, "idlab:radius": 7, "idlab:nas": 4, "idlab:slapd": 6,
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
    row = one(host, "sourcetype=idlab:sp event=oidc_login_failed")
    assert row["signature"] == "oidc-rp:token_validation_failed" and "cause" not in row


def test_sp_login_ok_user(host):
    rows = search(f"`support_index` host={host} tag=authentication action=success sourcetype=idlab:sp | sort user | table app user")
    assert [(r["app"], r["user"]) for r in rows] == [("saml-sp", "alice@idlab.example"), ("oidc-rp", "dave@idlab.example")]


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
        "radius_reject_bad_password", "radius_bad_shared_secret", "radius_unknown_client", "nas_no_reply"}


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
    return q.replace("(`support_index` sourcetype=idlab:slapd", f"(`support_index` host={host} sourcetype=idlab:slapd", 1)


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
