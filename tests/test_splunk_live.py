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
EXPECTED = {"idlab:keycloak": 6, "idlab:sp": 46, "idlab:api": 24, "idlab:radius": 7, "idlab:nas": 4, "idlab:slapd": 6,
            "idlab:nginx:access": 12, "idlab:nginx:error": 10, "idlab:squid:access": 7, "idlab:squid:cache": 5,
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
            break
        time.sleep(3)
    else:
        pytest.fail(f"indexed events never matched {EXPECTED}: {rows}")
    # Just after Splunk starts, events are searchable before the app's
    # search-time fields apply to them: wait for a calculated field too.
    while time.time() < deadline:
        if search(f"`support_index` host={name} signature=egress_proxy_tls_untrusted | stats count") == [{"count": "1"}]:
            return name
        time.sleep(3)
    pytest.fail("the app's search-time fields never applied to the replayed events")


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
    row = one(host, "sourcetype=idlab:sp source=docker:oidc-rp event=oidc_login_failed reason=token_validation_failed")
    assert row["signature"] == "oidc-rp:token_validation_failed" and "cause" not in row


def test_sp_login_ok_user(host):
    rows = search(f"`support_index` host={host} tag=authentication action=success sourcetype=idlab:sp | sort user app | table app user")
    assert [(r["app"], r["user"]) for r in rows] == [
        ("oidc-rp-edge", "alice@idlab.example"), ("saml-sp", "alice@idlab.example"),
        ("saml-sp-proxied", "alice@idlab.example"), ("oidc-rp", "dave@idlab.example")]


def test_proxied_app_failure_names_the_proxied_copy(host):
    row = one(host, "sourcetype=idlab:sp source=docker:oidc-rp-proxied event=oidc_login_failed")
    assert (row["action"], row["app"], row["dest"], row["signature"]) == (
        "failure", "oidc-rp-proxied", "oidc-rp-proxied", "oidc-rp:token_exchange_failed")


def test_edge_rp_force_https_fields(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:sp source=docker:oidc-rp-edge event=force_https "
                  "| stats count by scheme x_forwarded_proto")
    assert {(r["scheme"], r["x_forwarded_proto"]): r["count"] for r in rows} == {("http", "-"): "7", ("http", "https"): "5"}


def test_redirect_loops_are_bursts(host):
    rows = search(f"`support_redirect_loops` | search host={host} app=oidc-rp-edge | eval t=strftime(_time, \"%H:%M:%S\") "
                  "| table t redirects route signature runbook")
    # the lone /login redirect at 18:41 is not a loop
    assert [(r["t"], r["redirects"], r["route"], r["signature"], r["runbook"]) for r in rows] == [
        ("18:40:00", "6", "/", "redirect_loop_no_forwarded_proto", "15-redirect-loop"),
        ("18:42:00", "5", "/debug", "redirect_loop_proxy_hops", "15-redirect-loop")]


def test_api_calls_are_cim_authentication(host):
    rows = search(f"`support_index` host={host} tag=authentication sourcetype=idlab:api "
                  "| fillnull value=- user | stats count by action app dest status user")
    sub = "0b6f6f1e-3c1b-4d4e-9a55-1f2e3d4c5b6a"
    assert {(r["action"], r["app"], r["dest"], r["status"], r["user"]): r["count"] for r in rows} == {
        ("success", "api", "api", "200", sub): "6",  # 2 of them blocked by the browser (CORS)
        ("failure", "api", "api", "401", sub): "2",
        ("failure", "api", "api", "401", "7d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d"): "1",
        ("failure", "api", "api", "401", "-"): "2",
        ("failure", "api", "api", "400", "-"): "1"}


def test_api_rejection_reasons_and_lifetime(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:api event=api_token_rejected "
                  "| fillnull value=- token_lifetime aud | stats count by reason token_lifetime aud")
    assert {(r["reason"], r["token_lifetime"], r["aud"]) for r in rows} == {
        ("no_token", "-", "-"), ("not_jwt", "-", "-"), ("not_bearer", "-", "-"),
        ("wrong_audience", "300", "idlab-api-staging account"),
        ("expired", "10", "idlab-api account"),
        ("expired", "-", "idlab-api account")}


def test_api_rejection_causes(host):
    rows = search(f"`support_failures` host={host} sourcetype=idlab:api | stats count by signature runbook")
    assert {r["signature"]: (r["count"], r["runbook"]) for r in rows} == {
        "api_bearer_no_token": ("1", "16-api-bearer-401"), "api_bearer_not_jwt": ("1", "16-api-bearer-401"),
        "api_bearer_not_bearer": ("1", "16-api-bearer-401"), "api_bearer_wrong_audience": ("1", "16-api-bearer-401"),
        "api_bearer_expired": ("2", "16-api-bearer-401"),
        # a trailing slash, and no header at all; not the back-end call, the exact match or "*"
        "api_cors_origin_mismatch": ("2", "19-cors-blocked")}


def test_api_cors_mismatch_is_a_success_with_a_reason(host):
    rows = search(f"`support_index` host={host} eventtype=idlab_api_cors_mismatch "
                  "| fillnull value=- cors_allow_origin | table _time action reason origin cors_allow_origin")
    assert [(r["action"], r["reason"], r["origin"], r["cors_allow_origin"]) for r in rows] == [
        ("success", "cors_origin_mismatch", "https://spa.idlab.example", "-"),
        ("success", "cors_origin_mismatch", "https://rp.idlab.example:8182", "https://rp.idlab.example:8182/")]


def test_api_access_lines_keep_their_status(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:api uri_path=/v1/whoami | stats count by status")
    assert {r["status"]: r["count"] for r in rows} == {"200": "2", "204": "1", "400": "1", "401": "5"}


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
        "proxy_rate_limited", "proxy_header_too_large", "oidc-rp:access_denied",
        "egress_proxy_auth_required", "egress_proxy_policy_block", "egress_proxy_tls_untrusted",
        "egress_app_proxy_auth_required", "egress_app_proxy_policy_block", "egress_app_tls_untrusted",
        "egress_app_proxy_bypassed", "egress_app_proxy_unreachable",
        "api_bearer_no_token", "api_bearer_not_jwt", "api_bearer_not_bearer", "api_bearer_wrong_audience",
        "api_bearer_expired", "api_cors_origin_mismatch", "proxy_answered_503", "proxy_client_cert_missing",
        "proxy_client_cert_expired", "proxy_client_cert_rejected"}


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
    rows = search(f"`support_index` host={host} eventtype=idlab_proxy_error | fillnull value=- route "
                  "| stats count by signature runbook app route")
    got = {r["signature"]: (r["runbook"], r["app"], r["route"]) for r in rows}
    assert got == {
        "proxy_upstream_closed": ("06-proxy-bad-gateway", "proxy", "rp.idlab.example:8185"),
        "proxy_upstream_timeout": ("07-proxy-gateway-timeout", "proxy", "rp.idlab.example:8185"),
        "proxy_rate_limited": ("08-proxy-rate-limit", "proxy", "idp.idlab.example:8183"),
        # nginx cut this line before its host
        "proxy_header_too_large": ("10-proxy-header-too-large", "proxy", "-"),
        # from the access log
        "proxy_answered_503": ("17-service-unavailable", "proxy", "idp.idlab.example:8183"),
        "proxy_client_cert_missing": ("18-client-cert", "proxy", "partner.idlab.example:8189"),
        "proxy_client_cert_expired": ("18-client-cert", "proxy", "partner.idlab.example:8189"),
        "proxy_client_cert_rejected": ("18-client-cert", "proxy", "partner.idlab.example:8189"),
    }
    assert all(r["count"] == "1" for r in rows)


def test_proxy_mutual_tls_fields(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:nginx:access ssl_client_verify=* "
                  "| fillnull value=MISSING client_dn client_not_after ssl_client_verify_reason "
                  "| table status ssl_client_verify ssl_client_verify_reason client_dn client_not_after")
    assert {(r["status"], r["ssl_client_verify"], r["ssl_client_verify_reason"], r["client_dn"]) for r in rows} == {
        ("200", "SUCCESS", "MISSING", "CN=partner-client"),
        ("400", "NONE", "MISSING", "MISSING"),  # no "-" from automatic key=value extraction
        ("400", "FAILED:certificate has expired", "certificate has expired", "CN=partner-client"),
        ("400", "FAILED:self-signed certificate", "self-signed certificate", "CN=partner-client")}


def test_proxy_info_lines_explain_but_do_not_count(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:nginx:error log_level=info "
                  "| fillnull value=- ssl_verify_error | stats count(signature) as n count by ssl_verify_error")
    assert {r["ssl_verify_error"]: (r["n"], r["count"]) for r in rows} == {"10": ("0", "1"), "-": ("0", "2")}


def test_proxy_notices_are_not_failures(host):
    rows = search(f"`support_index` host={host} sourcetype=idlab:nginx:error log_level=notice | stats count(signature) as n count")
    assert rows == [{"n": "0", "count": "3"}]


def test_forwarded_headers_point_at_the_proxy(host):
    row = one(host, "signature=kc_invalid_destination")
    assert (row["action"], row["kc_reason"], row["runbook"]) == ("failure", "invalid_destination", "09-proxy-forwarded-headers")
    assert row["cause"].startswith("Reverse proxy is the likely cause")
    assert row["app"] == "keycloak (via proxy)", "Keycloak's clientId=\"null\" is not an app"


def test_masked_detail_is_one_value(host):
    row = one(host, "sourcetype=idlab:sp reason=access_denied")
    assert (row["detail"], row["signature"]) == ("state=***", "oidc-rp:access_denied") and "state" not in row


def test_squid_access_fields(host):
    row = one(host, "sourcetype=idlab:squid:access status=407")
    assert (row["result_code"], row["action"], row["http_method"], row["dest"], row["dest_port"]) == (
        "TCP_DENIED", "blocked", "CONNECT", "keycloak", "8180")
    assert "user" not in row and row["duration"] == "0"
    row = one(host, "sourcetype=idlab:squid:access user=egress-svc")
    assert (row["result_code"], row["action"], row["duration"]) == ("TCP_TUNNEL", "allowed", "0.034")
    rows = search(f"`support_index` host={host} eventtype=idlab_egress_access tag=web tag=proxy | stats count")
    assert rows == [{"count": "7"}]


def test_squid_tls_error_is_decoded(host):
    row = one(host, "sourcetype=idlab:squid:cache tls_lib_err=*")
    assert (row["log_level"], row["tls_squid_err"], row["tls_lib_err"], row["tls_error"]) == (
        "ERROR", "SQUID_TLS_ERR_ACCEPT", "A000418", "tlsv1 alert unknown ca")


def test_egress_causes(host):
    rows = search(f"`support_failures` host={host} signature=egress_* | fillnull value=- app route runbook "
                  "| stats count by signature runbook app route")
    got = {(r["signature"], r["route"]): (r["runbook"], r["app"], r["count"]) for r in rows}
    assert got == {
        ("egress_proxy_auth_required", "keycloak:8180"): ("11-proxy-auth-required", "egress proxy", "1"),
        ("egress_app_proxy_auth_required", "-"): ("11-proxy-auth-required", "oidc-rp-egress", "1"),
        ("egress_proxy_policy_block", "keycloak:8180"): ("12-proxy-policy-block", "egress proxy", "2"),
        # the app's own healthcheck refused by policy: a route other than the IdP
        ("egress_proxy_policy_block", "localhost:8182"): ("12-proxy-policy-block", "egress proxy", "1"),
        ("egress_app_proxy_policy_block", "-"): ("12-proxy-policy-block", "oidc-rp-egress", "1"),
        ("egress_proxy_tls_untrusted", "-"): ("13-proxy-tls-interception", "egress proxy", "1"),
        ("egress_app_tls_untrusted", "-"): ("13-proxy-tls-interception", "oidc-rp-egress", "1"),
        ("egress_app_proxy_bypassed", "-"): ("14-proxy-bypass", "oidc-rp-egress", "1"),
        ("egress_app_proxy_unreachable", "-"): ("-", "oidc-rp-egress", "1"),
    }, got


def test_egress_scenario_is_one_cause_on_both_sides(host):
    rows = search(f"`support_failures` host={host} signature=egress_*_auth_required | stats values(app) as apps by cause")
    assert len(rows) == 1 and sorted(rows[0]["apps"]) == ["egress proxy", "oidc-rp-egress"]


def test_quoted_error_is_kept_whole(host):
    row = one(host, 'sourcetype=idlab:sp reason=backchannel_failed "Tunnel connection failed: 407"')
    assert row["error"].endswith("Tunnel connection failed: 407 Proxy Authentication Required'\"'\"')))")
    assert row["detail"] == "ProxyError" and "port" not in row


def alert_query(host, name, threshold=None):
    """A saved search's SPL limited to this run's host (the alert's own time window is not applied)."""
    from splunk_conf import read_conf
    spl = read_conf("savedsearches.conf")[name]["search"].replace("`support_index`", f"`support_index` host={host}", 1)
    return spl.replace(">= 3", f">= {threshold}") if threshold else spl


def test_redirect_loop_alert(host):
    spl = read_conf_search("App stuck in a redirect loop").replace(
        "`support_redirect_loops`", f"`support_redirect_loops` | search host={host}", 1)
    rows = {r["cause"]: r for r in search(spl)}
    assert len(rows) == 2
    [missing] = [r for c, r in rows.items() if "gets no X-Forwarded-Proto" in c]
    assert (missing["app"], missing["loops"], missing["redirects"], missing["paths"]) == ("oidc-rp-edge", "1", "6", "/")
    assert missing["runbook_url"].endswith("/15-redirect-loop.md")


def read_conf_search(name):
    from splunk_conf import read_conf
    return read_conf("savedsearches.conf")[name]["search"]


def test_egress_alert(host):
    rows = {r["runbook"]: r for r in search(alert_query(host, "Egress proxy refusing the IdP"))}
    assert set(rows) == {"11-proxy-auth-required", "12-proxy-policy-block", "13-proxy-tls-interception"}
    # Squid's and the app's side of each; the healthcheck refused on localhost:8182 is not the IdP
    assert (rows["11-proxy-auth-required"]["count"], rows["12-proxy-policy-block"]["count"]) == ("2", "3")
    assert rows["12-proxy-policy-block"]["routes"] == "keycloak:8180"
    assert sorted(rows["13-proxy-tls-interception"]["apps"]) == ["egress proxy", "oidc-rp-egress"]
    assert all(r["runbook_url"].endswith(r["runbook"] + ".md") for r in rows.values())


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
    q = q.replace("[search `support_redirect_loops`]", f"[search `support_redirect_loops` | search host={host}]", 1)
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
    # the fixtures span 18:05-18:55, so 1-minute buckets, filled continuously
    assert len(rows) == 51
    assert not any("gap" in key for r in rows for key in r)


def test_overview_proxy_panels(host):
    rows = search(overview_query(host, "ds_proxy_causes"))
    assert [r["runbook"] for r in rows] == [
        "06-proxy-bad-gateway", "07-proxy-gateway-timeout", "08-proxy-rate-limit", "10-proxy-header-too-large",
        "18-client-cert", "18-client-cert", "18-client-cert", "17-service-unavailable"]
    assert all(r["_runbook_url"].endswith(r["runbook"] + ".md") for r in rows)
    series = {k for r in search(overview_query(host, "ds_proxy_status")) for k in r if not k.startswith("_")}
    assert series == {"2xx", "3xx", "400", "400 client certificate", "429", "502", "503", "504"}
    mtls = search(overview_query(host, "ds_mtls_clients"))
    assert {(r["client"], r["not_after"], r["result"], r["count"]) for r in mtls} == {
        ("CN=partner-client", "Nov 23 18:32:36 2027 GMT", "accepted", "1"),
        ("no certificate sent", "-", "refused: no certificate", "1"),
        ("CN=partner-client", "Oct 18 18:51:00 2026 GMT", "refused: certificate has expired", "1"),
        ("CN=partner-client", "Nov 3 18:32:36 2027 GMT", "refused: self-signed certificate", "1")}
    days = {r["result"]: r.get("days_left") for r in mtls}
    assert days["refused: no certificate"] is None and int(days["refused: certificate has expired"]) < 0


def test_overview_when_did_it_start_lists_the_proxy_causes(host):
    runbooks = {r.get("runbook") for r in search(overview_query(host, "ds_by_cause"))}
    assert {"06-proxy-bad-gateway", "07-proxy-gateway-timeout", "08-proxy-rate-limit",
            "09-proxy-forwarded-headers", "10-proxy-header-too-large"} <= runbooks


def test_overview_when_did_it_start_shows_apps_and_routes(host):
    rows = {r["runbook"] if r.get("runbook") else r["cause"][:40]: r for r in search(overview_query(host, "ds_by_cause"))}
    assert (rows["06-proxy-bad-gateway"]["apps"], rows["06-proxy-bad-gateway"]["routes"]) == ("proxy", "rp.idlab.example:8185")
    assert rows["09-proxy-forwarded-headers"]["apps"] == "keycloak (via proxy)"
    assert "routes" not in rows["10-proxy-header-too-large"]
    # each egress scenario is one row, from both sides
    assert sorted(rows["11-proxy-auth-required"]["apps"]) == ["egress proxy", "oidc-rp-egress"]
    assert rows["11-proxy-auth-required"]["routes"] == "keycloak:8180"
    assert sorted(rows["12-proxy-policy-block"]["routes"]) == ["keycloak:8180", "localhost:8182"]
    assert rows["14-proxy-bypass"]["apps"] == "oidc-rp-egress"
    # ... and each failed login counts once: Squid's 407, 403 and TLS lines
    # pair with the app's; Squid's aborted 403 and the one to localhost don't
    assert [rows[r]["count"] for r in ("11-proxy-auth-required", "12-proxy-policy-block",
                                       "13-proxy-tls-interception")] == ["1", "3", "1"]
    [unreachable] = [r for r in rows.values() if r["cause"].startswith("App cannot reach its egress proxy")]
    assert unreachable["_runbook_url"] == "https://github.com/MarkHawk/identity-lab/tree/main/runbooks"


def test_overview_egress_panels(host):
    rows = search(overview_query(host, "ds_egress_causes"))
    assert [r.get("runbook", "-") for r in rows] == [
        "11-proxy-auth-required", "12-proxy-policy-block", "13-proxy-tls-interception", "14-proxy-bypass", "-"]
    assert [(r["failed calls (app)"], r["refusals (Squid)"]) for r in rows] == [
        ("1", "1"), ("1", "3"), ("1", "1"), ("1", "0"), ("1", "0")]
    series = {k for r in search(overview_query(host, "ds_egress_status")) for k in r if not k.startswith("_")}
    assert series == {"tunnelled", "407", "403", "intercepted, no tunnel"}


def test_overview_when_did_it_start_shows_loops_and_bearer_tokens(host):
    rows = [r for r in search(overview_query(host, "ds_by_cause")) if r.get("runbook", "").startswith(("15-", "16-"))]
    loops = {r["routes"]: r for r in rows if r["runbook"] == "15-redirect-loop"}
    assert {k: (r["count"], r["apps"], r["affected"]) for k, r in loops.items()} == {
        "/": ("1", "oidc-rp-edge", "not in log"), "/debug": ("1", "oidc-rp-edge", "not in log")}
    assert loops["/"]["cause"].startswith("Redirect loop (too many redirects): the app forces HTTPS but gets no X-Forwarded-Proto")
    [expired] = [r for r in rows if r["cause"].startswith("API refuses the access token as expired")]
    assert expired["count"] == "2" and expired["affected"] == "2 users"
    assert expired["cause"].endswith(". Token lifetime (exp - iat): 10 s, very short: check the client's access token lifespan in the IdP")
    [audience] = [r for r in rows if r["cause"].startswith("API refuses the access token as not meant for it")]
    assert "Token lifetime" not in audience["cause"] and audience["apps"] == "api"


def test_overview_api_panels(host):
    rows = search(overview_query(host, "ds_api_reasons"))
    assert [(r["reason"], r["status"], r["count"], r.get("lifetime", "-")) for r in rows] == [
        ("no_token", "401", "1", "-"), ("not_jwt", "401", "1", "-"), ("not_bearer", "400", "1", "-"),
        ("wrong_audience", "401", "1", "-"), ("expired", "401", "2", "10 s")]
    assert rows[3]["audiences"] == "idlab-api-staging account" and rows[3]["clients"] == "oidc-rp"
    assert all(r["_runbook_url"].endswith("/16-api-bearer-401.md") for r in rows)
    series = {k for r in search(overview_query(host, "ds_api_results")) for k in r if not k.startswith("_")}
    assert series == {"accepted", "no_token", "not_jwt", "not_bearer", "wrong_audience", "expired", "cors_origin_mismatch"}
