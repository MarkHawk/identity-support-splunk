"""The committed samples (captured from a real identity-lab run by
scripts/capture_lab.py) still parse as the app expects, and still show
every scenario the runbooks cover."""

import collections
import json

import pytest

from conftest import ROOT, load_module
from splunk_conf import break_events, extract, index_sourcetype, read_conf

hec_send = load_module("sender/hec_send.py")
props, transforms = read_conf("props.conf"), read_conf("transforms.conf")
SAMPLES = ROOT / "samples"
LOGS = sorted((SAMPLES / "logs").glob("*.log"))
REPORTS = sorted(p for p in (SAMPLES / "reports").glob("*.json") if not p.name.endswith(".meta.json"))


def sample_events():
    for path in LOGS:
        sourcetype = hec_send.SERVICES[path.stem]
        for event in break_events(props[sourcetype], path.read_text()):
            typed = index_sourcetype(props, transforms, sourcetype, event)
            yield path.stem, event, extract(props[typed], transforms, event)


def test_capture_metadata():
    meta = json.loads((SAMPLES / "capture.json").read_text())
    assert meta["since"] < meta["until"]
    assert {p.stem for p in LOGS} <= set(meta["lines"])


@pytest.mark.parametrize("path", LOGS, ids=lambda p: p.name)
def test_every_sample_event_is_timestamped_and_grouped_like_props(path):
    sourcetype = hec_send.SERVICES[path.stem]
    lines = path.read_text().splitlines()
    events = break_events(props[sourcetype], path.read_text())
    assert hec_send.group_events(lines, sourcetype) == events
    assert all(hec_send.docker_ts(e) for e in events)


def test_every_runbook_scenario_is_in_the_samples():
    seen = collections.Counter()
    for service, event, f in sample_events():
        if f.get("kc_error") == "invalid_redirect_uri":
            seen["03 redirect URI"] += 1
        if f.get("reason") == "idp_cert_expired":
            seen["01 signing certificate"] += 1
        if f.get("reason") == "invalid_response" and "timestamp" in f.get("error", "").lower():
            seen["02 clock skew"] += 1
        if f.get("ldap_result_code") == "49" or f.get("err") == "49":
            seen["04 LDAP 49"] += 1
        if "Message-Authenticator" in f.get("radius_drop_error", ""):
            seen["05 RADIUS no reply"] += 1
        if f.get("radius_result") == "incorrect":
            seen["RADIUS Access-Reject"] += 1
        for start, scenario in PROXY_REASONS.items():
            if f.get("nginx_reason", "").startswith(start):
                seen[scenario] += 1
        if f.get("kc_reason") == "invalid_destination":
            seen["09 proxy forwarded headers"] += 1
        if f.get("result_code", "").startswith("TCP_DENIED"):
            seen[{"407": "11 proxy auth (Squid)", "403": "12 proxy policy (Squid)"}[f["status"]]] += 1
        if f.get("tls_lib_err") == "A000418":
            seen["13 TLS interception (Squid)"] += 1
        if f.get("reason") == "backchannel_failed":
            for text, scenario in EGRESS_APP_ERRORS.items():
                if text in f["error"]:
                    seen[scenario] += 1
    # 14 (NO_PROXY) leaves nothing in Squid's log: the app tries Keycloak
    # directly and cannot resolve it.
    assert set(seen) == {"01 signing certificate", "02 clock skew", "03 redirect URI", "04 LDAP 49",
                         "05 RADIUS no reply", "RADIUS Access-Reject", *PROXY_REASONS.values(),
                         "09 proxy forwarded headers", "11 proxy auth (Squid)", "12 proxy policy (Squid)",
                         "13 TLS interception (Squid)", *EGRESS_APP_ERRORS.values()}, seen


EGRESS_APP_ERRORS = {
    "Tunnel connection failed: 407": "11 proxy auth (app)",
    "Tunnel connection failed: 403": "12 proxy policy (app)",
    "CERTIFICATE_VERIFY_FAILED": "13 TLS interception (app)",
    "(Caused by NameResolutionError": "14 NO_PROXY (app)",
}


PROXY_REASONS = {
    "upstream prematurely closed connection": "06 proxy bad gateway",
    "upstream timed out": "07 proxy gateway timeout",
    "limiting requests": "08 proxy rate limit",
    "upstream sent too big header": "10 proxy header too large",
}


def test_proxy_statuses_in_the_samples():
    statuses = collections.Counter(f["status"] for service, _, f in sample_events()
                                   if service == "proxy" and "status" in f)
    assert {"200", "302", "429", "502", "504"} <= set(statuses)
    # 502 from scenarios 06 and 10; a run may go through the scenarios more than once
    assert statuses["502"] >= 2 and statuses["504"] >= 1 and statuses["429"] >= 1


def test_proxied_apps_logged_logins():
    services = {service for service, _, f in sample_events() if f.get("event", "").endswith("_login_ok")}
    assert {"saml-sp-proxied", "oidc-rp-proxied"} <= services


@pytest.mark.parametrize("path", REPORTS, ids=lambda p: p.name)
def test_reports_are_tool_reports_with_a_capture_time(path):
    report = json.loads(path.read_text())
    assert report["tool"] in hec_send.TOOLS
    assert path.with_name(path.stem + ".meta.json").exists()


def test_replay_plan_covers_the_samples():
    logs, reports = hec_send.replay_plan(SAMPLES)
    assert logs == LOGS and reports == REPORTS
