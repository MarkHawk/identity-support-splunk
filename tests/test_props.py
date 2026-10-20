"""Line breaking, timestamps and field extractions, checked offline against
the fixtures in tests/fixtures/lab (and samples/, once captured)."""

import collections
import csv
import datetime as dt
import re

import pytest

from conftest import ROOT, load_module
from splunk_conf import APP, break_events, extract, index_sourcetype, pcre, read_conf

hec_send = load_module("sender/hec_send.py")
props = read_conf("props.conf")
transforms = read_conf("transforms.conf")
FIXTURES = ROOT / "tests/fixtures/lab"
LOG_SOURCETYPES = sorted(set(hec_send.SERVICES.values()))
# Sourcetypes events are searched under: idlab:nginx lines are given their
# own type at index time.
SEARCH_SOURCETYPES = sorted(set(LOG_SOURCETYPES) - {"idlab:nginx"} | {"idlab:nginx:access", "idlab:nginx:error"})


def events(service):
    sourcetype = hec_send.SERVICES[service]
    return break_events(props[sourcetype], (FIXTURES / "logs" / f"{service}.log").read_text())


def fields(service, contains):
    matching = [e for e in events(service) if contains in e]
    assert len(matching) == 1, f"{len(matching)} events contain {contains!r}"
    sourcetype = index_sourcetype(props, transforms, hec_send.SERVICES[service], matching[0])
    return extract(props[sourcetype], transforms, matching[0])


# --- line breaking and time ------------------------------------------------

@pytest.mark.parametrize("sourcetype", LOG_SOURCETYPES)
def test_sender_and_props_agree_where_events_start(sourcetype):
    breaker = props[sourcetype]["LINE_BREAKER"]
    assert breaker == f"([\\r\\n]+)(?={hec_send.EVENT_START[sourcetype]})"
    assert props[sourcetype]["EVENT_BREAKER"] == breaker


@pytest.mark.parametrize("sourcetype", LOG_SOURCETYPES)
def test_timestamp_is_dockers_prefix(sourcetype):
    s = props[sourcetype]
    assert (s["TIME_PREFIX"], s["TIME_FORMAT"], s["TZ"]) == ("^", "%Y-%m-%dT%H:%M:%S.%9NZ", "UTC")
    assert s["SHOULD_LINEMERGE"] == "false"
    assert int(s["MAX_TIMESTAMP_LOOKAHEAD"]) == len("2026-10-19T18:00:00.000000000Z")


@pytest.mark.parametrize("service", sorted(hec_send.SERVICES))
def test_every_fixture_event_starts_with_a_docker_timestamp(service):
    for event in events(service):
        assert hec_send.docker_ts(event), event


@pytest.mark.parametrize("service", sorted(hec_send.SERVICES))
def test_props_and_sender_group_lines_identically(service):
    lines = (FIXTURES / "logs" / f"{service}.log").read_text().splitlines()
    assert hec_send.group_events(lines, hec_send.SERVICES[service]) == events(service)


def test_keycloak_stack_trace_is_one_event():
    trace = [e for e in events("keycloak") if "UserStorageManager" in e]
    assert len(trace) == 1 and trace[0].count("\n") == 3


def test_python_traceback_is_one_event():
    tb = [e for e in events("saml-sp") if "Traceback" in e]
    assert len(tb) == 1 and tb[0].endswith("ValueError: example")


def test_healthz_is_dropped_at_index_time():
    t = transforms["idlab_sp_drop_healthz"]
    assert (t["DEST_KEY"], t["FORMAT"]) == ("queue", "nullQueue")
    dropped = [e for e in events("saml-sp") if pcre(t["REGEX"]).search(e)]
    assert len(dropped) == 1 and "/healthz" in dropped[0]
    assert props["idlab:sp"]["TRANSFORMS-null_healthz"] == "idlab_sp_drop_healthz"


def test_proxy_lines_are_typed_access_or_error_at_index_time():
    typed = collections.Counter(index_sourcetype(props, transforms, "idlab:nginx", e) for e in events("proxy"))
    assert typed == {"idlab:nginx:access": 7, "idlab:nginx:error": 7}
    for sourcetype in ("idlab:nginx:access", "idlab:nginx:error"):
        assert "LINE_BREAKER" not in props[sourcetype], "search-time only: lines break as idlab:nginx"


# --- fields ----------------------------------------------------------------

def test_keycloak_event_fields():
    f = fields("keycloak", 'error="user_not_found"')
    assert f["log_level"] == "WARN" and f["logger"] == "org.keycloak.events"
    assert (f["kc_type"], f["kc_clientId"], f["kc_username"], f["kc_ipAddress"], f["kc_userId"]) == (
        "LOGIN_ERROR", "oidc-rp", "dave", "192.0.2.10", "null")


def test_keycloak_ldap_result_code_from_the_stack_trace():
    assert fields("keycloak", "UserStorageManager")["ldap_result_code"] == "49"


def test_sp_quoted_and_plain_values():
    f = fields("saml-sp", "idp_cert_expired")
    assert f["sp_app"] == "saml-sp" and f["log_level"] == "WARNING"
    assert f["event"] == "saml_login_failed" and f["reason"] == "idp_cert_expired"
    assert f["error"] == "IdP signing certificate expired on 2026-10-19 18:09:00 UTC; refresh the IdP metadata"


def test_sp_clock_skew_fields():
    f = fields("saml-sp", "Could not validate timestamp")
    assert f["reason"] == "invalid_response" and f["error"].startswith("Could not validate timestamp")
    assert f["sp_clock_minus_issue_instant"] == "+00:10:05"


def test_sp_login_ok_user_fields():
    assert fields("saml-sp", "saml_login_ok")["name_id"] == "alice@idlab.example"
    assert fields("oidc-rp", "oidc_login_ok")["email"] == "dave@idlab.example"


def test_sp_access_line():
    f = fields("saml-sp", "POST /saml/acs")
    assert (f["src"], f["http_method"], f["uri_path"], f["status"]) == ("192.0.2.10", "POST", "/saml/acs", "401")


def test_radius_reject_never_extracts_a_password():
    f = fields("radius", "Login incorrect")
    assert (f["radius_result"], f["user"], f["nas_client"]) == ("incorrect", "dave", "nas")
    assert f["radius_reason"] == "ldap: Bind credentials incorrect: Invalid credentials"
    line = "2026-10-19T18:40:10.000000000Z Mon Oct 19 18:40:10 2026 : Auth: (3) Login incorrect: [dave/s3cret] (from client nas port 0)"
    extracted = extract(props["idlab:radius"], transforms, line)
    assert extracted["user"] == "dave" and "s3cret" not in extracted.values()


def test_radius_dropped_packet():
    f = [extract(props["idlab:radius"], transforms, e) for e in events("radius") if "Dropping packet" in e][0]
    assert f["src"] == "192.0.2.12" and f["nas_client"] == "nas"
    assert "invalid Message-Authenticator" in f["radius_drop_error"]
    assert "(from client" not in f["radius_drop_error"]


def test_radius_unknown_client():
    assert fields("radius", "unknown client")["src"] == "192.0.2.20"


def test_nas_lines():
    assert fields("nas", "no reply")["attempts"] == "3"
    assert fields("nas", "Access-Reject")["nas_result"] == "Access-Reject"


def test_proxy_access_fields():
    f = fields("proxy", '" 504 ')
    assert (f["src"], f["http_method"], f["uri_path"], f["status"], f["bytes"]) == (
        "192.0.2.10", "GET", "/auth/callback", "504", "562")
    assert f["request"] == "GET /auth/callback?state=s&code=c HTTP/1.1"
    assert (f["site"], f["upstream"], f["upstream_status"]) == ("rp.idlab.example:8185", "192.0.2.32:8182", "504")
    assert (f["request_time"], f["upstream_time"]) == ("5.005", "5.004")


def test_proxy_access_answered_by_nginx_itself():
    f = fields("proxy", '" 429 ')
    assert (f["status"], f["upstream"], f["upstream_status"], f["upstream_time"]) == ("429", "-", "-", "-")


def test_proxy_access_after_a_retry_keeps_every_upstream():
    f = fields("proxy", "upstream_status=502, 200")
    assert (f["upstream"], f["upstream_status"], f["upstream_time"]) == (
        "192.0.2.32:8182, 192.0.2.33:8182", "502, 200", "0.020, 0.011")


@pytest.mark.parametrize("contains, reason", [
    ("prematurely", "upstream prematurely closed connection while reading response header from upstream"),
    ("timed out", "upstream timed out (110: Operation timed out) while reading response header from upstream"),
    ("too big header", "upstream sent too big header while reading response header from upstream"),
    ("limiting requests", 'limiting requests, excess: 0.307 by zone "kc_login"'),
])
def test_proxy_error_reason(contains, reason):
    f = fields("proxy", contains)
    assert (f["log_level"], f["nginx_reason"], f["src"]) == ("error", reason, "192.0.2.10")


def test_proxy_error_request_upstream_and_host():
    f = fields("proxy", "prematurely")
    assert (f["connection_id"], f["request"], f["http_method"], f["uri_path"]) == ("69", "GET / HTTP/1.1", "GET", "/")
    assert (f["upstream"], f["site"]) == ("http://192.0.2.32:8182/", "rp.idlab.example:8185")


def test_proxy_error_rate_limit_zone():
    f = fields("proxy", "limiting requests")
    assert (f["limit_zone"], f["limit_excess"], f["site"]) == ("kc_login", "0.307", "idp.idlab.example:8183")
    assert "upstream" not in f


def test_proxy_error_line_cut_short_by_nginx():
    f = fields("proxy", "too big header")
    assert f["uri_path"] == "/realms/idlab/protocol/saml"
    assert f["upstream"].endswith("&Signature=S6DHaj") and "site" not in f


def test_proxy_notice_lines():
    f = fields("proxy", "SIGHUP")
    assert (f["log_level"], f["nginx_reason"]) == ("notice", "signal 1 (SIGHUP) received from 183, reconfiguring")
    assert "connection_id" not in f and "src" not in f


def test_slapd_bind_and_result_join_on_conn_and_op():
    bind = fields("ldap", 'BIND dn="cn=keycloak-svc')
    result = fields("ldap", "conn=1027 op=0 RESULT tag=97")
    assert bind["bind_dn"] == "cn=keycloak-svc,ou=services,dc=idlab,dc=example"
    assert (bind["conn"], bind["op"], bind["ldap_op"]) == (result["conn"], result["op"], "BIND")
    assert (result["ldap_tag"], result["err"], result["ldap_op"]) == ("97", "49", "RESULT")
    accept = fields("ldap", "ACCEPT")
    assert (accept["conn"], accept["ldap_op"], accept["src"]) == ("1027", "ACCEPT", "192.0.2.13")


# --- signatures, causes and runbooks ----------------------------------------

def eval_signatures():
    """Every literal signature the EVAL-signature expressions can produce."""
    found = set()
    for sourcetype in SEARCH_SOURCETYPES:
        expr = props[sourcetype].get("EVAL-signature", "")
        # a literal ending in "_" is a prefix (such as "ldap_bind_" . err), not a signature
        found |= {s for s in re.findall(r'(?<![=!]=)"([a-z]+_[a-z0-9_]+)"', expr) if not s.endswith("_")}
    return found


def causes():
    with (APP / "lookups/support_causes.csv").open(newline="") as f:
        return list(csv.DictReader(f))


def test_every_signature_has_a_cause_and_runbook():
    known = {row["signature"] for row in causes()}
    # kc_<error> and <app>:<reason> are built at search time; the Keycloak
    # errors the lab's scenarios produce are listed explicitly.
    assert eval_signatures() <= known
    assert {"kc_invalid_redirect_uri", "kc_user_not_found", "kc_invalid_user_credentials"} <= known


def test_causes_link_identity_lab_runbooks():
    for row in causes():
        assert row["cause"] and re.fullmatch(r"0[1-5]-[a-z-]+", row["runbook"]), row
        assert row["runbook_url"] == (
            f"https://github.com/MarkHawk/identity-lab/blob/main/runbooks/{row['runbook']}.md")


def test_every_log_sourcetype_looks_up_causes():
    for sourcetype in (s for s in SEARCH_SOURCETYPES if "EVAL-signature" in props[s]):
        assert props[sourcetype]["LOOKUP-support_causes"] == "support_causes signature OUTPUT cause runbook runbook_url"
    assert transforms["support_causes"]["filename"] == "support_causes.csv"


def test_eventtypes_and_tags_line_up():
    eventtypes, tags = read_conf("eventtypes.conf"), read_conf("tags.conf")
    tagged = {s.removeprefix("eventtype=") for s in tags.sections()}
    assert tagged == set(eventtypes.sections())
    auth = {s.removeprefix("eventtype=") for s in tags.sections() if tags[s].get("authentication") == "enabled"}
    assert {s.removeprefix("eventtype=") for s in tags.sections() if tags[s].get("web") == "enabled"} == {
        "idlab_proxy_access"}
    assert auth == {"idlab_keycloak_login", "idlab_sp_login", "idlab_radius_auth", "idlab_ldap_bind_failure"}


def test_report_sourcetypes_are_json():
    for sourcetype in hec_send.TOOLS.values():
        assert props[sourcetype]["KV_MODE"] == "json"


def test_fixture_times_are_plausible():
    # Guards against a fixture typo that would silently land outside the scenario window.
    for path in (FIXTURES / "logs").glob("*.log"):
        for line in path.read_text().splitlines():
            ts = hec_send.docker_ts(line)
            assert ts and dt.datetime(2026, 10, 19, 18, tzinfo=dt.UTC) <= ts < dt.datetime(2026, 10, 19, 19, tzinfo=dt.UTC)
