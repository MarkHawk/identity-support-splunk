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
# Sourcetypes events are searched under: idlab:nginx and idlab:squid events
# are given their own type at index time.
SEARCH_SOURCETYPES = sorted(set(LOG_SOURCETYPES) - {"idlab:nginx", "idlab:squid"}
                            | {"idlab:nginx:access", "idlab:nginx:error", "idlab:squid:access", "idlab:squid:cache"})


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



def test_squid_cache_log_detail_lines_stay_with_their_message():
    squid = events("squid")
    assert len(squid) == 12
    tls = [e for e in squid if "Cannot accept a TLS connection" in e]
    assert len(tls) == 1 and "TLS_LIB_ERR=A000418" in tls[0] and "current master transaction" in tls[0]
    assert any("Accepting HTTP Socket" in e and "listening port: 3128" in e for e in squid)


def test_squid_events_are_typed_access_or_cache_at_index_time():
    typed = collections.Counter(index_sourcetype(props, transforms, "idlab:squid", e) for e in events("squid"))
    assert typed == {"idlab:squid:access": 7, "idlab:squid:cache": 5}
    for sourcetype in ("idlab:squid:access", "idlab:squid:cache"):
        assert "LINE_BREAKER" not in props[sourcetype], "search-time only: events break as idlab:squid"


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
    # identity-lab masks state, session_state and code itself, as ***
    assert f["request"] == ("GET /auth/callback?state=***&session_state=***"
                            "&iss=https%3A%2F%2Fidp.idlab.example%3A8183%2Frealms%2Fidlab&code=*** HTTP/1.1")
    assert (f["site"], f["upstream"], f["upstream_status"]) == ("rp.idlab.example:8185", "192.0.2.32:8182", "504")
    assert (f["request_time"], f["upstream_time"]) == ("5.005", "5.004")


@pytest.mark.parametrize("contains, uri_path, status", [
    ("SAMLRequest=***", "/realms/idlab/protocol/saml", "502"),         # masked by the lab
    ("SAMLRequest=masked-", "/realms/idlab/protocol/saml", "400"),     # masked by sanitise.py
    ("session_code=masked-", "/realms/idlab/login-actions/authenticate", "429"),
])
def test_proxy_access_with_masked_values(contains, uri_path, status):
    access = [e for e in events("proxy") if contains in e and "[error]" not in e]
    assert len(access) == 1
    f = extract(props["idlab:nginx:access"], transforms, access[0])
    assert (f["uri_path"], f["status"], f["site"]) == (uri_path, status, "idp.idlab.example:8183")


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
    assert f["upstream"].endswith("&Signature=masked-Signa") and "site" not in f
    assert f["request"].startswith("GET /realms/idlab/protocol/saml?SAMLRequest=***&RelayState=%2Fdebug&")


def test_proxy_error_with_values_masked_by_the_lab():
    f = fields("proxy", "timed out")
    assert (f["uri_path"], f["site"]) == ("/auth/callback", "rp.idlab.example:8185")
    assert f["upstream"].startswith("https://192.0.2.32:8182/auth/callback?state=***&session_state=***&")


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
        if row["signature"] == "egress_app_proxy_unreachable":
            continue  # no runbook covers it; see the next test
        assert row["cause"] and re.fullmatch(r"(?:0[1-9]|1[0-4])-[a-z-]+", row["runbook"]), row
        assert row["runbook_url"] == (
            f"https://github.com/MarkHawk/identity-lab/blob/main/runbooks/{row['runbook']}.md")


def test_unreachable_egress_proxy_has_no_runbook_link():
    row = {r["signature"]: r for r in causes()}["egress_app_proxy_unreachable"]
    assert (row["runbook"], row["runbook_url"]) == ("", "")
    assert "no runbook covers this: see Where to look in runbooks 11 to 14" in row["cause"]


def test_each_egress_scenario_is_one_cause_from_both_sides():
    by_sig = {r["signature"]: r for r in causes()}
    for squid, app in [("egress_proxy_auth_required", "egress_app_proxy_auth_required"),
                       ("egress_proxy_policy_block", "egress_app_proxy_policy_block"),
                       ("egress_proxy_tls_untrusted", "egress_app_tls_untrusted")]:
        assert by_sig[squid]["cause"] == by_sig[app]["cause"] and by_sig[squid]["runbook"] == by_sig[app]["runbook"]
    assert by_sig["egress_app_proxy_bypassed"]["cause"].startswith(
        "Forward proxy is bypassed or misconfigured, even though Squid logs nothing")


def test_every_log_sourcetype_looks_up_causes():
    for sourcetype in (s for s in SEARCH_SOURCETYPES if "EVAL-signature" in props[s]):
        assert props[sourcetype]["LOOKUP-support_causes"] == "support_causes signature OUTPUT cause runbook runbook_url"
    assert transforms["support_causes"]["filename"] == "support_causes.csv"


@pytest.mark.parametrize("contains, signature, runbook", [
    ("prematurely", "proxy_upstream_closed", "06-proxy-bad-gateway"),
    ("timed out", "proxy_upstream_timeout", "07-proxy-gateway-timeout"),
    ("limiting requests", "proxy_rate_limited", "08-proxy-rate-limit"),
    ("too big header", "proxy_header_too_large", "10-proxy-header-too-large"),
    ("SIGHUP", None, None),
])
def test_proxy_error_signature(contains, signature, runbook):
    """EVAL-signature's match() patterns, run against the fixture's reasons."""
    expr = props["idlab:nginx:error"]["EVAL-signature"]
    rules = re.findall(r'match\(nginx_reason, "([^"]+)"\), "([a-z_]+)"', expr)
    assert len(rules) == expr.count("match(")
    reason = fields("proxy", contains)["nginx_reason"]
    found = [sig for pattern, sig in rules if pcre(pattern).search(reason)]
    assert found == ([signature] if signature else [])
    for field in ("app", "route"):
        rule = re.search(r'match\(nginx_reason, "([^"]+)"\)', props["idlab:nginx:error"][f"EVAL-{field}"]).group(1)
        assert bool(pcre(rule).search(reason)) == bool(signature)
    if signature:
        assert {row["signature"]: row["runbook"] for row in causes()}[signature] == runbook


def test_forwarded_headers_cause_names_the_proxy():
    f = fields("keycloak", "invalid_destination")
    assert (f["kc_error"], f["kc_reason"]) == ("invalid_authn_request", "invalid_destination")
    row = {r["signature"]: r for r in causes()}["kc_invalid_destination"]
    assert row["runbook"] == "09-proxy-forwarded-headers"
    assert row["cause"].startswith("Reverse proxy is the likely cause") and "nginx logs nothing" in row["cause"]
    assert props["idlab:keycloak"]["EVAL-app"].startswith(
        'case(kc_error=="invalid_authn_request" AND kc_reason=="invalid_destination", "keycloak (via proxy)", ')


def test_proxy_rows_are_app_proxy_with_their_route():
    s = props["idlab:nginx:error"]
    assert re.fullmatch(r'if\(match\(nginx_reason, "[^"]+"\), "proxy", null\(\)\)', s["EVAL-app"])
    assert s["EVAL-route"] == s["EVAL-app"].replace('"proxy"', "site")


def test_eventtypes_and_tags_line_up():
    eventtypes, tags = read_conf("eventtypes.conf"), read_conf("tags.conf")
    tagged = {s.removeprefix("eventtype=") for s in tags.sections()}
    assert tagged == set(eventtypes.sections())
    auth = {s.removeprefix("eventtype=") for s in tags.sections() if tags[s].get("authentication") == "enabled"}
    assert {s.removeprefix("eventtype=") for s in tags.sections() if tags[s].get("web") == "enabled"} == {
        "idlab_proxy_access", "idlab_egress_access"}
    assert tags["eventtype=idlab_egress_access"]["proxy"] == "enabled"
    assert auth == {"idlab_keycloak_login", "idlab_sp_login", "idlab_api_auth", "idlab_radius_auth", "idlab_ldap_bind_failure"}


def test_report_sourcetypes_are_json():
    for sourcetype in hec_send.TOOLS.values():
        assert props[sourcetype]["KV_MODE"] == "json"


def test_fixture_times_are_plausible():
    # Guards against a fixture typo that would silently land outside the scenario window.
    for path in (FIXTURES / "logs").glob("*.log"):
        for line in path.read_text().splitlines():
            ts = hec_send.docker_ts(line)
            assert ts and dt.datetime(2026, 10, 19, 18, tzinfo=dt.UTC) <= ts < dt.datetime(2026, 10, 19, 19, tzinfo=dt.UTC)


def test_calculated_fields_never_use_each_other():
    """Splunk evaluates a stanza's EVAL- fields independently, so one that
    reads another sees the extracted value (or nothing), not the result."""
    for sourcetype in props.sections():
        calculated = {k.removeprefix("EVAL-") for k in props[sourcetype] if k.startswith("EVAL-")}
        for key, expr in props[sourcetype].items():
            if key.startswith("EVAL-"):
                used = set(re.findall(r"(?<![\w.\"'])([A-Za-z_][\w.]*)\b(?!\s*\()", re.sub(r'"[^"]*"', '""', expr)))
                assert not (used & calculated) - {key.removeprefix("EVAL-")}, (sourcetype, key)



def test_app_lines_with_values_masked_by_the_lab():
    f = fields("oidc-rp", "detail='state=***'")
    assert (f["event"], f["reason"], f["error"], f["detail"]) == (
        "oidc_login_failed", "access_denied", "User denied consent", "state=***")
    assert "state" not in f, "the quoted detail is one value, not a field of its own"
    f = fields("oidc-rp-egress", "/auth/callback?state=***")
    assert (f["src"], f["http_method"], f["uri_path"], f["status"]) == ("192.0.2.30", "GET", "/auth/callback", "502")



def test_app_quoted_value_with_quotes_inside_is_kept_whole():
    """shlex.quote writes a ' inside a quoted value as '"'"'."""
    f = fields("oidc-rp-egress", "Tunnel connection failed: 407")
    assert f["error"].startswith("HTTPSConnectionPool(host='\"'\"'keycloak'\"'\"', port=8180): Max retries")
    assert f["error"].endswith("Tunnel connection failed: 407 Proxy Authentication Required'\"'\"')))")
    assert f["detail"] == "ProxyError" and "port" not in f, "no pairs from inside a quoted value"


def test_edge_rp_force_https_fields():
    f = fields("oidc-rp-edge", "path=/login scheme=http")
    assert (f["sp_app"], f["event"], f["path"], f["scheme"], f["x_forwarded_proto"]) == (
        "oidc-rp", "force_https", "/login", "http", "-")
    f = fields("oidc-rp-edge", '"GET /login HTTP/1.1" 302')
    assert (f["src"], f["uri_path"], f["status"]) == ("192.0.2.40", "/login", "302")


# --- the egress proxy (Squid) ------------------------------------------------

def test_squid_access_fields():
    f = fields("squid", "TCP_DENIED/407")
    assert (f["elapsed_ms"], f["src"], f["result_code"], f["status"], f["bytes"]) == ("0", "192.0.2.40", "TCP_DENIED", "407", "3413")
    assert (f["http_method"], f["url"], f["dest_host"], f["dest_port"]) == ("CONNECT", "keycloak:8180", "keycloak", "8180")
    assert (f["squid_user"], f["hierarchy_code"], f["peer"], f["http_content_type"]) == ("-", "HIER_NONE", "-", "text/html")


@pytest.mark.parametrize("contains, result_code, status", [
    ("TCP_DENIED_ABORTED/403", "TCP_DENIED_ABORTED", "403"),
    ("NONE_NONE/200", "NONE_NONE", "200"),
    ("egress-svc", "TCP_TUNNEL", "200"),
])
def test_squid_result_codes(contains, result_code, status):
    f = fields("squid", contains)
    assert (f["result_code"], f["status"]) == (result_code, status)


def test_squid_access_to_a_destination_that_is_not_the_idp():
    f = fields("squid", "localhost:8182")
    assert (f["dest_host"], f["dest_port"], f["status"]) == ("localhost", "8182", "403")


def test_squid_access_cim_fields():
    s = props["idlab:squid:access"]
    assert 'match(result_code, "DENIED"), "blocked", "allowed"' in s["EVAL-action"]
    assert s["EVAL-user"] == 'if(squid_user == "-", null(), squid_user)'
    assert s["EVAL-duration"] == "tonumber(elapsed_ms) / 1000"


def test_squid_cache_tls_error():
    f = fields("squid", "Cannot accept a TLS connection")
    assert (f["log_level"], f["squid_message"]) == ("ERROR", "Cannot accept a TLS connection")
    assert f["squid_error_detail"] == "SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000418+TLS_IO_ERR=1"
    assert (f["tls_squid_err"], f["tls_lib_err"]) == ("SQUID_TLS_ERR_ACCEPT", "A000418")


def test_squid_cache_plain_and_warning_messages():
    f = fields("squid", "Reconfiguring")
    assert "log_level" not in f and f["squid_message"] == "Reconfiguring Squid Cache (version 7.7)..."
    assert fields("squid", "no_suid")["log_level"] == "WARNING"


def test_squid_tls_lib_errors_lookup_decodes_unknown_ca():
    assert props["idlab:squid:cache"]["LOOKUP-squid_tls_lib_errors"] == "squid_tls_lib_errors tls_lib_err OUTPUT tls_error"
    assert transforms["squid_tls_lib_errors"]["filename"] == "squid_tls_lib_errors.csv"
    with (APP / "lookups/squid_tls_lib_errors.csv").open(newline="") as f:
        rows = {r["tls_lib_err"]: r["tls_error"] for r in csv.DictReader(f)}
    assert rows["A000418"] == "tlsv1 alert unknown ca"
    assert all(re.fullmatch(r"A000[0-9A-F]{3}", code) and text for code, text in rows.items())


def eval_case(expr, f, source):
    """Evaluate the egress rules of an EVAL-signature case(): ANDs of field=="x", match(field, "re")."""
    for cond, sig in re.findall(r'((?:(?:\w+=="[^"]*"|match\(\w+, "(?:[^"\\]|\\.)*"\))(?: AND )?)+), "([a-z_]+)"', expr):
        ok = True
        for name, value in re.findall(r'(\w+)=="([^"]*)"', cond):
            ok &= f.get(name) == value
        for name, pattern in re.findall(r'match\((\w+), "((?:[^"\\]|\\.)*)"\)', cond):
            value = source if name == "source" else f.get(name, "")
            ok &= bool(pcre(pattern.replace("\\\\", "\\")).search(value))
        if ok:
            return sig
    return None


@pytest.mark.parametrize("contains, signature", [
    ("TCP_DENIED/407", "egress_proxy_auth_required"),
    ("TCP_DENIED/403 3331", "egress_proxy_policy_block"),
    ("TCP_DENIED_ABORTED/403", "egress_proxy_policy_block"),
    ("localhost:8182", "egress_proxy_policy_block"),
    ("egress-svc", None),
    ("NONE_NONE/200", None),
])
def test_squid_access_signature(contains, signature):
    f = fields("squid", contains)
    assert eval_case(props["idlab:squid:access"]["EVAL-signature"], f, "docker:squid") == signature


def test_squid_tls_error_signature():
    s = props["idlab:squid:cache"]
    f = fields("squid", "Cannot accept a TLS connection")
    assert pcre(re.search(r'match\(squid_error_detail, "([^"]+)"\)', s["EVAL-signature"]).group(1)).search(
        f["squid_error_detail"])
    assert "egress_proxy_tls_untrusted" in s["EVAL-signature"] and '"egress proxy"' in s["EVAL-app"]


@pytest.mark.parametrize("contains, signature", [
    ("Tunnel connection failed: 407", "egress_app_proxy_auth_required"),
    ("Tunnel connection failed: 403", "egress_app_proxy_policy_block"),
    ("CERTIFICATE_VERIFY_FAILED", "egress_app_tls_untrusted"),
    ("Failed to resolve '\"'\"'keycloak", "egress_app_proxy_bypassed"),
    ("Failed to resolve '\"'\"'squid", "egress_app_proxy_unreachable"),
])
def test_egress_app_signature(contains, signature):
    f = fields("oidc-rp-egress", contains)
    assert f["reason"] == "backchannel_failed"
    assert eval_case(props["idlab:sp"]["EVAL-signature"], f, "docker:oidc-rp-egress") == signature


def test_bypass_and_tls_rules_only_apply_to_the_app_behind_the_proxy():
    f = fields("oidc-rp-egress", "CERTIFICATE_VERIFY_FAILED")
    assert eval_case(props["idlab:sp"]["EVAL-signature"], f, "docker:oidc-rp") is None


def test_proxied_egress_and_edge_app_names():
    for key in ("EVAL-app", "EVAL-dest"):
        assert 'replace(source, "^.*(-proxied|-egress|-edge)$", "\\1")' in props["idlab:sp"][key]


# --- the API (bearer tokens) -------------------------------------------------

def test_api_healthz_is_dropped_at_index_time():
    assert props["idlab:api"]["TRANSFORMS-null_healthz"] == "idlab_sp_drop_healthz"
    t = transforms["idlab_sp_drop_healthz"]
    assert [e for e in events("api") if pcre(t["REGEX"]).search(e)] == [e for e in events("api") if "/healthz" in e]


def test_api_rejection_fields():
    f = fields("api", "does not include idlab-api")
    assert (f["log_level"], f["event"], f["error"]) == ("WARNING", "api_token_rejected", "invalid_token")
    assert f["error_description"] == "The access token audience (idlab-api-staging account) does not include idlab-api"
    assert (f["sub"], f["azp"], f["aud"]) == ("0b6f6f1e-3c1b-4d4e-9a55-1f2e3d4c5b6a", "oidc-rp", "idlab-api-staging account")
    assert (f["iss"], f["exp"], f["iat"]) == (
        "https://idp.idlab.example:8180/realms/idlab", "2026-10-19T18:56:50Z", "2026-10-19T18:51:50Z")


def test_api_claims_the_token_lacks_are_not_fields():
    f = fields("api", "error=no_token")
    assert f["error"] == "no_token"
    assert not {"error_description", "sub", "azp", "aud", "iss", "exp", "iat"} & set(f)


def test_api_rejection_without_iat():
    f = fields("api", "expired at 2026-10-19T18:54:00Z")
    assert f["exp"] == "2026-10-19T18:54:00Z" and "iat" not in f


def test_api_access_line():
    f = fields("api", '"GET /v1/whoami HTTP/1.1" 400')
    assert (f["src"], f["http_method"], f["uri_path"], f["status"]) == ("192.0.2.50", "GET", "/v1/whoami", "400")


def test_api_is_cim_authentication():
    et = read_conf("eventtypes.conf")["idlab_api_auth"]["search"]
    assert et == "sourcetype=idlab:api (event=api_request_ok OR event=api_token_rejected)"
    assert read_conf("tags.conf")["eventtype=idlab_api_auth"]["authentication"] == "enabled"
