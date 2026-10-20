import base64
import json
import urllib.parse
import zlib

import pytest

from conftest import load_script

sanitise = load_script("sanitise")

# Built by concatenation so no source file holds a whole private key header.
KEY_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
# Private-looking values are built the same way, so the hygiene test (which
# scans this file too) only ever sees them at run time.
GW, NAS, OTHER = "172.30" + ".181.1", "172.30" + ".181.10", "10.1" + ".2.3"
CORP = "a@" + "corp.co.uk"
HOME = "/home/" + "someone"


def test_addresses_are_mapped_consistently_across_files(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "keycloak.log").write_text(f'x ipAddress="{GW}", y\n')
    (raw / "radius.log").write_text(f"Received packet from {NAS} then {GW}\n")
    sanitise.sanitise_tree(raw, tmp_path / "out", personal=[])
    assert (tmp_path / "out/keycloak.log").read_text() == 'x ipAddress="192.0.2.10", y\n'
    assert (tmp_path / "out/radius.log").read_text() == "Received packet from 192.0.2.11 then 192.0.2.10\n"


def test_public_and_loopback_addresses_are_kept():
    s = sanitise.Sanitiser()
    assert s.text("127.0.0.1 - - 8.8.8.8 192.0.2.5") == "127.0.0.1 - - 8.8.8.8 192.0.2.5"


def test_emails_outside_example_domains_are_replaced_but_lab_users_kept():
    s = sanitise.Sanitiser()
    out = s.text(f"alice@idlab.example {CORP} b@example.com {CORP}")
    assert out == "alice@idlab.example user1@example.com b@example.com user1@example.com"


def test_home_directories_are_replaced():
    assert sanitise.Sanitiser().text(f"{HOME}/identity-lab/x and /home/pi") == "~/identity-lab/x and /home/pi"


def test_personal_patterns_masked_except_github_account(tmp_path):
    pf = tmp_path / "p"
    pf.write_text("# comment\nSomebody\nre:(?i)labhost\n")
    s = sanitise.Sanitiser(sanitise.load_personal_patterns(pf))
    out = s.text("Somebody on LABHOST, see https://github.com/Somebody/identity-lab and Somebodyelse")
    assert out == "redacted on redacted, see https://github.com/Somebody/identity-lab and Somebodyelse"


def test_private_key_stops_the_run(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.log").write_text("fine\n")
    (raw / "b.log").write_text(KEY_HEADER + "\n")
    with pytest.raises(sanitise.UnsafeContent):
        sanitise.sanitise_tree(raw, tmp_path / "out", personal=[])
    assert not (tmp_path / "out").exists()


def test_private_key_hidden_in_base64_stops_the_run():
    hidden = base64.b64encode((KEY_HEADER + "\nAAAA" * 10).encode()).decode()
    with pytest.raises(sanitise.UnsafeContent):
        sanitise.Sanitiser().text("blob=" + hidden)


def test_deflated_saml_request_in_a_url_is_checked(tmp_path, monkeypatch):
    """A SAML redirect binding sends the AuthnRequest deflated, base64 and
    URL-encoded; a proxy's access log records it in the query string."""
    monkeypatch.setattr(sanitise, "PERSONAL_FILE", tmp_path / "absent")
    deflate = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    request = f'<samlp:AuthnRequest Destination="https://{OTHER}:8183/realms/idlab/protocol/saml"/>'.encode()
    enc = urllib.parse.quote(base64.b64encode(deflate.compress(request) + deflate.flush()).decode(), safe="")
    line = f'192.0.2.10 "GET /realms/idlab/protocol/saml?SAMLRequest={enc}&RelayState=%2F HTTP/1.1" 200 1\n'
    (tmp_path / "proxy.log").write_text(line)
    kinds = [k for _, k in sanitise.check_paths([tmp_path / "proxy.log"], personal=[])]
    assert kinds == ["private IPv4 address", "single-use login value"]


def test_url_encoded_email_is_checked(tmp_path):
    (tmp_path / "proxy.log").write_text(f'"GET /x?login_hint={urllib.parse.quote(CORP)} HTTP/1.1"\n')
    assert [k for _, k in sanitise.check_paths([tmp_path / "proxy.log"], personal=[])] == ["email address"]


def test_single_use_login_values_are_masked_consistently():
    code, state = "aedb9efb-c3ca-1c1d-6704-47f5c633d1fb.cNza9AJBNUr", "PeQFxbStmiKKMgplVeqlBAfpp49dRE"
    s = sanitise.Sanitiser()
    callback = s.text(f'"GET /auth/callback?state={state}&session_state=abc123&code={code} HTTP/1.1" 302')
    assert callback == ('"GET /auth/callback?state=masked-state-1&session_state=masked-session_state-1'
                        '&code=masked-code-1 HTTP/1.1" 302')
    # the same state in another file and line keeps its name; a new one gets the next
    assert s.text(f"/auth?response_type=code&state={state}&nonce=n0nce&code_challenge_method=S256") == (
        "/auth?response_type=code&state=masked-state-1&nonce=masked-nonce-1&code_challenge_method=S256")
    assert s.text("?state=" + "other-state-value") == "?state=masked-state-2"
    assert s.text("?SAMLRequest=fVN%2B&RelayState=%2Fdebug&SigAlg=x&Signature=S6DH") == (
        "?SAMLRequest=masked-SAMLRequest-1&RelayState=%2Fdebug&SigAlg=x&Signature=masked-Signature-1")
    # already masked samples stay as they are when sanitised again
    assert s.text(callback) == callback


def test_check_finds_unmasked_single_use_values(tmp_path):
    # built at run time, so the hygiene test never sees an unmasked value here
    (tmp_path / "a.log").write_text("GET /realms/idlab/login-actions/authenticate?session_code=" + "E4Q6cUOsih3eHTtVX\n")
    (tmp_path / "b.log").write_text("GET /x?session_code=masked-session_code-1&state=s\n")
    assert sanitise.check_paths([tmp_path], personal=[]) == [(str(tmp_path / "a.log"), "single-use login value")]


def test_json_reports_are_sanitised_value_by_value(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    report = {"tool": "rate-limit-probe", "target": {"url": f"http://{OTHER}:9000/v1"}, "sent": 13}
    (raw / "rate-limit-probe-x.json").write_text(json.dumps(report))
    sanitise.sanitise_tree(raw, tmp_path / "out", personal=[])
    out = json.loads((tmp_path / "out/rate-limit-probe-x.json").read_text())
    assert out == {"tool": "rate-limit-probe", "target": {"url": "http://192.0.2.10:9000/v1"}, "sent": 13}


def test_health_checks_are_trimmed():
    lines = [
        '2026-10-19T17:32:17.0Z 127.0.0.1 - - [19/Oct/2026:17:32:17 +0000] "GET /healthz HTTP/1.1" 200 16',
        "2026-10-19T17:32:18.0Z 2026-10-19 17:32:18,000 WARNING saml-sp event=saml_login_failed",
    ]
    assert sanitise.trim_log("saml-sp", lines) == lines[1:]


def test_slapd_keeps_only_connections_that_matter():
    lines = [
        f't conn=1 fd=11 ACCEPT from IP={GW}:1 (IP=0.0.0.0:389)',
        't conn=1 op=0 BIND dn="" method=128',
        't conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=0 text=',
        't conn=2 op=0 BIND dn="cn=keycloak-svc,ou=services,dc=idlab,dc=example" method=128',
        't conn=2 op=0 RESULT tag=97 err=49 qtime=0 etime=0 text=',
        't conn=3 op=0 BIND dn="" method=128',
        't conn=3 op=0 RESULT tag=97 err=49 qtime=0 etime=0 text=',
        "t slapd starting",
    ]
    assert sanitise.trim_log("ldap", lines) == lines[3:]


def test_main_sanitises_then_checks(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sanitise, "PERSONAL_FILE", tmp_path / "absent")
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "radius.log").write_text(f"from {OTHER}\n")
    assert sanitise.main(["--in", str(raw), "--out", str(tmp_path / "out")]) == 0
    assert "clean" in capsys.readouterr().out


def test_check_names_kinds_never_values(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sanitise, "PERSONAL_FILE", tmp_path / "absent")
    (tmp_path / "a.log").write_text(f"from {OTHER}\n")
    assert sanitise.main(["--check", str(tmp_path / "a.log")]) == 1
    err = capsys.readouterr().err
    assert "private IPv4 address" in err and OTHER not in err
