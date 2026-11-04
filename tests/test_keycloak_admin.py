"""scripts/keycloak_admin.py can only read: every request it would send is
a GET under the Admin REST API, or the one POST that gets the admin token."""

import ast
import datetime as dt
import json
import urllib.parse

import pytest

from conftest import ROOT, load_script

kc = load_script("keycloak_admin")

PASSWORD = "not-" + "the-admin-password"
TOKEN = "fake-" + "admin-token-value"


class FakeConnection:
    """Answers like Keycloak; records every request."""

    def __init__(self, server):
        self.server = server

    def request(self, method, url, body=None, headers=None):
        self.server.sent.append({"method": method, "url": url, "body": body, "headers": headers or {}})

    def getresponse(self):
        sent = self.server.sent[-1]
        status, payload = self.server.answer(sent)
        return type("R", (), {"status": status, "read": lambda self: json.dumps(payload).encode()})()

    def close(self):
        pass


class FakeKeycloak:
    def __init__(self, events=(), status=200):
        self.sent, self.events, self.status = [], list(events), status

    def answer(self, sent):
        path, query = urllib.parse.urlsplit(sent["url"]).path, dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(sent["url"]).query))
        if path == kc.TOKEN_PATH:
            return self.status, {"access_token": TOKEN} if self.status == 200 else {"error": "invalid_grant", "echo": PASSWORD}
        first, size = int(query.get("first", 0)), int(query.get("max", 100))
        return 200, self.events[first:first + size]

    def client(self):
        return kc.ReadOnlyAdmin("127.0.0.1", 8180, "admin", PASSWORD, connect=lambda: FakeConnection(self))


@pytest.mark.parametrize("method, path, ok", [
    ("GET", "/admin/realms/idlab/admin-events?first=0", True),
    ("POST", kc.TOKEN_PATH, True),
    ("PUT", "/admin/realms/idlab", False),
    ("DELETE", "/admin/realms/idlab/attack-detection/brute-force/users/x", False),
    ("POST", "/admin/realms/idlab/users", False),
    ("PATCH", "/admin/realms/idlab", False),
    ("HEAD", "/admin/realms/idlab", False),
    ("get", "/admin/realms/idlab", False),
    ("GET", "/realms/idlab/account", False),
    ("GET", "/admin/realms/../../realms/master", False),
    ("POST", kc.TOKEN_PATH + "/../logout", False),
    ("POST", "/realms/idlab/protocol/openid-connect/token", False),
])
def test_only_reads_and_the_token_request_are_allowed(method, path, ok):
    assert kc.allowed(method, path) is ok


@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "PATCH"])
def test_a_write_is_refused_before_anything_is_sent(method):
    server = FakeKeycloak()
    with pytest.raises(kc.WriteRefused, match="only reads"):
        server.client()._send(method, "/admin/realms/idlab")
    assert server.sent == []


def test_fetching_admin_events_sends_gets_only_after_the_token():
    server = FakeKeycloak([{"id": "e1", "time": 1793742513452}])
    server.client().admin_events("idlab", dt.datetime(2026, 11, 3, 21, tzinfo=dt.UTC), dt.datetime(2026, 11, 3, 22, tzinfo=dt.UTC))
    assert [(s["method"], urllib.parse.urlsplit(s["url"]).path) for s in server.sent] == [
        ("POST", kc.TOKEN_PATH), ("GET", "/admin/realms/idlab/admin-events")]
    assert server.sent[1]["headers"]["Authorization"] == "Bearer " + TOKEN


def test_admin_events_are_paged_and_filtered_to_the_window():
    base = 1793742000000
    events = [{"id": f"e{i}", "time": base + i * 1000} for i in range(250)]
    server = FakeKeycloak(list(reversed(events)))  # Keycloak returns the newest first
    since = dt.datetime.fromtimestamp((base + 10_000) / 1000, dt.UTC)
    until = dt.datetime.fromtimestamp((base + 20_000) / 1000, dt.UTC)
    found = server.client().admin_events("idlab", since, until)
    assert [e["id"] for e in found] == [f"e{i}" for i in range(10, 21)]
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(server.sent[1]["url"]).query))
    assert (query["dateFrom"], query["dateTo"], query["max"]) == ("2026-11-03", "2026-11-03", "100")
    assert len(server.sent) == 1 + 3  # the token, then pages of 100, 100 and 50


def test_errors_never_carry_the_password_or_the_token():
    server = FakeKeycloak(status=401)
    with pytest.raises(kc.AdminError) as err:
        server.client().admin_events("idlab", dt.datetime.now(dt.UTC), dt.datetime.now(dt.UTC))
    assert "HTTP 401" in str(err.value) and PASSWORD not in str(err.value)
    assert PASSWORD not in repr(server.client()) and TOKEN not in repr(server.client())


def test_every_request_goes_through_the_one_guarded_send():
    """No other code path in the module can send a request."""
    tree = ast.parse((ROOT / "scripts/keycloak_admin.py").read_text())
    senders = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "request"
                       for c in ast.walk(node))]
    assert [f.name for f in senders] == ["_send"]
    first = senders[0].body[0]
    assert isinstance(first, ast.If) and "allowed" in ast.unparse(first.test)
    for name in ("urllib.request", "requests", "urlopen"):
        assert name not in (ROOT / "scripts/keycloak_admin.py").read_text().replace("urllib.parse", "")
