"""Read a realm's admin events from Keycloak's Admin REST API, and nothing else.

Keycloak keeps admin events (a realm updated, a user changed) in its
database. With the jboss-logging listener at its default levels they never
reach its log, so scripts/capture_lab.py fetches them here.

This client can only read. Every request goes through ReadOnlyAdmin._send,
which refuses anything but:

    GET  /admin/realms/...                                  the Admin REST API
    POST /realms/master/protocol/openid-connect/token       the admin token itself

The one POST is how Keycloak hands out an admin token (a password grant to
admin-cli); it changes nothing. The password and the token stay in memory:
they are never written, printed or put in an error message.

A real deployment should use a dedicated account that can only view
events (the realm-management role view-events), not the admin account the
lab uses.
"""

import datetime as dt
import http.client
import json
import socket
import ssl
import urllib.parse

TOKEN_PATH = "/realms/master/protocol/openid-connect/token"
ADMIN_PREFIX = "/admin/realms/"
PAGE = 100


class AdminError(Exception):
    """A problem to report in one line; never carries a credential."""


class WriteRefused(AdminError):
    """A request this read-only client will not send."""


class _HTTPSConnection(http.client.HTTPSConnection):
    """Connects to one address, checks the certificate against another name."""

    def __init__(self, *args, tls_server_name=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._tls_server_name = tls_server_name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_server_name or self.host)


def allowed(method, path):
    """True only for a GET under the Admin REST API, or the admin token POST."""
    path = urllib.parse.urlsplit(path).path
    if ".." in path.split("/"):
        return False
    return (method == "GET" and path.startswith(ADMIN_PREFIX)) or (method == "POST" and path == TOKEN_PATH)


class ReadOnlyAdmin:
    def __init__(self, host, port, user, password, cafile=None, tls_server_name=None, timeout=15, connect=None):
        self.host, self.port, self.tls_server_name, self.timeout = host, int(port), tls_server_name, timeout
        self._user, self._password, self._token = user, password, None
        self._cafile = cafile
        self._connect = connect or self._https

    def __repr__(self):
        return f"ReadOnlyAdmin({self.host}:{self.port})"

    def _https(self):
        ctx = ssl.create_default_context(cafile=self._cafile)
        return _HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx,
                                tls_server_name=self.tls_server_name)

    def _send(self, method, path, body=None, headers=None):
        if not allowed(method, path):
            raise WriteRefused(f"refused {method} {urllib.parse.urlsplit(path).path}: this client only reads")
        conn = self._connect()
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read()
        except ssl.SSLCertVerificationError as exc:
            raise AdminError(f"Keycloak's certificate is not trusted: {exc.verify_message}") from None
        except (OSError, http.client.HTTPException) as exc:
            raise AdminError(f"cannot reach Keycloak at {self.host}:{self.port}: {exc}") from None
        finally:
            conn.close()
        if response.status != 200:
            # The body is not shown: a token endpoint's error can echo its input.
            raise AdminError(f"Keycloak answered {method} {urllib.parse.urlsplit(path).path} with HTTP {response.status}")
        try:
            return json.loads(data)
        except ValueError:
            raise AdminError(f"Keycloak's answer to {urllib.parse.urlsplit(path).path} is not JSON") from None

    def _bearer(self):
        if self._token is None:
            body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                           "username": self._user, "password": self._password})
            reply = self._send("POST", TOKEN_PATH, body, {"Content-Type": "application/x-www-form-urlencoded"})
            if not isinstance(reply, dict) or not reply.get("access_token"):
                raise AdminError("Keycloak gave no admin token")
            self._token = reply["access_token"]
        return self._token

    def get(self, path, query=None):
        url = path + ("?" + urllib.parse.urlencode(query) if query else "")
        return self._send("GET", url, headers={"Authorization": "Bearer " + self._bearer(), "Accept": "application/json"})

    def admin_events(self, realm, since, until):
        """The realm's admin events from since to until (aware datetimes),
        oldest first. Keycloak filters by whole days, so the times are
        filtered here."""
        path = ADMIN_PREFIX + urllib.parse.quote(realm, safe="") + "/admin-events"
        lo, hi = since.timestamp() * 1000, until.timestamp() * 1000
        found, first = [], 0
        while True:
            page = self.get(path, {"dateFrom": since.astimezone(dt.UTC).strftime("%Y-%m-%d"),
                                   "dateTo": until.astimezone(dt.UTC).strftime("%Y-%m-%d"),
                                   "first": first, "max": PAGE})
            if not isinstance(page, list):
                raise AdminError("Keycloak's admin events are not a list")
            found += [e for e in page if isinstance(e, dict) and lo <= e.get("time", -1) <= hi]
            if len(page) < PAGE:
                break
            first += PAGE
        return sorted(found, key=lambda e: e["time"])
