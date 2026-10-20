# Changelog

## 0.2.0 (2026-10-20)

Adds identity-lab's nginx reverse proxy and its five scenarios (runbooks
06 to 10).

- **Sources:** the sender ships the proxy's log and the `saml-sp-proxied`
  and `oidc-rp-proxied` app copies.
- **Sourcetypes:** `idlab:nginx` lines are typed at index time as
  `idlab:nginx:access` (CIM Web: status, upstream, timings) or
  `idlab:nginx:error`.
- **Causes:** no valid answer from the app behind the proxy (06), upstream
  timed out (07), rate limited (08), Keycloak's `invalid_destination`
  behind the proxy (09) and the IdP's response headers too big for the
  proxy's buffer (10), each with its runbook link.
- **Dashboard:** reverse proxy panels for responses over time and for
  5xx and 429 by likely cause; proxy causes in "When did it start?", which now shows 20 rows;
  panel heights set so nothing scrolls inside a panel.
- **Alerts:** "Reverse proxy 502/504 spike" and "Reverse proxy rate
  limiting logins", with runbook links.
- **Samples:** re-captured with the proxy scenarios. Single-use login
  values (codes, state, nonce, SAML messages and signatures) are masked.
- **Fix:** Keycloak events with `clientId="null"` no longer show an app
  called "null".

Upgrading from 0.1.0: install with `-update 1` and restart Splunk, since
the proxy's sourcetypes are set at index time. Proxy lines indexed before
the upgrade stay `idlab:nginx`.

## 0.1.0

First release.
