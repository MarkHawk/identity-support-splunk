# Changelog

## 0.4.0 (2026-10-22)

Adds identity-lab's redirect loop behind the reverse proxy (runbook 15)
and its API that checks bearer tokens (runbook 16).

- **Sources:** the sender ships the `oidc-rp-edge` app copy (behind the
  proxy's plain-HTTP route) and the API.
- **Sourcetypes:** `oidc-rp-edge` logs as the other app copies, so it is
  `idlab:sp`, app `oidc-rp-edge`; its forced HTTPS redirects carry `path`,
  `scheme` and `x_forwarded_proto`. The API is `idlab:api`: `reason`,
  `status`, `sub`, `azp`, `aud`, `iss`, `exp`, `iat` and `token_lifetime`
  (`exp - iat`), with accepted and refused tokens as CIM Authentication.
  The API never logs the token, and neither does the app.
- **Causes:** a redirect loop (5 or more redirects of the same path, each
  within 2 seconds of the last) by what arrived in `X-Forwarded-Proto`:
  nothing, `https` the app ignores (trusted proxy count), or plain HTTP.
  The API's refusals by reason: wrong audience (naming the `azp` client to
  look at), expired, no token, not a Bearer header, not a JWT, untrusted
  issuer, not an access token, unverifiable signature, signing keys
  unreachable. All link runbook 15 or 16.
- **Dashboard:** 15 and 16 in "When did it start?"; the expired-token row
  names the tokens' lifetime, or says it is not in the log. A new "API
  (bearer tokens)" row: calls over time by result, and rejections by
  reason. The cause columns are wider, so the tables are about half as
  tall; nothing scrolls inside a panel.
- **Alert:** "App stuck in a redirect loop" (runbook 15). The API's
  refusals have none: they are per client, and the dashboard shows them.
- **Fix:** a failed login through the egress proxy counted twice in "When
  did it start?" (Squid and the app both log it). It counts once now; the
  egress panel shows the app's and Squid's counts in their own columns.
- **Masking:** OAuth token parameters (`access_token`, `id_token`,
  `refresh_token`, `id_token_hint`) and anything shaped like a JWT are
  masked, and the sanitiser's check fails on any left.
- **Samples:** re-captured with scenarios 15 and 16. identity-lab now
  masks nonce, code_challenge, Signature, session_code and client_data in
  the proxy's log itself.
- **Docs:** a scenario coverage table in the README, and a screenshot of
  the Forward proxy (egress) row with real lab data (runbooks 11 to 13).

## 0.3.0 (2026-10-22)

Adds identity-lab's Squid egress proxy and its four scenarios (runbooks
11 to 14).

- **Sources:** the sender ships Squid's log and the `oidc-rp-egress` app
  copy, whose calls to the IdP go through Squid.
- **Sourcetypes:** `idlab:squid` events are typed at index time as
  `idlab:squid:access` (CIM Web, tagged `proxy`: result code, status,
  CONNECT host and port) or `idlab:squid:cache` (with TLS errors; a
  lookup decodes OpenSSL's code, so `A000418` reads "tlsv1 alert unknown
  ca").
- **Causes:** proxy credentials (407, runbook 11), policy (403, including
  `TCP_DENIED_ABORTED/403`, runbook 12) and TLS interception the app
  doesn't trust (13), from Squid's side and the app's, as one row each;
  the proxy bypassed by `NO_PROXY` (14), which says the forward proxy is
  bypassed or misconfigured even though Squid logs nothing; and the proxy
  unreachable, with no runbook link.
- **Dashboard:** a "Forward proxy (egress)" row, and 11 to 14 in "When
  did it start?", which now has a routes column and shows 25 rows. Proxy
  rows have the app `proxy`, and the runbook 09 row `keycloak (via
  proxy)`. Heights measured so nothing scrolls inside a panel.
- **Alert:** "Egress proxy refusing the IdP" (407, 403, TLS), with
  runbook links; the IdP's host comes from the `egress_idp_hosts` macro.
- **Masking:** values identity-lab now masks as `***` are left as they
  are; the sanitiser still masks the ones the lab leaves (nonce,
  code_challenge, Signature, session_code, client_data).
- **Fixes:** app log values quoted with quotes inside (requests' error
  text) are kept whole, with no stray fields from inside them, and
  Splunk's automatic key=value extraction is off for the app logs.
- **Samples:** re-captured with the egress proxy. Runbook 14 has no
  app-side line in them: identity-lab recreates the app container for
  that scenario, which drops its logs.

Upgrading from 0.2.0: install with `-update 1` and restart Splunk, since
Squid's sourcetypes are set at index time.

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
