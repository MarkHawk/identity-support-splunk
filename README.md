# Identity Support for Splunk

**A Splunk app that answers the three questions every support ticket
starts with: when did it start, who is affected, and what is the likely
cause?** It reads the logs from
[identity-lab](https://github.com/MarkHawk/identity-lab) (the identity
provider, a SAML service provider, an OIDC relying party, a RADIUS
server, a NAS and an LDAP directory) and the JSON reports from
[token-inspector](https://github.com/MarkHawk/token-inspector) and
[rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe). Each
failure gets a likely cause and a link to the identity-lab runbook that
explains it.

It ships with sample data captured from a real identity-lab run, so you
can try it without the lab.

## Try it in 5 minutes

You need Docker with Compose, Python 3.12 or later, and about 2 GB of
free disk space for the Splunk image.

```
git clone https://github.com/MarkHawk/splunk-support-app
cd splunk-support-app
python3 scripts/init_env.py
docker compose up -d
```

- `init_env.py` writes a gitignored `.env` with a random admin password and
  HEC token. It never prints them.
- `docker compose up -d` downloads Splunk Enterprise 10.4.4 the first time
  (about 1.5 GB, so a few minutes on a typical connection). It then starts
  Splunk, which takes another minute or two, and waits until Splunk reports
  healthy. A loader container then sends the samples, with times moved so the
  newest event is a minute old. `docker compose logs loader` shows what it sent.

Then open <http://localhost:18000> and sign in as `admin` with the
`SPLUNK_PASSWORD` value from `.env`. The app opens on **Support overview**.
The samples cover about two minutes, so set the time picker to *Last 15
minutes* to spread them out.

When you've finished, `docker compose down -v` removes the stack and its
data. Everything listens on 127.0.0.1 only, on ports 18000 (web), 18088
(HEC) and 18089 (management). That leaves a Splunk you already run on 8000
and 8088 alone.

## What you see

**Support overview**
- Failures, users affected, and the first and latest failure.
- Failures over time, stacked by likely cause.
- *When did it start?* One row per cause with first and last seen, count,
  users and apps. Select a row to open its runbook.
- *Who is affected?* Users and apps, each with their causes.
- *RADIUS: Access-Reject versus no reply.* A reject means the server
  answered no. No reply means it dropped or ignored the request (a shared
  secret mismatch, or an unknown NAS), which users see as a timeout.
- *LDAP binds refused by the directory* (result 49, invalid credentials),
  next to the identity provider's own LDAP errors.

**Tool reports**
- token-inspector verdicts, likely causes and failed checks, with runbook
  links.
- rate-limit-probe reports: 429s seen, verdict, likely cause and problems
  found.

**Alerts** (Activity > Triggered Alerts; no actions are configured)

| Alert | Fires when | Runbook |
|---|---|---|
| SSO failure rate jumped | 5 or more failed SSO logins in 10 minutes, and over 3 times the previous hour's rate | 01 to 04 |
| RADIUS server not responding | any request dropped or ignored in the last 5 minutes | 05 |
| LDAP bind failing (result 49) | the directory or the IdP's LDAP federation reports 49 in the last 15 minutes | 04 |
| SAML certificate or clock problem | the SP refuses logins for a certificate or clock reason in the last 15 minutes | 01, 02 |
| rate-limit-probe found a problem | a report in the last hour has a FAIL | (the report's own next step) |

The samples set off the LDAP and SAML alerts at the next five-minute run.
The RADIUS alert looks back only five minutes, so it can miss them by the
time it runs. The capture is also too short for the SSO spike. On Splunk
Free there is no alerting: the same searches still run as reports.

## How it works

Container logs are shipped as `docker logs --timestamps` output, so every
event is timed by Docker's clock, the same for every component (slapd's own
timestamps are hexadecimal). Line breaking only splits where a new event
starts, so a Java stack trace or a Python traceback stays whole.

| Sourcetype | From | Key fields |
|---|---|---|
| `idlab:keycloak` | identity provider | `kc_type`, `kc_error`, `kc_clientId`, `kc_username`, `ldap_result_code` (from stack traces) |
| `idlab:sp` | SAML SP and OIDC RP | `event`, `reason`, `error`, `name_id` / `email`; health checks dropped at index time |
| `idlab:radius` | RADIUS server | `radius_result`, `radius_outcome` (Access-Accept, Access-Reject, no reply), `user`, `nas_client` |
| `idlab:nas` | NAS client output | `nas_result`, `radius_outcome`, `attempts` |
| `idlab:slapd` | LDAP directory | `conn`, `op`, `bind_dn`, `err` (a bind is two lines, joined on `conn` and `op`) |
| `token_inspector:report` | token-inspector `--json` | `verdict`, `likely_cause`, `runbook_url` |
| `rate_limit_probe:report` | rate-limit-probe `--json` | `verdict`, `likely_cause`, `target_url`, `status_429` |

- **CIM:** login events map to the Authentication data model (`action`,
  `app`, `dest`, `src`, `user`, `reason`, `signature`), tagged
  `authentication`. So do the directory's failed binds.
- **Likely cause:** each failure gets a short `signature`, such as
  `saml_clock_skew` or `radius_bad_shared_secret`. The
  [`support_causes`](identity_support/lookups/support_causes.csv) lookup
  turns it into a cause, a runbook and its URL.
- **Index:** everything lives in the `identity_support` index (90 days).
  Searches go through the `` `support_index` `` macro, so pointing the app
  at another index is a one-line change in `local/macros.conf`.

## Install it on your own Splunk

1. Package the app:

   ```
   python3 scripts/package_app.py   # writes dist/identity_support-<version>.tgz
   ```

2. Install it, either:
   - in Splunk Web: *Apps > Manage Apps > Install app from file*; or
   - from the CLI: `splunk install app <file> -auth admin`.

3. Restart Splunk. The app creates the `identity_support` index.
4. Create a HEC token whose default index is `identity_support`, or one
   allowed to write to it.

## Send your own data

`sender/hec_send.py` uses only the Python standard library. It reads
`HEC_URL`, `HEC_TOKEN` and `HEC_INDEX` from the environment or `.env` and
never prints the token.

```
python3 sender/hec_send.py docker --since 30m          # identity-lab container logs
python3 sender/hec_send.py report report.json          # a token-inspector or rate-limit-probe --json report
python3 sender/hec_send.py replay samples --shift-to-now
```

- **Where things go:** container logs go to HEC's raw endpoint, so the app's
  `props.conf` breaks lines and reads times exactly as it would for a file.
  Reports go to the event endpoint with their own time.
- **Checking first:** `--dry-run` reads and counts without sending.

TLS is always verified. For Splunk's default self-signed certificate, trust
the CA that signed it and name the certificate:

```
docker cp <container>:/opt/splunk/etc/auth/cacert.pem splunk-ca.pem
python3 sender/hec_send.py --cacert splunk-ca.pem --tls-server-name SplunkServerDefaultCert docker --since 30m
```

`--insecure` also works, but only when `HEC_URL` points at `localhost` or
`127.0.0.1`. For any other host it is refused.

## Capture new samples

`scripts/capture_lab.py` never changes the lab. It records the start time,
tells you to run identity-lab's own end-to-end test (which breaks and fixes
every scenario), and waits for you. It then collects the lab's logs for
that window and the tools' reports into `captures/raw/` (gitignored), and
writes a sanitised copy to `samples/`.

`scripts/sanitise.py` does the sanitising:
- Each private address becomes its own documentation address, the same in
  every file.
- Personal email addresses, home directories and the personal strings in
  your local `.personal-patterns` are replaced.
- A private key anywhere stops the run.
- Health-check noise is trimmed.

Read the diff before committing.

## Development

```
python3 -m venv venv
venv/bin/pip install -r requirements-dev.txt
venv/bin/pytest
```

- **Offline tests:** the tests reach loopback and nothing else. They run the
  app's own regular expressions against fixtures and the samples, check that
  the sender and `props.conf` agree on event boundaries, and check that
  nothing private is committed.
- **Live tests:** `tests/test_splunk_live.py` checks the calculated fields,
  eventtypes, tags and lookups in a real Splunk. It runs against the reviewer
  stack when `SUPPORT_SPLUNK_MGMT`, `SUPPORT_SPLUNK_PASSWORD`,
  `SUPPORT_HEC_URL` and `SUPPORT_HEC_TOKEN` are set, and is skipped otherwise.
- **CI:** runs the tests, Splunk AppInspect (default and cloud checks) and a
  compose validation. AppInspect needs Python 3.13 or earlier:
  `requirements-appinspect.txt`.

## Related tools

- [identity-lab](https://github.com/MarkHawk/identity-lab): a Docker identity
  lab that reproduces SAML, OIDC, LDAP and RADIUS failures on demand, each
  with a support runbook. This app's runbook links point there.
- [token-inspector](https://github.com/MarkHawk/token-inspector): explains
  offline what is wrong with a SAML response or a JWT.
- [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe): explains
  why an integration keeps getting `429 Too Many Requests`.

## A note on how this was built

This app was written with AI-assisted tooling (Claude Code).

## Licence

MIT. See [LICENSE](LICENSE).
