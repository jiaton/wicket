# Changelog

Dates are when the change went live on the maintainer's deployment. Everything below is in `main`.

## 2026-10-28

- **First-run setup.** A deploy needs only `zone` (and `routes: wildcard`) in `wicket.yaml`. Without an `OWNER_PASSWORD` secret, `cf deploy` prints a one-time link where the owner picks passwords in the browser (PBKDF2-SHA256 hashes in KV), allow-lists their address and may paste a Cloudflare token. `setup: false` keeps the secrets-only path.
- **Settings page** now owns hosts (mode, recipe, country rule, pass-through; 24-hour counts per host), access lists and trust, every limit, shares, passwords, Cloudflare wiring, the notification policy and searchable bans. Saves are live everywhere within 30 s; *Reset* returns to `wicket.yaml`.
- **Pass-through rules** (`hosts.<name>.passthrough`): requests carrying the app's own credential (headers, cookies, query parameters, optional path prefixes and rejection statuses; preset `api`) reach the app, which validates them; its rejections count toward `limits.origin`. wicket stores no app tokens.
- **Share links**: one host, 1 hour to 30 days, host-only cookie, revocable.
- **Country rules** per host: `countries: {allow: […]}` or `{deny: […]}`.
- **Host modes** `open` (forwarded untouched, bans apply) and `off` (maintenance page). `routes: wildcard` with `default_mode` for hosts not listed.
- **Cloudflare section**: verifies the API token, probes Analytics Engine, creates the IP list and the zone WAF rule with one click each; ids live in KV.
- **Security review fixes**: fail closed for five minutes when KV writes fail (free-tier quota), IPv6 counted and banned by /64, unban links bound to their ban, traversal-safe prefix checks, the session cookie wins over a stray app header, app-style carriers never move the lockdown counter, wrong tokens during a lockdown still strike, 2xx scanner scope limited to a short sensitive-file list, slow-scanner analysis counts 400/404/405 only, logout requires same-origin, forwarded requests log two path segments, `cookie_domain: ""` for host-only cookies.
- **Operations**: `wicket-apply-secrets` fails when `cf deploy` fails; Node import extensions in deploy-time code.

## 2026-10-11

- Ban bookkeeping after reading live logs: ban kinds in outcomes (`ban`, `ban-scan`, `ban-origin`), isolate memory of recent bans (no repeat bans while KV caches a miss), one KV write per ban, digest lines deduplicated, Lists API 429 retry plus a five-minute repair queue, reconcile grace period for young list items, API keys sprayed at scanner paths never trigger a lockdown, `/.env`-style files count on observe hosts even when the app answers 200.
- Deploy from the Cloudflare dashboard (Workers Builds) with the config in a build variable.

## 2026-10-10

- Scanner signatures from the OWASP Core Rule Set, slow-scanner bans from the five-minute analysis, `allow_dns`, trusted addresses after an owner login.
- Notification policy per kind with hourly digests; owner settings page; traffic analysis split into detectors.

## 2026-10-07

- Renamed from `gate` to `wicket`; `wicket.yaml` compiled at deploy time; hourly KV ↔ IP-list reconcile; request-path fallback for Cloudflare's cron.
