# Roadmap

Who wicket is for, after the first weeks in production: people who put something they built on a public hostname, want it reachable from any device without installing a VPN client (the Tailscale gap), and do not want to run an identity provider. One password, their own Cloudflare account, bans at the edge. Everything below serves that.

Status as of 2026-10-28: open source, 97 tests, in production on fourteen hosts. The 2026-10-11 fixes held (KV writes 350–410 a day, one ban per scanner per data centre). One real lesson since: the maintainer's own phone was banned when a new app sent a token header wicket did not know. Hence phase A.

## A. Let apps keep their own auth (pass-through rules)

Today a request with `X-API-Key`, `x-access-token` or `?token=` must carry a value registered in `API_TOKENS`, or it is a strike; a foreign `Authorization: Bearer` is ignored and the client gets wicket's 401. Both are wrong for an app that validates its own tokens, and both mean wicket keeps copies of app secrets.

- Per host, `passthrough:` lists the carriers the app validates itself: headers, cookies, query parameters, optional path prefixes. A request carrying one skips the password page and reaches the app; wicket stores nothing.
- The app's answer is watched like observe mode: 401/403 count as failed logins for the address (`limits.origin`), scanner signatures and probe bursts still apply. Brute force protection stays; the app decides who is in.
- Sensible defaults users can turn on in one line: `passthrough: api` (Authorization, X-API-Key, x-access-token, ?token= on `/api/`).
- `API_TOKENS` remains for wicket-only tokens (`X-Wicket-Token`) and for apps with no auth of their own.

## Done since 2026-10-28

A (pass-through rules, custom rules editable on the page), B (hosts, access, limits on the settings page; `open`/`off` modes; wildcard routes; 24-hour counts per host; ban search), C (Cloudflare section: token check, Analytics probe, one-click IP list and WAF rule), D except TOTP (share links, country rules), E (security review, all findings fixed), and first-run setup: a deploy with only `zone` + `routes: wildcard` prints a one-time link where the owner picks passwords in the browser (PBKDF2 hashes in KV); `setup: false` keeps the secrets-only path. See CHANGELOG.md. Left: TOTP (not wanted), the Workers Builds end-to-end test, a v1.0 tag.

## B. Configure in the browser, deploy once

Deploying is one command, but every change to hosts, modes, allow lists or limits is an edit to `wicket.yaml` plus a redeploy. The settings page already owns the notification policy; it should own the rest.

- Runtime settings in KV (`settings:*`), seeded from `wicket.yaml`, read once per request with a short per-isolate cache; `wicket.yaml` stays as the reproducible base and *Reset* returns to it. Sections: Hosts (mode, recipe, pass-through, off), Access (allow_ips, allow_dns, trust_window, bypass, API tokens by name with values entered once and never shown), Limits, Notifications, Bans, Cloudflare.
- Optional wildcard route (`routes: wildcard`) so a new hostname needs no deploy: unlisted hosts get `default_mode` (`open` keeps today's promise that unlisted hosts are untouched; `gated` for people who want the safe default).
- The settings page gets a layout that survives fifty hosts: tabs, search in bans, per-host counters from Analytics (requests, rejects, bans in the last day), the last twenty events per host.

## C. Connect the user's Cloudflare account

The parts that still need the dashboard: enabling Analytics Engine, creating the IP list and the WAF rule, finding the account id. A *Cloudflare* section on the settings page takes an API token (stored as a secret via the API, never in KV), checks its permissions, creates the list and the WAF rule on the zone, verifies that Analytics Engine answers, and shows what is wired and what is not. The CLI gets the same as `npm run setup:cloudflare`.

## D. Sharing and shaping access

- **Share links**: a signed link that grants one host for a chosen time (a friend trying your app this week), revocable from the settings page; no second password to hand out.
- **Country rules** per host (`allow_countries` / `deny_countries`), the cheapest filter there is at the edge.
- **Off** mode per host (maintenance page, nothing forwarded) and **open** mode (routed but untouched, so a host can sit in the list for analytics only).
- Optional second factor for the owner password (TOTP) for people who want it; never required, never per browser.

## E. Security review follow-ups

A full read-only review of the pipeline, crypto, UI templates, ban logic and jobs is run before each phase lands; findings are fixed first. See SECURITY.md for reporting.

## F. Release

Workers Builds path tested end to end; CHANGELOG; v1.0 tag; a short screencast of deploy → first login → first ban.

Not planned: user accounts, OAuth/OIDC, email OTP, per-browser identity, proxying video or large files.
