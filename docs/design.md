# wicket — design

**One password and a ban list for everything you self-host behind a Cloudflare Tunnel. No Access, no fail2ban, no server.**

wicket is a single Cloudflare Worker that stands in front of the hostnames you expose through a Cloudflare Tunnel. It is for people who run services at home (a NAS, a Home Assistant box, a handful of apps they wrote) and want them reachable from the internet without Cloudflare Access's per-browser identity flow and without maintaining fail2ban on the host.

## What it is not

- **Not a reverse proxy.** Your reverse proxy (Caddy, nginx, Traefik) keeps routing; wicket only decides whether a request may reach it.
- **Not for video or large files.** Cloudflare's terms forbid serving disproportionate media through the proxy without their paid products. Jellyfin/Emby/Plex streams, Immich originals, big downloads stay on a direct (DNS-only) hostname, protected by the app's own login and, if you like, fail2ban. wicket's fail2ban action (`contrib/fail2ban/`) makes those bans reach the edge too.
- **Not an identity system.** One shared password (optionally a second one for friends) and host-scoped API tokens. If you need per-user accounts, use Access or an SSO proxy.

## Per-host modes

Every routed hostname has a mode in the config:

| mode | password page | tokens | bans enforced | what is counted |
|---|---|---|---|---|
| `gated` | yes | yes | yes | wrong passwords/tokens, anonymous probe bursts |
| `observe` | no (requests pass straight through) | n/a | yes | origin login failures (watch rules / recipes), 4xx probe bursts |
| (no route) | — | — | — | nothing; the Worker never runs |

`observe` is for apps that have their own login and native clients that cannot answer a password page (Home Assistant's companion app, Immich's mobile app, a public site). The Worker still blocks banned addresses, still detects scanners, and learns about failed logins by looking at the origin's responses.

## Request pipeline

The Worker is an ordered list of steps (`src/pipeline/handler.ts`); the first one that answers wins. The order *is* the security model:

1. wicket's own endpoints (`/__wicket/login|logout|unban`), so a banned owner can still use the signed unban link
2. allow-listed addresses pass
3. banned addresses get 403 on every host and path
4. `/.well-known/acme-challenge/` passes (certificate renewals)
5. observe-mode hosts: forward, watch, count
6. configured bypass prefixes pass
7. `OPTIONS` preflights pass (browsers send them without cookies)
8. API tokens: registered → pass; wrong explicit token → strike; foreign bearer → ignored
9. session cookie → pass
10. nothing presented: known scanner path/agent (third hit) or probe burst → scanner ban, else the password page (JSON 401 for non-browsers)

## Ban triggers

All triggers end in the same place (`src/actions/ban.ts`): a permanent `ban:<ip>` in KV, the address appended to a Cloudflare IP list (a zone WAF rule blocks it at the edge for every proxied host), and a notification with a signed one-click **Unban** link.

| trigger | mode | counter | default |
|---|---|---|---|
| wrong password | gated | per IP, KV | 3 in 24 h |
| wrong API/app token | gated | per IP, KV | 3 in 24 h |
| rotating-IP guessing | gated | global, KV → lockdown (no bans) | 10 in 10 min → 1 h pause |
| scanner (signature) | both | requests for known scanner paths/agents per IP, isolate memory | 3 in 10 min |
| scanner | gated | anonymous rejections per IP, isolate memory | 100 in 60 s |
| scanner | observe | origin 404/400/405 per IP, isolate memory | 100 in 60 s |
| scanner (slow) | both | anonymous probes per IP, Analytics Engine, network-wide, every 5 min | 30 in 5 min |
| origin login failure | observe | matched watch rule per IP, KV | 5 in 10 min |

### Watch rules and recipes

Counting every 401 from an origin would ban legitimate users of apps that answer 401 to anonymous page loads. Rules are therefore explicit: `{ path prefix, methods, statuses }`. The repository ships **recipes** (the fail2ban `filter.d` idea) for common self-hosted apps, so a host can say `recipe: immich` instead of spelling out rules. Apps whose login failure is a `200` with an error body (Home Assistant, Nextcloud, Gitea) cannot be detected by status; their recipes cover what *is* detectable (token misuse on the API) and the docs point at the app's own lockout.

## Configuration

Workers have no filesystem, so the user-facing file `wicket.yaml` is compiled when the deploy config is evaluated: `deploy/config.ts` reads and validates it, `cloudflare.config.ts` (cf CLI) turns it into routes, cron triggers and plain-text variables, and `deploy/wrangler.ts` writes the same thing as `wrangler.jsonc`. The Worker itself only ever sees variables (`HOSTS_JSON`, `ALLOW_IPS`, the limits, …) and parses them defensively in `src/config/`. Validation happens at deploy time so a typo stops the deploy instead of silently changing a host's mode; the Worker-side parser still falls back to `gated` for anything it does not understand.

```yaml
zone: example.com
hosts:
  nas.example.com:    gated
  photos.example.com: { mode: observe, recipe: immich }
  ha.example.com:     { mode: observe, recipe: home-assistant }
  home.example.com:
    mode: observe
    watch: [{ path: /api/unlock, methods: [POST], status: [401] }]
```

## Notifications

Events carry a **kind** (scanner, credentials, app_logins, lockdown, traffic, reconcile, unban) and a **severity** (scanner ban `info`, password/token/origin ban `warn`, lockdown `critical`, cron anomalies `info`). The *policy* maps each kind to `immediate`, `digest` or `off`, with one digest window; it comes from `wicket.yaml` and can be changed at runtime on the owner-only `/__wicket/settings` page (saved in KV, so no redeploy; *Reset* returns to the file). Scanner bans are digested by default because the internet scans constantly and a human cannot act on them anyway; credential bans stay immediate because they might be a person. Channels are small HTTP adapters (Telegram, ntfy, Discord, Slack, generic webhook, Apprise) with a minimum severity each and an optional `batch` flag that turns a channel into a digest-only channel. Digests collapse bans of one kind into one line; traffic alerts skip addresses that are already banned.

## Traffic analysis

Every request writes one row to Analytics Engine: host, path, address, country, **outcome** (`pass`, `token`, `login`, `fail`, `ban`, `banned`, `reject`, `observe`, `origin-fail`, …), method, status, duration. The outcome is what makes the analysis precise: a `401` from a wrong wicket password (`fail`) and a `401` from a scanner probing `/wp-login.php` (`reject`) are different rows, not the same "4xx".

Every five minutes (`src/cron/analyze.ts`):

1. **One base query** over the last five minutes, grouped by address, country, outcome and host.
2. **Fold** (`addresses.ts`): per address, how many wicket credential failures, app login failures (observe mode), anonymous probes, and on which hosts; whether a ban happened in this window.
3. **Slow scanner bans** (`slow-scanner.ts`): any address with `limits.scanning` or more probes in the window is banned through the same exit as every other ban. The request-path counter is per data centre and in memory, so it only sees bursts; this count is network-wide and sees the patient scanner too.
4. **Detectors** (`detectors/`): each is a small file with an `id` and `run(ctx) → Alert[]`. The context gives it the folded addresses, a `query()` for its own SQL, and `alreadyBanned()` / `failureCount()` lookups. Shipped: `credentials` (any wrong wicket password/token, with the count left before the ban), `guessing` (several addresses failing at once), `app-logins`, `scanning` (probes below the ban line, bursts), `new-country`, `quiet-hours`. A detector never sends anything.
5. **Dedup and send**: each alert's `key` is remembered in KV for an hour, so a sustained event pings once; surviving alerts are grouped by `kind` and emitted as one event per kind, which the notification policy then delivers immediately, in the digest, or not at all.

The tiers, least to most serious: scanning (`traffic`, digest by default) → scanner bans (`scanner`, digest) → app login failures (`app_logins`) → wicket credential attempts (`credentials`, even a single one) → lockdown (`critical`). Addresses already banned are skipped everywhere: a scanner is reported once, as its ban.

Why a fixed window and not an incremental cursor: Analytics Engine samples and rows arrive late by tens of seconds; a watermark would miss them, while "last five minutes + one-hour dedup" sees everything and still never repeats. Overlapping or missed runs (the cron fallback) are harmless for the same reason.

## Cloudflare side

Required once per account: the Analytics Engine switch (dashboard only), an IP list, a WAF custom rule `ip.src in $<list>` → block, and an API token with *Account Rule Lists: Edit* (+ *Account Analytics: Read* for the cron alerts).

Two periodic jobs: every five minutes the traffic analysis and the notification digests; hourly the **reconcile** (`src/cron/reconcile.ts`), which adds KV bans missing from the list (an API call failed, the list was recreated) and removes list items wicket wrote whose KV ban is gone. Items written by anyone else (fail2ban, manual) are identified by their comment and never touched, so one list can have several writers.

Both jobs are started by Cloudflare's Cron Triggers **and** by the request path: each isolate checks its own clock and, once a window has passed, takes a short KV lock and runs the job in the background. Cron Triggers have been observed to stop being delivered for a Worker while `/schedules` still lists them (this project and several community reports in 2026), and a security tool whose alerts silently stop is worse than one that spends a few KV writes. Whichever fires first takes the lock; the other skips.

## Companion: fail2ban on the host

If you still run fail2ban for the direct hostnames, `contrib/fail2ban/` adds its bans to the same IP list, so one list serves both worlds.

## Threat model

What wicket defends against:

- **Opportunistic scanning and credential stuffing** against the apps behind it. An anonymous visitor to a gated host sees only the password page; the app's own login, API and bugs are unreachable. Probe bursts and wrong credentials lead to a permanent per-address ban enforced at Cloudflare's edge.
- **Password guessing against wicket itself.** Three wrong answers per address, then a ban; an address-independent counter catches guessing spread over many addresses and pauses password entry site-wide (lockdown) while sessions and tokens keep working, so the attacker loses the oracle without locking you out.
- **Brute force against apps in observe mode**, to the extent their failure is visible in a status code.
- **Credential leakage to origins.** wicket's cookie and token are stripped before the request is forwarded; a compromised app cannot replay them.
- **Cross-site request forgery on the login form** (`Sec-Fetch-Site` check) and **cookie theft via subdomain takeover is limited** by `HttpOnly`, `Secure`, `SameSite=Lax` and an HMAC that mixes in the current password, so rotating the password invalidates every cookie.

What it does not defend against:

- **A leaked shared password.** Anyone with it is you (or your friend). Rotate it; that logs out every browser that used it.
- **An attacker already inside your allow-listed network**, or on the same carrier-grade NAT address as you (allow list) or as a banned address (collateral ban).
- **Attacks that bypass Cloudflare**: if your origin is reachable directly (open ports, a leaked origin IP), wicket never sees the traffic. Use the Tunnel so the origin has no inbound ports.
- **Application-layer vulnerabilities on observe-mode hosts.** Those apps are exposed by choice; wicket only adds bans and detection.
- **Timing side channels on KV.** Bans and counters are eventually consistent, so a burst within a few seconds may get one extra attempt before the ban lands; the edge list closes that gap once the API call completes.
- **Cloudflare itself.** wicket trusts `CF-Connecting-IP` and the proxy; it is a Cloudflare-native tool by design.
