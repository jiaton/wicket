# Configuration reference

Everything lives in `wicket.yaml` (compiled into the Worker at deploy time, validated: an unknown recipe, a host outside the zone or a typo in a mode stops the deploy) and in the secrets. Durations accept `30s`, `10m`, `24h`, `7d`.

Hosts, access lists, limits and the notification policy can also be changed on the owner-only settings page (`/__wicket/settings`) without a redeploy: those changes are stored in KV, layer over the file (a saved section replaces that section of the file, it does not merge), and *Reset* returns to it. A host must still be routed to the Worker; with `routes: wildcard` every subdomain is, so adding a host is a form on that page.

Country rules (`countries: {allow: [...]}` or `{deny: [...]}`, ISO codes) refuse visitors from other countries with 403 before any credential is looked at; allow-listed addresses are exempt. Unknown countries pass a deny list and fail an allow list. On the settings page: `allow:US,CA` or `deny:RU`.

Host modes: `gated` (password page unless a cookie, token or pass-through credential is present), `observe` (forwarded, the app's own login watched, scanners banned), `open` (forwarded untouched, bans still apply; a host that only wants analytics), `off` (503 maintenance page).

```yaml
zone: example.com                 # every host must be inside it
worker: wicket                    # Worker name
setup: true                       # first-run setup page while no owner password exists (secrets or KV); false = secrets only
routes: explicit                  # explicit = one route per host below; wildcard = *.example.com/*, unlisted hosts get default_mode
default_mode: gated               # wildcard routes only: gated | observe | open | off for hosts not listed
site_name: example.com            # prefix of every notification; default = zone
cookie_domain: example.com        # one login per domain; default = zone. "" = host-only cookie, one login per host
cookie_days: 365

hosts:
  nas.example.com: gated
  api.example.com: { passthrough: api }   # gated, but the app's own tokens reach the app (see Pass-through)
  eu.example.com: { countries: { allow: [DE, FR] } }   # or deny: [RU]; 403 for everyone else, allow-listed addresses excepted
  photos.example.com: { mode: observe, recipe: immich }
  blog.example.com:
    mode: observe
    watch: [{ path: /api/unlock, methods: [POST], status: [401] }]

allow_ips: [203.0.113.7]          # pass without a password (login page still available); your home IP. IPv4, IPv4 CIDR, IPv6 (matches its /64) or IPv6 CIDR
allow_dns: []                     # DDNS names resolved every 5 min, same effect as allow_ips
trust_window: 24h                 # an address that logged in as owner is immune to counting/bans this long; 0 = off
bypass: [nas.example.com/hooks/]  # host/prefix that passes without credentials

limits:
  password: { count: 3, window: 24h }                  # wrong passwords/tokens per address
  rotating: { count: 10, window: 10m, lockdown: 1h }   # failures from any address → pause logins
  scanner:  { count: 100, window: 60s }                # burst: anonymous probes per address, counted at the edge
  scanning: { count: 30 }                              # slow: probes per address in the 5-min analysis, network-wide
  signatures: { count: 3, window: 10m }                # known scanner paths / User-Agents per address; 0 = off
  origin:   { count: 5, window: 10m }                  # observe: matched failed logins per address

alerts:
  admin_hosts: [nas.example.com]
  quiet_hours: "1-6"               # local hours, inclusive; "" disables
  timezone: America/Los_Angeles
  ip_requests: 300                 # one address in 5 min
  ip_errors: 30                    # anonymous probes from one address in 5 min → scanning line
  guess_ips: 3                     # distinct failing addresses in 5 min

signatures:                        # extra scanner patterns (regex, case-insensitive) on top of the built-in lists
  paths: []
  agents: []

notifications:                     # immediate | digest | off per kind; see Notifications
  scanner: digest
  credentials: immediate
  app_logins: immediate
  lockdown: immediate
  traffic: digest
  reconcile: digest
  unban: immediate
  digest_every: 1h

cloudflare:
  kv_namespace_id: ""              # created on the first deploy when empty
  analytics_dataset: wicket_traffic
  cron: "*/5 * * * *"              # alerts + digests
  reconcile_cron: "17 * * * *"     # KV bans ↔ IP list
```

## The settings page, section by section

*Hosts* (one row per host: mode, recipe, country rule, pass-through, and with a Cloudflare token the last 24 hours: requests, requests that reached the app, probes, bans, blocked; hosts seen in traffic but not listed appear below the table), *Access*, *Limits*, *Shares*, *Passwords*, *Cloudflare*, *Notifications*, *Bans* (search by address prefix, host or country; Unban). Every save is live on every data centre within 30 seconds.

## Share links

*Shares* on the settings page creates a link for one host (1 hour to 30 days, with a label): `https://app.example.com/__wicket/share?s=…`. Opening it sets a cookie for that host alone and sends the visitor to the app; no password, no settings access. The link is shown once. Revoking the share (same page) invalidates the link and every cookie it issued; shares expire on their own.

## First-run setup and where passwords live

A deploy without an `OWNER_PASSWORD` secret prints a one-time link (`/__wicket/setup?token=…`; the token is a fresh var on every deploy and only matters while no owner password exists). The page sets the owner password and an optional friend password, stored in KV as PBKDF2-SHA256 hashes (40,000 iterations) together with a random cookie secret; it can allow-list the visitor's address and take a Cloudflare API token. Afterwards the page is gone and passwords are changed under *Passwords* on the settings page (changing the owner password signs every browser out). Secrets, when present, take precedence over KV and make the Passwords section read-only. `setup: false` turns the page off for people who want secrets only.

## Secrets

| Name | Value |
|---|---|
| `COOKIE_SECRET` | `openssl rand -hex 32`; optional when the setup page is used |
| `OWNER_PASSWORD` | your password; changing it logs out every browser that used it; optional when the setup page is used |
| `FRIEND_PASSWORD` | optional second password |
| `API_TOKENS` | optional, `name:token` comma-separated; `name:token@host1\|host2` restricts hosts |
| `NOTIFY_JSON` | optional channel list (below); or just `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` |
| `CF_API_TOKEN`, `CF_ACCOUNT_ID` | optional; an API token with Account → *Analytics: Read* (traffic alerts), *Filter Lists: Edit* (edge bans) and, for the one-click setup on the settings page, Zone → *Zone: Read*, *WAF: Edit* |
| `CF_LIST_ID` | optional; the IP list for edge bans. Not needed when the list is created from the settings page (its id is kept in KV) |

Without `OWNER_PASSWORD` or `COOKIE_SECRET` the login page answers 503: wicket fails closed.

## No fixed public IP?

- **Dynamic IP with a DDNS name**: `allow_dns: [home.example.duckdns.org]`. Resolved over DNS-over-HTTPS every five minutes; a failed lookup keeps the last answer.
- **No public IP (carrier-grade NAT)**: do not allow-list the shared address. Any address that logs in with the owner password is **trusted** for `trust_window` (refreshed while the owner cookie is in use): wrong passwords from it are not counted, no trigger bans it, and it may log in during a lockdown. A neighbour on your NAT cannot get your household banned, and you cannot ban yourself from a phone. An attacker sharing your exact address is immune for the window too; a ban would have hit you as well.
- **Nothing configured**: everything works, you type the password once per browser.

## Credentials wicket understands

| Carrier | Forwarded to the origin? | Wrong value is a strike? |
|---|---|---|
| cookie `__wicket` | no (stripped) | n/a |
| `X-Wicket-Token: <token>` | no (stripped) | yes |
| `?wicket_token=<token>` (for webhooks that cannot set headers) | no (stripped) | yes |
| `x-access-token`, `X-API-Key`, `?token=` | yes, untouched | yes |
| `Authorization: Bearer <token>` | yes, untouched | **no** (it may be the app's own auth) |

`OPTIONS` preflights and `/.well-known/acme-challenge/` always pass. A host whose clients already send one of the pass-through carriers needs either their values in `API_TOKENS` or a pass-through rule, or those clients get banned.

## Pass-through: let the app keep its own auth

Most apps you would gate already validate a token of their own (an API key, a bearer, a session cookie). A `passthrough` rule on a gated host says which carriers those are; a request carrying one skips the password page and reaches the app, which decides. wicket stores no app tokens. The app's **401** counts as a failed login for the address (`limits.origin`, five in ten minutes → ban), and scanner signatures and probe bursts apply as on observe hosts. Browsers without a credential still get the password page.

```yaml
hosts:
  api.example.com: { passthrough: api }        # preset: Authorization, X-API-Key, x-access-token, ?token=, on API paths only
  app.example.com:
    passthrough:
      headers: [authorization, x-session]      # header names
      cookies: [sid]                           # the app's session cookie
      params: [token]                          # query parameters
      paths: [/api/, /mcp]                     # optional: only on these prefixes (empty = any path)
      status: [401, 403]                       # what "the app rejected the credential" looks like; default [401]
    recipe: jellyseerr                         # optional: the app's login rule also counts for pass-through requests
```

The `api` preset covers `/api/`, `/v1/`, `/v2/`, `/rest/`, `/graphql`, `/mcp`, `/sse`, `/rpc` and `/ws`; anything else stays gated. An app that answers 403 or 400 to bad credentials needs `status` (or its recipe), or its rejections are never counted. On the settings page the same rule is one line: `headers=authorization,x-session; cookies=sid; params=token; paths=/api/,/mcp; status=401,403` (every part optional, at least one of headers/cookies/params).

What this costs: anyone can add such a header and reach the app's authentication code, exactly as on an observe host. The app's own login must therefore be sound; wicket adds the ban after five rejections. A stale token in a polling client is five 401s away from a ban, so keep `limits.origin` at five or more. Owner-trusted and allow-listed addresses are never banned this way.

## Observe mode and recipes

Counting every 401 would ban users of apps that answer 401 to anonymous page loads, so rules are explicit: a path prefix, optional methods, and the statuses that mean "login failed". Each built-in recipe (`src/recipes/index.ts`) was checked against the app's source.

| recipe | rule |
|---|---|
| `immich` | `POST /api/auth/login → 401` |
| `jellyfin`, `emby` | `POST /Users/AuthenticateByName → 401` (emby also `/emby/Users/…`) |
| `navidrome` | `POST /auth/login → 401` |
| `audiobookshelf`, `calibre-web`, `linkding` | `POST /login → 401` |
| `photoprism` | `POST /api/v1/session → 401` |
| `kavita` | `POST /api/Account/login → 401` |
| `jellyseerr`, `overseerr` | `POST /api/v1/auth/local → 403` |
| `qbittorrent` | `POST /api/v2/auth/login → 401` (next major release; 5.1 and earlier answer 200 and ban by themselves) |
| `grafana` | `POST /login → 401` |
| `portainer` | `POST /api/auth → 422` |
| `syncthing` | `POST /rest/noauth/auth/password → 403` |
| `nginx-proxy-manager` | `POST /api/tokens → 400` |
| `pihole` (v6) | `POST /api/auth → 401` |
| `adguard-home` | `POST /control/login → 403` |
| `uptime-kuma` (2.x) | `POST /api/auth/sign-in/* → 401` |
| `filebrowser` | `POST /api/login → 403` |
| `frigate` | `POST /api/login → 401` |
| `node-red` | `POST /auth/token → 403` |
| `n8n` | `POST /rest/login → 401` |
| `authelia` | `POST /api/firstfactor → 401` |
| `vaultwarden` | `POST /identity/connect/token → 400` (a 2FA account's first step is also 400; keep the limit at 5 or more) |
| `paperless-ngx` | `POST /api/token/ → 400` |
| `freshrss` | `POST /api/greader.php/accounts/ClientLogin → 401/400` |
| `vikunja` | `POST /api/v1/login → 403` |
| `mealie` | `POST /api/auth/token → 401` |
| `seafile` | `POST /api2/auth-token/ → 400` |
| `open-webui` | `POST /api/v1/auths/signin → 400` |
| `ghost` | `POST /ghost/api/admin/session → 401` |
| `home-assistant` | `/api/* → 401` (token guessing; the UI login fails with 200, enable HA's `ip_ban_enabled`) |
| `generic-api` | `/api/* → 401` (any API that rejects bad bearers; only if nothing of yours calls it anonymously) |

**Not detectable by status**, because the failure is a 200 page or a redirect: Home Assistant's and Nextcloud's web login, Gitea/Forgejo, Miniflux, BookStack, Wallabag, Sonarr/Radarr and friends, Stirling-PDF, code-server, Paperless's and Seafile's web forms, WordPress, Homarr, Authentik, and anything that logs in over a WebSocket (Uptime Kuma 1.x, Dockge, Zigbee2MQTT). Use the app's own lockout there. Komga and Transmission authenticate with HTTP Basic on paths their UIs also call anonymously, so a rule would ban visitors.

Add your own with `watch`. Observe hosts also ban scanner signatures and bursts of origin 400/404/405.

## Scanner signatures

The built-in list is `PROBE_PATHS` in `src/recipes/signatures.ts` (login pages, admin panels, exploit endpoints) plus two files from the [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) (Apache-2.0): `restricted-files.data` and `scanners-user-agents.data`; `npm run signatures:update` refreshes them. Matching is a case-insensitive substring check on the decoded path and the User-Agent, only for requests that were rejected anyway, so it cannot touch a logged-in user. One exception on observe hosts: `/.env`-style files and dot-directories (`/.git/`, `/.svn/`, …) count even when the app answered 200, because single-page apps serve their index for any path; login paths and User-Agents on a 200 never count (a blog really has `/wp-login.php`). `signatures.paths` / `signatures.agents` add your own regexes.

## Notifications

**Policy** (`notifications:` in `wicket.yaml`, overridable on `/__wicket/settings` until *Reset to config*). Every kind is `immediate`, `digest` (one message per `digest_every`, 15 min to 24 h) or `off`:

| kind | what | default |
|---|---|---|
| `scanner` | addresses banned as scanners | `digest` |
| `credentials` | every wrong wicket password / token (with the count left before the ban), the ban itself, distributed guessing | `immediate` |
| `app_logins` | failed logins at apps in observe mode, and the ban after five | `immediate` |
| `lockdown` | password entry paused (rotating-IP guessing) | `immediate` |
| `traffic` | scanning below `limits.scanning`, bursts, new countries, admin hosts at night | `digest` |
| `reconcile` | the hourly KV ↔ IP-list check changed something | `digest` |
| `unban` | an unban / lift-lockdown link was used | `immediate` |

A digest collapses bans of one kind into one line, each address once; the window starts with the first collected event, so a quiet hour produces no message. The analysis skips addresses already banned. Tiers from least to most serious: `traffic` → `scanner` → `app_logins` → `credentials` → `lockdown`.

**Channels** (`NOTIFY_JSON`): `min` is the lowest severity a channel receives (`info` < `warn` < `critical`); `batch: true` makes a channel digest-only below `critical`. Without `NOTIFY_JSON`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` form one Telegram channel.

```json
[
  { "type": "telegram", "token": "123:abc", "chat_id": "42", "min": "info" },
  { "type": "ntfy", "url": "https://ntfy.sh/your-topic", "min": "warn" },
  { "type": "discord", "url": "https://discord.com/api/webhooks/…", "min": "warn", "batch": true },
  { "type": "slack", "url": "https://hooks.slack.com/services/…", "min": "critical" },
  { "type": "webhook", "url": "https://example.com/hook", "min": "info" },
  { "type": "apprise", "url": "https://apprise.example.com/notify/key", "min": "warn" }
]
```

Severities: scanner bans, unbans, reconcile changes and traffic digests are `info`; bans from wrong passwords, tokens or failed app logins and distributed guessing are `warn`; a lockdown is `critical`. Immediate ban messages carry a signed **Unban** link valid for seven days; the lockdown message carries **Lift lockdown**.

## fail2ban companion

Hosts that must stay direct (media servers, a KVM) can keep fail2ban. `contrib/fail2ban/` has an action that pushes each ban into the same Cloudflare IP list. Its items are left alone by wicket's reconcile (only items whose comment starts with `wicket ` are managed).

## Cloudflare section of the settings page

With `CF_API_TOKEN` and `CF_ACCOUNT_ID` set, the settings page shows whether the token is active, whether Analytics Engine answers (if not: the account switch under *Workers & Pages → Analytics Engine*), which IP list bans go to and whether the zone has the WAF rule that blocks it. Two buttons create what is missing: the list `wicket_banned` (Account → *Filter Lists: Edit*) and the rule `ip.src in $wicket_banned → Block` on the zone (Zone → *Zone: Read* and *WAF: Edit*). The ids are stored in KV; `CF_LIST_ID` in the secrets takes precedence when both exist. If you would rather not give the Worker a token with WAF permissions, create the rule in the dashboard and leave those two permissions off.

## When KV writes fail

On the free plan KV allows 1,000 writes a day; a busy scanning day uses about 500. If a write fails, the Worker refuses password and token entry from the internet for five minutes (503), keeps sessions, allow-listed and trusted addresses working, remembers new bans in memory, and sends one critical message. Nothing is accepted that could not be counted. Workers Paid ($5/month) lifts the limit.

## Limits

Free plan: Workers 100k requests/day; KV 1,000 writes/day (bans, counters, digests, and one lock write per five-minute window ≈ 300/day; a busy scanning day ≈ 500); Analytics Engine 100k rows/day and 10k SQL queries/day (the analysis uses ≈ 1.5k). KV is eventually consistent: a burst within seconds may get one extra try before the ban lands. The burst counter lives in isolate memory and is approximate across data centres. Cloudflare caps request bodies at 100 MB. Bans are per address; carrier-grade NAT means a ban can hit more than one person.
