# wicket

**One password and a ban list for everything you self-host behind a Cloudflare Tunnel. No Access, no fail2ban, no server.**

wicket is a single Cloudflare Worker that stands in front of the hostnames you expose through a Cloudflare Tunnel. It is for people who run services at home (a NAS, Home Assistant, a few apps of their own) and want them reachable from anywhere without Cloudflare Access's per-browser identity flow and without keeping fail2ban alive on the box.

- **One shared password.** Type it once per browser; a signed cookie scoped to your domain then opens every gated host for a year. An optional second password for friends can be rotated without logging you out.
- **API tokens** for callers that cannot type: webhooks, MCP servers, native apps. Tokens can be limited to certain hosts. Apps that already send their own `Authorization: Bearer`, `X-API-Key`, `x-access-token` or `?token=` keep working: register the value and wicket lets it through untouched.
- **Three strikes, permanent ban.** Wrong passwords and tokens are counted per address. The third one writes a ban, appends the address to a Cloudflare IP list so a WAF rule blocks it at the edge on every proxied host, and sends you a message with a one-click **Unban** link.
- **Scanner auto-ban.** A hundred anonymous probes in a minute from one address is a vulnerability scanner; it gets the same ban.
- **Rotating-IP brute force.** When failures from changing addresses pile up, wicket pauses password entry for an hour (existing sessions, tokens and allow-listed addresses keep working) and tells you.
- **Observe mode** for apps with their own login (Home Assistant's companion app, Immich's mobile app, a public site). No password page; wicket still enforces bans, catches scanners and **counts the app's own failed logins** using built-in recipes, then bans the address like a brute-forcer. This is fail2ban's `filter.d` moved to the edge.
- **Notifications you can tune.** Telegram, ntfy, Discord, Slack, a generic webhook or an Apprise endpoint. Every kind of event (scanner ban, wrong-password ban, lockdown, traffic alert, …) is delivered immediately, folded into an hourly digest, or dropped; scanner bans default to the digest because the internet scans all day. Change it in the config or on the owner-only settings page, no redeploy.
- **Traffic alerts.** Every request is written to Workers Analytics Engine; every five minutes wicket alerts on bursts, error floods, distributed guessing, first visits from a new country and admin hosts used at night. The periodic jobs run from Cloudflare's cron *and*, as a fallback, from ordinary traffic, because cron delivery has been seen to stop silently.
- **Plays well with fail2ban.** If you still run it for direct (non-proxied) hosts, `contrib/fail2ban` ships an action that adds its bans to the same IP list. An hourly cron keeps wicket's bans and the list in step.

What it is not: a reverse proxy (yours keeps routing), an identity system (two passwords and tokens, no accounts), or a way to stream video or move large files through Cloudflare's proxy (their terms forbid it; keep those hosts direct). See [`docs/design.md`](docs/design.md) for the model and the threat model.

## How it works

```
browser ──► Cloudflare edge ──► wicket (Worker, routed by hostname) ──► Tunnel ──► your reverse proxy ──► app
                 │                      │
          WAF rule blocks            KV: bans, counters
          listed IPs                 Analytics Engine: one row per request
```

Hosts in `wicket.yaml` get a Workers route. For a **gated** host the Worker answers with the password page until it sees a valid cookie or token; for an **observe** host it forwards everything and watches the origin's status codes. Hosts not listed are never touched.

## Setup

You need a Cloudflare zone, a Cloudflare Tunnel whose hostnames are proxied (orange cloud) DNS records, Node 22+, and either Cloudflare's `cf` CLI (`npm i -g cf && cf auth login`) or wrangler.

1. **Configure.**
   ```sh
   git clone https://github.com/jiaton/wicket && cd wicket && npm install
   cp wicket.example.yaml wicket.yaml   # edit: zone, hosts, allow_ips
   ```
   `wicket.yaml` is the only file you edit. It is compiled into the Worker's routes and variables at deploy time and validated (unknown recipe, host outside the zone, typo in a mode → the deploy stops). Durations accept `30s`, `10m`, `24h`, `7d`. `wicket.yaml` and `secrets.json` are git-ignored, so a fork never carries your hosts, IPs or passwords; keep them wherever you keep private things (a dotfiles repo, a password manager) and copy them in to deploy.

2. **Secrets.** Put these in a JSON file (`secrets.json`, git-ignored) or type them under the Worker's *Settings → Variables and Secrets*:

   | Name | Value |
   |---|---|
   | `COOKIE_SECRET` | `openssl rand -hex 32` |
   | `OWNER_PASSWORD` | your password |
   | `FRIEND_PASSWORD` | optional second password |
   | `API_TOKENS` | optional, `name:token` comma-separated; `name:token@host1\|host2` restricts hosts |
   | `NOTIFY_JSON` | optional channel list, see [Notifications](#notifications); or just `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` |
   | `CF_API_TOKEN`, `CF_ACCOUNT_ID` | optional; an API token with *Account Analytics: Read* (traffic alerts) and *Account Filter Lists: Edit* (edge bans) |
   | `CF_LIST_ID` | optional; the IP list from step 4 |

   Without `OWNER_PASSWORD` or `COOKIE_SECRET` the login page answers 503: wicket fails closed.

3. **Deploy.**
   ```sh
   # cf CLI — code, config and secrets in one shot
   cf deploy --secrets-file secrets.json

   # or wrangler
   npm run config:wrangler          # writes wrangler.jsonc from wicket.yaml
   npx wrangler deploy && npx wrangler secret bulk secrets.json
   ```
   > With cf 1.0.0-beta.x a deploy **without** `--secrets-file` uploads a version with no secrets, and wicket then rejects every password until you re-apply them. `npm run deploy` refuses for that reason; always pass the file. The KV namespace is provisioned on the first `cf deploy` (wrangler users create one with `wrangler kv namespace create STORE` and put its id in `wicket.yaml`). Analytics Engine needs the account switch flipped once in the dashboard (*Workers & Pages → Analytics Engine → Enable*).

4. **Edge bans (recommended).** Create an account IP list (*Manage Account → Configurations → Lists*, or `cf rules lists create --name wicket_banned --kind ip`) and a WAF custom rule on the zone: `ip.src in $wicket_banned` → Block. Put the list id in `CF_LIST_ID`. Banned addresses are then dropped at the edge for every proxied host, not just the routed ones, and before the Worker runs.

5. **Your reverse proxy.** Requests reach it from `cloudflared`, so make it trust `Cf-Connecting-Ip` for logging and its own rate limits. Caddy:
   ```
   servers {
       trusted_proxies static private_ranges
       client_ip_headers Cf-Connecting-Ip
   }
   ```

## Day to day

- **Logging in.** Open any gated host, type the password once; the cookie covers every host under your domain for a year. `/__wicket/login` shows the form explicitly, `/__wicket/logout` clears the cookie. Changing `OWNER_PASSWORD` logs out every browser that used it, since the password is mixed into the cookie's key.
- **At home.** Put your public IP in `allow_ips` and nobody in the house sees a password page; the login page still works there (the owner needs a cookie for the settings page), and wrong passwords from an allow-listed address are never counted.
- **A ban message** names the address, country, host and reason, with an **Unban** button (a signed link, valid seven days). Scanner bans arrive as one line in the digest instead. Nothing happened in the last hour → no digest.
- **Settings page.** `/__wicket/settings`, owner password only: per-kind delivery, digest interval, channels in use, bans in store by kind, a *Send test message* button. Saves to KV, takes effect on the next event, *Reset to config* goes back to the file.
- **Unbanning by hand.** Use the link, or delete the KV key `ban:<ip>` (`cf kv keys delete --force --namespace-id <id> 'ban:<ip>'`); the hourly reconcile then drops the address from the IP list. If you ban yourself while testing (three wrong passwords from an address that is not allow-listed), that is the way out.
- **Changing things later.** New host or mode → edit `wicket.yaml`, redeploy, and make sure the hostname is proxied. New password or token → secrets, redeploy. Notification policy → the settings page, no redeploy. `git pull` + redeploy picks up new recipes.

## Configuration reference

```yaml
zone: example.com                 # every host must be inside it
worker: wicket                    # Worker name
site_name: example.com            # prefix of every notification; default = zone
cookie_domain: example.com        # one login per domain; default = zone
cookie_days: 365

hosts:
  nas.example.com: gated
  photos.example.com: { mode: observe, recipe: immich }
  blog.example.com:
    mode: observe
    watch: [{ path: /api/unlock, methods: [POST], status: [401] }]

allow_ips: [203.0.113.7]          # pass without a password (login page still available); put your home IP here
bypass: [nas.example.com/hooks/]  # host/prefix that passes without credentials

limits:
  password: { count: 3, window: 24h }                  # wrong passwords/tokens per address
  rotating: { count: 10, window: 10m, lockdown: 1h }   # failures from any address → pause logins
  scanner:  { count: 100, window: 60s }                # anonymous probes per address
  origin:   { count: 5, window: 10m }                  # observe: matched failed logins per address

alerts:
  admin_hosts: [nas.example.com]
  quiet_hours: "1-6"               # local hours, inclusive; "" disables
  timezone: America/Los_Angeles
  ip_requests: 300                 # one address in 5 min
  ip_errors: 30                    # 4xx/5xx from one address in 5 min
  guess_ips: 3                     # distinct failing addresses in 5 min

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
  kv_namespace_id: ""              # cf provisions one when empty; wrangler needs it
  analytics_dataset: wicket_traffic
  cron: "*/5 * * * *"              # alerts + digests
  reconcile_cron: "17 * * * *"     # KV bans ↔ IP list
```

Allow-listing your home's public IP matters twice: from inside the house every host resolves to Cloudflare, so that address is what wicket sees, and it means nobody at home can get the whole household banned by mistyping three times.

### Credentials wicket understands

| Carrier | Forwarded to the origin? | Wrong value is a strike? |
|---|---|---|
| cookie `__wicket` | no (stripped) | n/a |
| `X-Wicket-Token: <token>` | no (stripped) | yes |
| `?wicket_token=<token>` (for webhooks that cannot set headers) | no (stripped) | yes |
| `x-access-token`, `X-API-Key`, `?token=` | yes, untouched | yes |
| `Authorization: Bearer <token>` | yes, untouched | **no** (it may be the app's own auth) |

Before gating a host whose clients already send one of the pass-through carriers, register their token values in `API_TOKENS`, or those clients get banned. `OPTIONS` preflights and `/.well-known/acme-challenge/` always pass (browsers send preflights without cookies; certificate renewals must reach your proxy).

### Observe mode and recipes

Counting every 401 would ban users of apps that answer 401 to anonymous page loads, so rules are explicit: a path prefix, optional methods, and the statuses that mean "login failed". Each built-in recipe (`src/recipes/index.ts`) was checked against the app's source; the status codes are less uniform than you would hope.

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

Add your own with `watch`. Observe hosts also ban bursts of origin 400/404/405 (scanners).

## Notifications

Two things decide who hears what: the **channels** (where messages go; secrets) and the **policy** (how each kind of event is delivered; config, changeable at runtime).

**Policy** — in `wicket.yaml` under `notifications:`, and on the owner-only page `https://<any gated host>/__wicket/settings`, which saves to KV and overrides the file until you press *Reset to config*. Every kind is `immediate` (a message per event), `digest` (collected and sent as one message per `digest_every`, 15 minutes to 24 hours) or `off`:

| kind | what | default |
|---|---|---|
| `scanner` | addresses banned for probe bursts | `digest` — the internet never stops scanning |
| `credentials` | wrong password / token bans | `immediate` |
| `app_logins` | failed logins at apps in observe mode | `immediate` |
| `lockdown` | password entry paused (rotating-IP guessing) | `immediate` |
| `traffic` | five-minute analysis: bursts, error floods, new countries, admin hosts at night | `digest` |
| `reconcile` | the hourly KV ↔ IP-list check changed something | `digest` |
| `unban` | an unban / lift-lockdown link was used | `immediate` |

A digest collapses bans of one kind into a single line (`Scanners banned (14): 1.2.3.4 (SG) nas, …`). The window starts with the first collected event, so a quiet hour produces no message at all, and a noisy one produces exactly one. Traffic alerts skip addresses that are already banned, so a scanner is reported once, as a ban, not again as an error flood. The settings page also shows the channels in use, the bans in store by kind, and has a *Send test message* button.

**Channels** — `NOTIFY_JSON` is an array; `min` is the lowest severity a channel receives (`info` < `warn` < `critical`), and `batch: true` makes a channel take digests for everything below `critical` regardless of the policy (a quiet channel next to a loud one). Without `NOTIFY_JSON`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` form one Telegram channel.

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

Hosts that must stay direct (media servers, a KVM) can keep fail2ban. `contrib/fail2ban/` has an action that pushes each ban into the same Cloudflare IP list, so an address banned on a direct host is also blocked at the edge. Its items are left alone by wicket's reconcile cron (only items whose comment starts with `wicket ` are managed).

## Limits

Free plan: Workers 100k requests/day, KV 1000 writes/day (failures, bans, lockdowns, unbans, alert dedup, digests, and one lock write per five-minute job window, about 300/day), Analytics Engine 100k rows/day and 10k SQL queries/day (the cron uses about 1.5k/day). KV is eventually consistent, so a burst of wrong passwords within a few seconds may get one extra try before the ban lands; the edge list closes the gap once the API call completes. The scanner counter lives in the isolate's memory and is approximate across Cloudflare's data centres. Cloudflare's proxy caps request bodies at 100 MB. Bans are per address; carrier-grade NAT means a ban can hit more than one person.

## Development

```
npm test               # vitest, plain Node, fakes for KV / Analytics / network
npm run check          # tsc + cf deploy --dry-run (compiles wicket.yaml, checks bindings)
npm run dev            # cf dev (needs .dev.vars with the secrets above)
```

[`AGENTS.md`](AGENTS.md) describes the layers and how to add a pipeline step, a ban trigger, a notification channel, a recipe or a setting. Contributions welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md). MIT.
