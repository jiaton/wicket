# wicket

**One password and a ban list for everything you self-host behind a Cloudflare Tunnel.**

A single Cloudflare Worker in front of the hostnames you expose through a Tunnel. Type one password per browser and every gated host opens for a year. Wrong passwords, API-key guessing and scanners get the address banned at the edge, and you get a message with an Unban button. No Cloudflare Access, no fail2ban, no server.

- **One shared password**, an optional second one for friends, and host-scoped API tokens for webhooks and apps.
- **Apps keep their own auth**: a one-line `passthrough` rule lets requests with the app's bearer, API key or session cookie reach the app; wicket stores no app tokens and bans the address after five rejections.
- **Three strikes, permanent ban**: wrong passwords and tokens per address → KV ban + Cloudflare IP list (WAF blocks it on every proxied host).
- **Scanner auto-ban**: known scanner paths and User-Agents (OWASP CRS lists), probe bursts, and slow network-wide scanning.
- **Rotating-IP guessing** pauses password entry for an hour and tells you.
- **Observe mode** for apps with their own login: no password page, but bans, scanner detection and the app's own failed logins counted via recipes (Immich, Jellyfin, Home Assistant, …).
- **Notifications** (Telegram, ntfy, Discord, Slack, webhook, Apprise) with per-kind immediate/digest/off, tunable on an owner-only settings page.

Not a reverse proxy, not an identity system, not for streaming video through Cloudflare. Model and threat model: [`docs/design.md`](docs/design.md).

```
browser ──► Cloudflare edge ──► wicket (Worker, routed by hostname) ──► Tunnel ──► your reverse proxy ──► app
                 │                      │
          WAF rule blocks            KV: bans, counters
          listed IPs                 Analytics Engine: one row per request
```

## Setup

Needs a Cloudflare zone, a Tunnel with proxied hostnames, Node 22+, and the `cf` CLI (`npm i -g cf && cf auth login`) or wrangler.

```sh
git clone https://github.com/jiaton/wicket && cd wicket && npm install
cp wicket.example.yaml wicket.yaml        # 1. edit zone, hosts, allow_ips (every key is commented)
cat > secrets.json <<EOF                  # 2. secrets (git-ignored, like wicket.yaml)
{ "COOKIE_SECRET": "$(openssl rand -hex 32)", "OWNER_PASSWORD": "change-me",
  "TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "42" }
EOF
npm run check                             # 3. validates wicket.yaml, uploads nothing
cf deploy --secrets-file secrets.json     # 4. deploy (wrangler: npm run config:wrangler && npx wrangler deploy && npx wrangler secret bulk secrets.json)
curl -sI https://nas.example.com/__wicket/login | head -1   # 200 = live, 503 = secrets missing
```

Then connect your Cloudflare account: create an API token (Account → *Analytics: Read*, *Filter Lists: Edit*; Zone → *Zone: Read*, *WAF: Edit*), put it and your account id in the secrets as `CF_API_TOKEN` / `CF_ACCOUNT_ID`, redeploy, and open the **Cloudflare** section of `/__wicket/settings`: it checks the token, tells you if Analytics Engine still needs its one-time switch in the dashboard (*Workers & Pages → Analytics Engine*), and creates the IP list and the WAF rule for edge bans with one click each. Make your reverse proxy trust `Cf-Connecting-Ip`.

> Never run `cf deploy` without `--secrets-file` (cf 1.0 beta uploads a version with no secrets; `npm run deploy` refuses for that reason). The KV namespace is created on the first deploy.

**No CLI?** Fork, then *Workers & Pages → Create → Continue with GitHub*: build command `npm run config:wrangler`, deploy command `npx wrangler deploy`, build variable `WICKET_YAML` = your `wicket.yaml` (text or base64). Add the secrets under the Worker's *Settings → Variables and Secrets*. *Sync fork* ships updates.

**Coding agent?** A clone plus "deploy wicket for zone X with hosts Y following README.md" is enough; it can do everything except `cf auth login`, the dashboard switches, and knowing your password. Rules it must keep are in [`AGENTS.md`](AGENTS.md).

## Day to day

- **Home**: put your public IP in `allow_ips`; no password page at home, nobody there can get the house banned. Dynamic IP → `allow_dns`; no public IP → logging in as owner makes the address trusted for `trust_window` ([details](docs/configuration.md#no-fixed-public-ip)).
- **Ban message**: address, country, host, reason, **Unban** button. Scanner bans come as one digest line per hour; nothing happened → no message.
- **Settings page** `/__wicket/settings` (owner): hosts and modes, allow lists and trust, limits, notification policy, newest bans with Unban. Everything saved there is live within 30 s, no redeploy.
- **Banned yourself?** Settings page, the link in the message, or `cf kv keys delete --force --namespace-id <id> 'ban:<ip>'`.
- **Changes**: hosts, access lists, limits and the notification policy → settings page (or `wicket.yaml` + redeploy, which stays the reproducible base); passwords and tokens → secrets + redeploy.

## Reference

[`docs/configuration.md`](docs/configuration.md): every `wicket.yaml` key, credential carriers, observe recipes and which apps cannot be detected, scanner signatures, notification policy and channels, fail2ban companion, free-plan limits.

## Development

```
npm test          # vitest in plain Node, fakes for KV / Analytics / network
npm run check     # tsc + cf deploy --dry-run
npm run dev       # cf dev (needs .dev.vars)
```

[`AGENTS.md`](AGENTS.md) describes the layers and how to add things. Contributions welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md). MIT.
