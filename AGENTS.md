# AGENTS.md — wicket

Cloudflare Worker: one shared password (plus host-scoped API tokens) in front of self-hosted services on a Cloudflare Tunnel, with fail2ban-style bans at the edge, scanner detection, observe mode for apps with their own login, and notifications. `README.md` is the user-facing description; `docs/design.md` the positioning, the pipeline order, the modes and triggers, and the threat model. Read both first.

## Layers (dependency direction: top → bottom only)

```
cloudflare.config.ts  cf CLI config, generated from wicket.yaml at evaluation time (no literals in here)
deploy/               build-time only, runs in Node, never bundled: config.ts (YAML → validated config →
                      vars/routes/crons), wrangler.ts (writes wrangler.jsonc)
src/index.ts          Worker entry: fetch = pipeline, scheduled = the five-minute or the hourly job (by cron string)
src/pipeline/         request handling as an ordered list of steps (handler.ts: STEPS)
  context.ts          Ctx (everything a step may need), Deps (injected fetch + clock), Outcome, Step
  endpoints.ts        /__wicket/login|logout|unban|settings (settings = owner-only page: status, policy, recent bans with unban/lift)
  observe.ts          forwardAndWatch (origin answer → watch rules, signatures, bursts); used by observe mode and by the pass-through step (app's own credential on a gated host)
  signatures.ts       known scanner path/agent → per-isolate counter → ban (used by step 10 and observe; scope `files` for 2xx answers on observe hosts)
  allow.ts            allow list = allow_ips + allow_dns (DoH, cached 5 min per isolate); also used by the slow-scanner job
  failures.ts         wrong password/token → counters → ban or 401
  respond.ts          html()/json() helpers
src/actions/ban.ts    the one exit for every ban trigger: KV once + IP list (failures queued in `edgeq`) + notification; request-path bans also go into the isolate's `recentBans`; lockdown
src/store/            bans.ts (bans with `kind` in KV metadata, counters, lockdown, `edgeq` pending list calls), locks.ts (job:* run-once locks), settings.ts (settings:notify), trust.ts (trust:<ip> = recent owner session → never counted or banned) — every KV key, behind named functions
src/notify/           events with kind + severity → policy (policy.ts: defaults ← NOTIFY_POLICY_JSON ← saved settings) → channels; digests queued in KV; adapters.ts has one function per channel type
src/cron/             index.ts (jobs, run-once locks, request-path fallback tick), reconcile.ts (KV bans ↔ IP list)
  analyze.ts          one base query → addresses.ts folds it per address → slow-scanner.ts bans (acts) → every detector (observes) → dedup → one event per kind
  detectors/          index.ts (Detector + DetectorContext + DETECTORS list); one file per detection:
                      credentials, guessing, app-logins, scanning, new-country, quiet-hours
src/cloudflare/       REST clients: lists.ts (IP list), analytics.ts (SQL)
src/config/           parsing only: env.ts (field names), settings.ts (vars), hosts.ts (HOSTS_JSON), tokens.ts (API_TOKENS), channels.ts (NOTIFY_JSON), notifications.ts (policy kinds/deliveries)
src/core/             pure functions, no I/O: crypto.ts, credentials.ts (carriers, cookie, CSRF), ip.ts, counters.ts
src/recipes/          data: per-app watch rules (index.ts), scanner signatures (signatures.ts + signatures.generated.ts from OWASP CRS via `npm run signatures:update`)
src/ui/               pages.ts (login, messages, shell), settings.ts (owner settings page)
tests/                vitest in plain Node; helpers.ts fakes KV, Analytics and the network
```

Rules that keep it layered:

- `core/` and `config/` import nothing from above them; `store/`, `cloudflare/`, `notify/` import only `config/` and `core/`; `cron/` and `actions/` may import those; `pipeline/` may import everything below it (including `cron/` for the fallback tick); only `index.ts` imports `pipeline/`.
- `deploy/` may import `src/` types and `src/recipes` (to validate recipe names); nothing in `src/` imports `deploy/` (it uses `node:fs`).
- All I/O goes through `Deps` (`fetch`, `now`) and the two bindings on `Env` (`STORE`, `TRAFFIC`). No module reads `Date.now()` or calls global `fetch` directly (only `index.ts` does), so every test runs without workerd; `emit` and the jobs take `now` as a parameter.
- KV keys exist in `store/` (`bans.ts`, `locks.ts`), plus `nq:*` in `notify/index.ts` and `alert:*` in `cron/analyze.ts`. Add a key = add a named function there.
- The IP list has several writers (wicket, fail2ban, people). wicket marks its items with the `LIST_COMMENT_MARKER` prefix and the reconcile cron only ever removes those.

## How to add things

- **A check in the request path**: one entry in `STEPS` (`pipeline/handler.ts`), returning a `Result` or `null`; one test in `tests/pipeline.test.ts`. Keep the order comment accurate — order is the security model (mirrored in `docs/design.md`).
- **A ban trigger**: in the request path call `banAddress(c, ip, kind, n)`; outside a request (a job) call `recordBan(env, deps, cfg, { ip, host, country, kind, fails })`. Add the `kind` to `BanKind` in `store/bans.ts` and its wording in `actions/ban.ts`.
- **A notification event**: `emit(env, fetch, { kind, severity, title, text, link?, ip?, cc?, host? }, now)`. A new `kind` goes into `EventKind`/`POLICY_KINDS`/`KIND_LABELS`/`DEFAULT_POLICY` in `config/notifications.ts`, the `notifications:` table in docs/configuration.md, and `digestEvent` if it should collapse in digests.
- **A notification channel**: extend `ChannelType` in `config/channels.ts`, add one function + `case` in `notify/adapters.ts`, add the host to `NOTIFY_HOSTS` in `tests/helpers.ts`, add a payload assertion in `tests/notify.test.ts`.
- **A recipe**: one entry in `src/recipes/index.ts` (verify the real app's failure status first; see CONTRIBUTING) and a row in the recipe table in docs/configuration.md.
- **A setting**: a key in `wicket.example.yaml` + `deploy/config.ts` (`WicketConfig`, `parseConfig`, `toVars`), the field in `config/env.ts`, the parsed default in `config/settings.ts`, a line in docs/configuration.md, an assertion in `tests/config.test.ts`.
- **A detection in the traffic analysis**: one file in `src/cron/detectors/` exporting a `Detector` (`id`, `run(ctx) → Alert[]`), one entry in `DETECTORS`, one test in `tests/detectors.test.ts` using a fake `DetectorContext`. A detector reads `ctx.addresses` (the window folded per address) or runs its own `ctx.query`; it never sends anything — `runAnalysis` dedups by `key` and emits one event per `kind`, so pick the `kind` that matches the severity tier (`credentials` > `app_logins` > `traffic`).
- **A periodic job**: add it to `fiveMinuteJob` or `hourlyJob` in `src/cron/index.ts`; both run under a run-once lock from the cron *and* from the request-path fallback (Cloudflare's cron delivery has gone silent for this Worker before; never rely on `scheduled` alone). A new cadence needs a schedule in `wicket.yaml` (`toCrons`), a branch in `index.ts` and a timer in `createFallbackTick`.

## Conventions

- TypeScript with `erasableSyntaxOnly` (no parameter properties, no enums). Comments, docs and UI strings in English.
- Every ban goes through `banAddress`/`recordBan`, which refuse trusted addresses (`store/trust.ts`), write KV exactly once and remember request-path bans in `c.recentBans` (step 3 consults it before KV, whose cached misses otherwise cause repeat bans); every allow-list decision goes through `c.allowed()` / `createAllowCheck`. Do not call `ipAllowed` or `writeBan` directly from a new feature. A ban's request reports its kind as the outcome (`ban` password/token, `ban-scan`, `ban-origin`); `cron/addresses.ts` folds on that, so a new ban kind needs a new outcome, not a reuse of `ban`.
- KV writes are the scarce resource on the free plan (1,000 a day; the five-minute lock alone is 288). A new feature that writes per request or per event needs a reason in its comment and, where possible, isolate memory (`core/counters.ts`) or a single aggregated key instead.
- Fail closed: missing secrets disable login (503); malformed `HOSTS_JSON` means `gated`; unknown tokens never pass. `deploy/config.ts` rejects a bad `wicket.yaml` so the deploy stops.
- Never forward wicket credentials to the origin (`stripCredentials`). Never log secrets.
- A wrong `Authorization: Bearer` is not a strike (it may be the origin's own auth); wrong `X-Wicket-Token` / `wicket_token` / `x-access-token` / `X-API-Key` / `?token=` are. Gating a host whose clients send those headers requires registering their values in `API_TOKENS` first.
- Nothing deployment-specific in the repo: no real hostnames, IPs, namespace or list ids. `wicket.yaml` and `secrets.json` are git-ignored; keep the real ones outside the repository (a private dotfiles repo, a password manager) and point `WICKET_CONFIG` at the file or symlink it in.
- Deploy with `cf deploy --secrets-file secrets.json`. **A bare `cf deploy` / `npm run deploy` wipes every secret** in cf 1.0.0-beta.5, so `npm run deploy` refuses. Cloudflare-side changes use `cf …`; the zone WAF rule and the Analytics Engine switch are the user's to set in the dashboard.
- Three config sources, resolved in `deploy/config.ts`: `$WICKET_YAML` (the text or its base64; Workers Builds users put it in a build variable so the fork stays clean) → `$WICKET_CONFIG` (a path; what `wicket-apply-secrets` sets) → `./wicket.yaml` → the example. `deploy/wrangler.ts` is the Workers Builds build command: it also finds or creates the KV namespace `<worker>-STORE` when `kv_namespace_id` is empty, so repeated builds reuse one namespace. Keep all three paths working when touching config loading.

## Deploying for a user (agent checklist)

When a user asks you to deploy wicket for them, follow README's *Setup* (details in docs/configuration.md) and this list:

1. `cp wicket.example.yaml wicket.yaml`; fill `zone`, `hosts` (mode and recipe per host), `allow_ips` / `allow_dns`, notifications. Every hostname must be a proxied DNS record inside the zone.
2. `secrets.json`: `COOKIE_SECRET` from `openssl rand -hex 32`; `OWNER_PASSWORD` from the user, never invented or echoed back; the rest optional.
3. `npm run check` must pass before any deploy. Then `cf deploy --secrets-file secrets.json` (or the wrangler pair). Never a bare `cf deploy`.
4. Verify: `curl -sI https://<gated host>/__wicket/login` answers 200. 503 means the secrets did not land.
5. Things only the user can do: `cf auth login`, the Analytics Engine switch (*Workers & Pages → Analytics Engine → Enable*), the zone WAF rule `ip.src in $wicket_banned` → Block. Say so instead of trying.
6. Leave `wicket.yaml` and `secrets.json` untracked, and nothing deployment-specific in tracked files.

## Forbidden

- Cloudflare Access, email OTP, or any per-browser identity flow (the owner rejected them).
- User accounts or hashed password stores; two shared passwords + tokens is the design.
- Proxying video or large-file hosts (Cloudflare terms); they stay direct.
