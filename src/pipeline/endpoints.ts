import { listRemove } from '../cloudflare/lists';
import { parseChannels } from '../config/channels';
import { DEFAULT_POLICY, isDelivery, mergePolicy, POLICY_KINDS, type NotifyPolicy } from '../config/notifications';
import { cookieValue, ENDPOINT_PREFIX, safeNext, sameOrigin, setCookie } from '../core/credentials';
import { safeEqual, signSession, signUnban, verifySession, type Role } from '../core/crypto';
import { emit, queueStatus } from '../notify';
import { resolvePolicy } from '../notify/policy';
import { clearBan, clearFailures, isBanned, isLockedDown, liftLockdown, listBans, LOCKDOWN_IP, readBan, readLockdown, type BanKind } from '../store/bans';
import { clearNotifySettings, clearRuntimeSettings, readRuntimeSettings, writeNotifySettings, writeRuntimeSettings } from '../store/settings';
import { defaultMode, formatPassthroughSpec, hostTableOf, isHostMode, parsePassthroughSpec, PASSTHROUGH_PRESETS } from '../config/hosts';
import { LIMIT_FIELDS, LIMIT_KEYS, parseDuration, runtimeOverridesOf, validAllowEntry, validHostname, type LimitKey } from '../config/runtime';
import { RECIPES } from '../recipes';
import { resolveRuntime } from '../runtime';
import { analyticsReachable, ensureList, ensureWafRule, findZone, listLists, verifyToken, wafRuleState } from '../cloudflare/setup';
import type { CloudflareView } from '../ui/settings';
import { isTrusted, markTrusted } from '../store/trust';
import { loginPage, messagePage, setupPage } from '../ui/pages';
import { hashPassword, randomSecret, verifyPassword } from '../core/password';
import { readAuth, writeAuth, writeCloudflareCreds } from '../store/auth';
import { settingsPage, type BanRow, type HostRow } from '../ui/settings';
import type { Ctx, Result } from './context';
import { failClosed, registerFailure } from './failures';
import { html } from './respond';

const LOGIN_ACTION = `${ENDPOINT_PREFIX}login`;
const SETTINGS_PATH = `${ENDPOINT_PREFIX}settings`;

/** `/__wicket/*`: login (GET form, POST check), logout, unban. Answers every request under the prefix. */
export async function endpoints(c: Ctx): Promise<Result | null> {
  if (!c.url.pathname.startsWith(ENDPOINT_PREFIX)) return null;
  const route = c.url.pathname.slice(ENDPOINT_PREFIX.length);

  if (route === 'unban' && c.req.method === 'GET') return unban(c);
  if (route === 'logout') {
    // Same-origin only: another site must not be able to sign the owner out with an <img>.
    if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site request.'), 403), 'reject'];
    return [html(messagePage('Signed out', 'The password cookie was cleared.'), 200, { 'set-cookie': setCookie('', c.cfg, 0) }), 'logout'];
  }
  if (route === 'login' && c.req.method === 'POST') return login(c);
  if (route === 'settings') return settings(c);
  if (route === 'setup') return setup(c);
  if (route === 'login') {
    return [html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: safeNext(c.url.searchParams.get('next')) }), 200), 'reject'];
  }
  return [html(messagePage('Not found', ''), 404), 'reject'];
}

export const loginForm = (c: Ctx, status: number) =>
  html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: c.url.pathname + c.url.search }), status);

async function login(c: Ctx): Promise<Result> {
  const { env, cfg, url, ip } = c;
  // Allow-listed addresses never need a cookie to pass, but the owner still needs one for
  // /__wicket/settings, so the password is checked; a wrong one is not a strike here.
  const allowed = (await c.allowed()) || (await isTrusted(env, ip));
  if (!allowed && (await isBanned(env, ip))) return [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'banned'];
  if (!allowed && (await isLockedDown(env))) {
    return [html(messagePage('Locked', 'Too many wrong passwords from the internet lately; password entry is paused for a while. Existing sessions keep working.'), 403), 'locked'];
  }
  if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site login is not allowed.'), 403), 'reject'];
  // KV writes failing (quota, outage): wrong passwords could not be counted, so none are accepted
  // from the internet at large; allow-listed and trusted addresses are never counted anyway.
  if (!allowed && c.kv.down()) return failClosed('password');

  const form = await c.req.formData().catch(() => null);
  const password = String(form?.get('password') ?? '');
  const next = safeNext(String(form?.get('next') ?? ''));
  // No honeypot field: browsers autofill hidden inputs no matter what they are called
  // (seen with "email" and "website"), and a human rejected that way looks like a brute-forcer.

  // Fail closed: with no owner password anywhere (a deploy that dropped its secrets, or setup not
  // done yet), comparing against `undefined` would otherwise accept the literal password "undefined".
  if (c.auth.kind === 'none' || !c.auth.owner || !c.auth.cookieSecret) {
    const hint = c.auth.setupOpen ? 'This Worker has not been set up yet: open the setup link printed when it was deployed.' : 'Password entry is disabled: the Worker has no secrets configured.';
    return [html(messagePage('Unavailable', hint), 503), 'reject'];
  }

  const role = password ? await matchPassword(c, password) : null;
  if (!role) {
    console.warn('login rejected', url.hostname, ip, allowed ? 'allow-listed, not counted' : 'counted');
    if (allowed) return [html(loginPage({ host: url.hostname, action: LOGIN_ACTION, next, error: 'Wrong password.' }), 401), 'reject'];
    return registerFailure(c, 'password', next);
  }

  c.exec.waitUntil(clearFailures(env, ip));
  if (role === 'owner') c.exec.waitUntil(markTrusted(env, ip, cfg.trustSeconds));
  const issuedAt = Math.floor(c.deps.now() / 1000);
  const value = await signSession(c.auth.cookieSecret, (role === 'owner' ? c.auth.owner : c.auth.friend)!, role, issuedAt);
  return [
    new Response(null, {
      status: 303,
      headers: { location: `${url.origin}${next}`, 'set-cookie': setCookie(value, cfg, cfg.cookieSeconds), 'cache-control': 'no-store' },
    }),
    'login',
  ];
}

/** Role of the session cookie on this request, if any. */
async function sessionRole(c: Ctx): Promise<Role | null> {
  const s = await verifySession(cookieValue(c.req), c.auth.cookieSecret, { owner: c.auth.owner ?? undefined, friend: c.auth.friend ?? undefined }, Math.floor(c.deps.now() / 1000), c.cfg.cookieSeconds);
  return s?.role ?? null;
}

/** Which role a typed password belongs to: constant-time compare against the secrets, or PBKDF2 against the KV hashes. */
async function matchPassword(c: Ctx, password: string): Promise<Role | null> {
  if (c.auth.kind === 'plain') {
    if (c.auth.owner && safeEqual(password, c.auth.owner)) return 'owner';
    if (c.auth.friend && safeEqual(password, c.auth.friend)) return 'friend';
    return null;
  }
  if (c.auth.kind === 'hash') {
    if (c.auth.owner && (await verifyPassword(password, c.auth.owner))) return 'owner';
    if (c.auth.friend && (await verifyPassword(password, c.auth.friend))) return 'friend';
  }
  return null;
}

const SETUP_PATH = `${ENDPOINT_PREFIX}setup`;
const MIN_PASSWORD = 12;

/**
 * /__wicket/setup — first run, when no owner password exists in the secrets or in KV. Needs
 * the one-time token printed at deploy time (constant-time compare), so a stranger who finds
 * a fresh Worker cannot claim it. Writes the password hashes and a cookie secret to KV, allow-
 * lists the visitor's address if asked, stores a Cloudflare token if given, signs the owner
 * in and sends them to the settings page. Gone for good once an owner password exists.
 */
async function setup(c: Ctx): Promise<Result> {
  if (!c.auth.setupOpen) return [html(messagePage('Not found', ''), 404), 'reject'];
  const token = String((c.req.method === 'POST' ? (await c.req.clone().formData().catch(() => null))?.get('token') : c.url.searchParams.get('token')) ?? '');
  if (!c.env.SETUP_TOKEN || !safeEqual(token, c.env.SETUP_TOKEN)) {
    return [html(messagePage('Setup', 'This page needs the setup link printed when the Worker was deployed.'), 403), 'reject'];
  }
  const view = { host: c.url.hostname, action: SETUP_PATH, token, ip: c.ip, cloudflare: Boolean(c.env.CF_API_TOKEN) };
  if (c.req.method !== 'POST') return [html(setupPage(view), 200, { 'cache-control': 'no-store' }), 'reject'];
  if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site request.'), 403), 'reject'];
  const form = await c.req.formData().catch(() => null);
  const password = String(form?.get('password') ?? '');
  const friend = String(form?.get('friend') ?? '');
  const fail = (error: string): Result => [html(setupPage({ ...view, error }), 400), 'reject'];
  if (password.length < MIN_PASSWORD) return fail(`The owner password needs at least ${MIN_PASSWORD} characters.`);
  if (password !== String(form?.get('password2') ?? '')) return fail('The two owner passwords differ.');
  if (friend && friend === password) return fail('The friend password must differ from the owner password.');
  const cfToken = String(form?.get('cfToken') ?? '').trim();
  const cfAccount = String(form?.get('cfAccount') ?? '').trim().toLowerCase();
  if (cfToken && !/^[0-9a-f]{32}$/.test(cfAccount)) return fail('The Cloudflare account id is 32 hex characters (dashboard → Workers & Pages → right column).');
  // Re-check under the lock-free assumption that two setups racing is harmless: last writer wins, both knew the token.
  if (await readAuth(c.env)) return [html(messagePage('Already set up', 'An owner password exists; sign in instead.'), 409), 'reject'];
  const cookieSecret = randomSecret();
  const ownerHash = await hashPassword(password);
  const friendHash = friend ? await hashPassword(friend) : undefined;
  await writeAuth(c.env, { owner: ownerHash, ...(friendHash ? { friend: friendHash } : {}), cookieSecret, at: c.deps.now() });
  if (cfToken) await writeCloudflareCreds(c.env, { token: cfToken, accountId: cfAccount });
  if (form?.get('allow') === '1' && c.ip && c.ip !== '0.0.0.0') {
    const doc = runtimeOverridesOf(await readRuntimeSettings(c.env));
    const allowIps = [...new Set([...(doc.access?.allowIps ?? c.cfg.allowIps), c.ip])];
    await writeRuntimeSettings(c.env, { ...doc, access: { allowIps, allowDns: doc.access?.allowDns ?? c.cfg.allowDns, trustSeconds: doc.access?.trustSeconds ?? c.cfg.trustSeconds, bypass: doc.access?.bypass ?? c.cfg.bypass.map((b) => `${b.host}${b.prefix}`) } });
  }
  c.invalidateRuntime();
  c.exec.waitUntil(markTrusted(c.env, c.ip, c.cfg.trustSeconds));
  const value = await signSession(cookieSecret, ownerHash, 'owner', Math.floor(c.deps.now() / 1000));
  return [
    new Response(null, { status: 303, headers: { location: `${c.url.origin}${SETTINGS_PATH}?ok=setup`, 'set-cookie': setCookie(value, c.cfg, c.cfg.cookieSeconds), 'cache-control': 'no-store' } }),
    'login',
  ];
}

/** Settings page: change the KV-stored passwords (owner must retype the current one). */
async function changePasswords(c: Ctx, form: FormData | null): Promise<string> {
  if (c.auth.kind !== 'hash') return 'Passwords are set in the secrets; change them there and redeploy.';
  const stored = await readAuth(c.env);
  if (!stored) return 'No stored passwords found.';
  if (!(await verifyPassword(String(form?.get('current') ?? ''), stored.owner))) return 'The current owner password is wrong.';
  const owner = String(form?.get('owner') ?? '');
  const friend = String(form?.get('friend') ?? '');
  if (owner && owner.length < MIN_PASSWORD) return `The owner password needs at least ${MIN_PASSWORD} characters.`;
  if (friend && friend !== '-' && friend === owner) return 'The friend password must differ from the owner password.';
  const next = { ...stored, at: c.deps.now() };
  if (owner) next.owner = await hashPassword(owner);
  if (friend === '-') delete next.friend;
  else if (friend) next.friend = await hashPassword(friend);
  await writeAuth(c.env, next);
  c.invalidateRuntime();
  return 'ok';
}

/**
 * /__wicket/settings — owner only. GET shows status, the notification policy and recent
 * bans; POST saves/resets the policy, sends a test message, unbans an address or lifts
 * the lockdown.
 */
const RECENT_BANS = 30;

async function settings(c: Ctx): Promise<Result> {
  const role = await sessionRole(c);
  if (role !== 'owner') {
    if (role === 'friend') return [html(messagePage('Owner only', 'Settings are for the owner password.'), 403), 'reject'];
    return [html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: SETTINGS_PATH }), 401), 'reject'];
  }
  const now = c.deps.now();

  if (c.req.method === 'POST') {
    if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site request.'), 403), 'reject'];
    const form = await c.req.formData().catch(() => null);
    const action = String(form?.get('action') ?? '');
    let notice = 'saved';
    if (action === 'reset') {
      await clearNotifySettings(c.env);
      notice = 'reset';
    } else if (action === 'test') {
      await emit(c.env, c.deps.fetch, { kind: 'test', severity: 'info', title: `${c.cfg.siteName}: test message`, text: `Sent from the settings page on ${c.url.hostname} by ${c.ip}.` }, now);
      notice = 'test';
    } else if (action === 'unban') {
      const ip = String(form?.get('ip') ?? '').trim();
      if (!ip || !(await isBanned(c.env, ip))) return [html(messagePage('Not banned', `${ip || '(empty)'} is not in the ban store.`), 404), 'admin'];
      await unbanAddress(c, ip, `from the settings page by ${c.ip}`);
      notice = 'unbanned';
    } else if (action === 'lift') {
      await liftLockdownAndTell(c, `from the settings page by ${c.ip}`);
      notice = 'lifted';
    } else if (action === 'host.save' || action === 'host.remove') {
      const result = await saveHost(c, action, form);
      if (result !== 'ok') return [html(messagePage('Not saved', result), 400), 'admin'];
      notice = action === 'host.save' ? 'host-saved' : 'host-removed';
    } else if (action === 'access.save' || action === 'limits.save') {
      const result = action === 'access.save' ? await saveAccess(c, form) : await saveLimits(c, form);
      if (result !== 'ok') return [html(messagePage('Not saved', result), 400), 'admin'];
      notice = action === 'access.save' ? 'access-saved' : 'limits-saved';
    } else if (action === 'auth.password') {
      const result = await changePasswords(c, form);
      if (result !== 'ok') return [html(messagePage('Not changed', result), 400), 'admin'];
      notice = 'password';
    } else if (action === 'cf.creds') {
      const token = String(form?.get('cfToken') ?? '').trim();
      const accountId = String(form?.get('cfAccount') ?? '').trim().toLowerCase();
      if (!token || !/^[0-9a-f]{32}$/.test(accountId)) return [html(messagePage('Not saved', 'A token and a 32-character account id are needed.'), 400), 'admin'];
      if (c.env.CF_API_TOKEN && !(await readAuth(c.env))) return [html(messagePage('Not saved', 'CF_API_TOKEN is set in the secrets and takes precedence.'), 400), 'admin'];
      await writeCloudflareCreds(c.env, { token, accountId });
      c.invalidateRuntime();
      notice = 'cf-creds';
    } else if (action === 'cf.list' || action === 'cf.waf') {
      const result = await cloudflareAction(c, action);
      if (result !== 'ok') return [html(messagePage('Cloudflare', result), 400), 'admin'];
      notice = action === 'cf.list' ? 'cf-list' : 'cf-waf';
    } else if (action === 'runtime.reset') {
      await clearRuntimeSettings(c.env);
      c.invalidateRuntime();
      notice = 'runtime-reset';
    } else {
      const base = mergePolicy(DEFAULT_POLICY, c.env.NOTIFY_POLICY_JSON);
      const kinds = { ...base.kinds };
      for (const k of POLICY_KINDS) {
        const v = form?.get(`kind.${k}`);
        if (isDelivery(v)) kinds[k] = v;
      }
      const policy: NotifyPolicy = mergePolicy(base, { kinds, digestSeconds: Number(form?.get('digest')) });
      await writeNotifySettings(c.env, policy);
    }
    return [new Response(null, { status: 303, headers: { location: `${c.url.origin}${SETTINGS_PATH}?ok=${notice}`, 'cache-control': 'no-store' } }), 'admin'];
  }

  const [policy, queues, lockdown, bans, rt] = await Promise.all([resolvePolicy(c.env), queueStatus(c.env, now), readLockdown(c.env), listBans(c.env), resolveRuntime(c.env)]);
  const cloudflare = await cloudflareStatus(c, rt.settings.listId, rt.overrides.cloudflare?.zoneId);
  const savedHosts = new Set(Object.keys(rt.overrides.hosts ?? {}).map((h) => h.toLowerCase()));
  const hostRows: HostRow[] = Object.entries(rt.hosts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([host, h]) => ({
      host,
      mode: h.mode,
      recipe: h.recipe ?? '',
      passthrough: h.passthrough ? (Object.entries(PASSTHROUGH_PRESETS).find(([, p]) => JSON.stringify(p) === JSON.stringify(h.passthrough))?.[0] ?? 'custom') : '',
      passthroughSpec: h.passthrough && !Object.values(PASSTHROUGH_PRESETS).some((p) => JSON.stringify(p) === JSON.stringify(h.passthrough)) ? formatPassthroughSpec(h.passthrough) : '',
      watchRules: h.watch.length,
      source: savedHosts.has(host) ? 'saved' : 'config',
    }));
  const banCounts: Partial<Record<BanKind | 'unknown', number>> = {};
  for (const b of bans) banCounts[b.kind ?? 'unknown'] = (banCounts[b.kind ?? 'unknown'] ?? 0) + 1;
  // Newest first from the key metadata; records are only read for the page shown, and only
  // for bans older than the metadata (the hourly job backfills those).
  const pageNo = Math.max(1, Math.floor(Number(c.url.searchParams.get('page')) || 1));
  const ordered = [...bans].sort((x, y) => (y.at ?? 0) - (x.at ?? 0));
  const slice = ordered.slice((pageNo - 1) * RECENT_BANS, pageNo * RECENT_BANS);
  const recent: BanRow[] = await Promise.all(
    slice.map(async (b) => {
      const r = b.at !== undefined ? null : await readBan(c.env, b.ip);
      return { ip: b.ip, kind: b.kind ?? r?.kind ?? 'unknown', host: b.host ?? r?.host ?? '', country: b.country ?? r?.country ?? '', at: b.at ?? r?.at ?? 0 };
    }),
  );
  const pages = Math.max(1, Math.ceil(ordered.length / RECENT_BANS));
  const ok = c.url.searchParams.get('ok');
  const NOTICES: Record<string, string> = {
    saved: 'Saved. Applies to the next event.',
    reset: 'Reset to the deploy-time config.',
    test: 'Test message sent to every channel.',
    unbanned: 'Unbanned.',
    lifted: 'Lockdown lifted.',
    'host-saved': 'Host saved. Live on every data centre within 30 s.',
    'host-removed': 'Host entry removed; wicket.yaml (or the default mode) applies again.',
    'runtime-reset': 'Hosts, access and limits reset to wicket.yaml.',
    'access-saved': 'Access settings saved. Live on every data centre within 30 s.',
    'limits-saved': 'Limits saved. Live on every data centre within 30 s.',
    'cf-list': 'IP list ready. Bans are added to it from now on.',
    'cf-creds': 'Cloudflare token saved.',
    password: 'Passwords changed. Browsers that used the old owner password are signed out.',
    setup: 'Welcome. wicket is set up; this address is allow-listed and signed in as owner.',
    'cf-waf': 'WAF rule ready. Listed addresses are blocked at the edge on every proxied host.',
  };
  const notice = ok ? NOTICES[ok] : undefined;
  return [
    html(
      settingsPage({
        host: c.url.hostname,
        action: SETTINGS_PATH,
        logout: `${ENDPOINT_PREFIX}logout`,
        hosts: hostRows,
        recipes: Object.keys(RECIPES),
        passthroughPresets: Object.keys(PASSTHROUGH_PRESETS),
        defaultMode: defaultMode(c.env),
        runtimeOverridden: rt.overridden,
        access: {
          allowIps: rt.settings.allowIps,
          allowDns: rt.settings.allowDns,
          trustSeconds: rt.settings.trustSeconds,
          bypass: rt.settings.bypass.map((b) => `${b.host}${b.prefix}`),
          saved: rt.overrides.access !== undefined,
        },
        limits: { values: Object.fromEntries(LIMIT_KEYS.map((k) => [k, rt.settings[k]])) as Record<LimitKey, number>, saved: rt.overrides.limits !== undefined },
        cloudflare,
        passwords: c.auth.kind === 'plain' ? 'secrets' : 'kv',
        hasFriend: Boolean(c.auth.friend),
        policy,
        source: policy.source,
        channels: queues,
        lockdown: lockdown ? { host: lockdown.host, fails: lockdown.fails, at: lockdown.at, until: lockdown.at + c.cfg.lockdownSeconds * 1000 } : null,
        banCounts,
        recent,
        page: Math.min(pageNo, pages),
        pages,
        perPage: RECENT_BANS,
        now,
        notice,
      }),
      200,
      { 'cache-control': 'no-store' },
    ),
    'admin',
  ];
}

const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/**
 * Hosts section: `host.save` writes one entry into the runtime overrides (replacing the
 * wicket.yaml entry for that host, or adding a host), `host.remove` drops the override.
 * Returns 'ok' or a message for the owner. The whole overrides document is one KV key, so a
 * save is one read and one write.
 */
async function saveHost(c: Ctx, action: 'host.save' | 'host.remove', form: FormData | null): Promise<string> {
  const host = String(form?.get('host') ?? '').trim().toLowerCase();
  if (!HOSTNAME.test(host)) return `"${host}" is not a valid hostname.`;
  if (c.cfg.cookieDomain && host !== c.cfg.cookieDomain && !host.endsWith(`.${c.cfg.cookieDomain}`)) return `"${host}" is not under ${c.cfg.cookieDomain}.`;
  const doc = runtimeOverridesOf(await readRuntimeSettings(c.env));
  const hosts: Record<string, unknown> = { ...(doc.hosts ?? {}) };
  if (action === 'host.remove') {
    if (!(host in hosts)) return `${host} has no saved entry.`;
    delete hosts[host];
  } else {
    const mode = String(form?.get('mode') ?? 'gated');
    if (!isHostMode(mode)) return `Unknown mode "${mode}".`;
    const recipe = String(form?.get('recipe') ?? '');
    if (recipe && !(recipe in RECIPES)) return `Unknown recipe "${recipe}".`;
    const passthrough = String(form?.get('passthrough') ?? '');
    const entry: Record<string, unknown> = { mode };
    if (mode === 'observe' && recipe) entry.recipe = recipe;
    if (mode === 'gated' && passthrough) {
      if (passthrough === 'custom') {
        const rule = parsePassthroughSpec(String(form?.get('spec') ?? ''));
        if (typeof rule === 'string') return `Pass-through rule: ${rule}.`;
        entry.passthrough = rule;
      } else if (passthrough in PASSTHROUGH_PRESETS) entry.passthrough = passthrough;
      else return `Unknown pass-through preset "${passthrough}".`;
    }
    // Watch rules from wicket.yaml survive a mode/recipe change made here.
    const watch = hostTableOf(c.env.HOSTS_JSON)[host]?.watch;
    if (mode === 'observe' && watch?.length) entry.watch = watch;
    hosts[host] = entry;
  }
  await writeRuntimeSettings(c.env, { ...doc, hosts });
  c.invalidateRuntime();
  return 'ok';
}

const LIST_NAME = 'wicket_banned';

/** c.env is the effective env; the secrets' own token is what the raw Worker env carries. */
const rawTokenInSecrets = (c: Ctx): boolean => Boolean(c.rawEnv.CF_API_TOKEN);

/** The Cloudflare section: what the token can see and what is wired. A few API calls, owner page only. */
async function cloudflareStatus(c: Ctx, listId: string, savedZoneId: string | undefined): Promise<CloudflareView> {
  const { env } = c;
  const token = await verifyToken(env, c.deps.fetch);
  const view: CloudflareView = {
    token: token.state,
    tokenSource: !env.CF_API_TOKEN ? 'none' : rawTokenInSecrets(c) ? 'secret' : 'kv',
    ...(token.state === 'invalid' ? { tokenNote: token.error } : {}),
    accountId: env.CF_ACCOUNT_ID ?? '',
    analytics: { ok: false, error: 'not checked' },
    list: { id: listId, source: listId ? (env.CF_LIST_ID ? 'secret' : 'saved') : 'none' },
    zone: c.cfg.zone,
    waf: c.cfg.zone ? 'unknown' : 'no-zone',
  };
  if (token.state !== 'active' || !env.CF_ACCOUNT_ID) {
    view.analytics = { ok: false, error: token.state === 'missing' ? 'CF_API_TOKEN missing' : `token ${token.state}` };
    return view;
  }
  const [analytics, lists] = await Promise.all([analyticsReachable(env, c.deps.fetch, c.cfg.analyticsDataset), listLists(env, c.deps.fetch)]);
  view.analytics = analytics;
  const mine = lists?.find((l) => l.id === listId);
  if (mine) view.list = { ...view.list, name: mine.name, items: mine.items };
  if (c.cfg.zone && listId) {
    const zone = savedZoneId ? { ok: true as const, id: savedZoneId } : await findZone(env, c.deps.fetch, c.cfg.zone);
    view.waf = zone.ok ? await wafRuleState(env, c.deps.fetch, zone.id, mine?.name ?? LIST_NAME) : 'unknown';
  }
  return view;
}

/** `cf.list` creates (or adopts) the IP list; `cf.waf` adds the blocking rule to the zone. Ids are kept in the runtime overrides. */
async function cloudflareAction(c: Ctx, action: 'cf.list' | 'cf.waf'): Promise<string> {
  const { env } = c;
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return 'CF_API_TOKEN and CF_ACCOUNT_ID must be set in the secrets first.';
  const doc = runtimeOverridesOf(await readRuntimeSettings(c.env));
  if (action === 'cf.list') {
    const r = await ensureList(env, c.deps.fetch, LIST_NAME);
    if (!r.ok) return `Could not create the IP list: ${r.error}. The token needs Account → Filter Lists: Edit.`;
    await writeRuntimeSettings(c.env, { ...doc, cloudflare: { ...(doc.cloudflare ?? {}), listId: r.id } });
    c.invalidateRuntime();
    return 'ok';
  }
  if (!c.cfg.zone) return 'The zone is not known to this deploy; redeploy with the current wicket.yaml first.';
  if (!c.cfg.listId) return 'Create the IP list first.';
  const zone = doc.cloudflare?.zoneId ? { ok: true as const, id: doc.cloudflare.zoneId } : await findZone(env, c.deps.fetch, c.cfg.zone);
  if (!zone.ok) return `Could not find zone ${c.cfg.zone}: ${zone.error}. The token needs Zone → Zone: Read.`;
  const lists = await listLists(env, c.deps.fetch);
  const name = lists?.find((l) => l.id === c.cfg.listId)?.name ?? LIST_NAME;
  const r = await ensureWafRule(env, c.deps.fetch, zone.id, name);
  if (!r.ok) return `Could not create the WAF rule: ${r.error}. The token needs Zone → Zone WAF: Edit.`;
  await writeRuntimeSettings(c.env, { ...doc, cloudflare: { ...(doc.cloudflare ?? {}), zoneId: zone.id } });
  c.invalidateRuntime();
  return 'ok';
}

const lines = (form: FormData | null, name: string): string[] =>
  String(form?.get(name) ?? '')
    .split(/\r?\n|,/)
    .map((s) => s.trim())
    .filter(Boolean);

/** Access section: allow lists, trust window, bypass prefixes → the runtime overrides document. */
async function saveAccess(c: Ctx, form: FormData | null): Promise<string> {
  const allowIps = lines(form, 'allowIps');
  for (const e of allowIps) if (!validAllowEntry(e)) return `"${e}" is not an IPv4/IPv6 address or CIDR.`;
  const allowDns = lines(form, 'allowDns').map((s) => s.toLowerCase());
  for (const n of allowDns) if (!validHostname(n)) return `"${n}" is not a hostname.`;
  const bypass = lines(form, 'bypass').map((s) => s.toLowerCase());
  for (const b of bypass) {
    const host = b.split('/')[0]!;
    if (!validHostname(host)) return `"${b}" must look like host/prefix.`;
    if (c.cfg.cookieDomain && host !== c.cfg.cookieDomain && !host.endsWith(`.${c.cfg.cookieDomain}`)) return `"${host}" is not under ${c.cfg.cookieDomain}.`;
  }
  const trustRaw = String(form?.get('trustSeconds') ?? '');
  const doc = runtimeOverridesOf(await readRuntimeSettings(c.env));
  const trustSeconds = trustRaw === 'custom' ? (doc.access?.trustSeconds ?? c.cfg.trustSeconds) : Number(trustRaw);
  if (!Number.isInteger(trustSeconds) || trustSeconds < 0) return 'Trust window must be a number of seconds.';
  await writeRuntimeSettings(c.env, { ...doc, access: { allowIps, allowDns, trustSeconds, bypass } });
  c.invalidateRuntime();
  return 'ok';
}

/** Limits section: counts and windows → the runtime overrides document. */
async function saveLimits(c: Ctx, form: FormData | null): Promise<string> {
  const limits: Partial<Record<LimitKey, number>> = {};
  for (const f of LIMIT_FIELDS) {
    const raw = String(form?.get(`limit.${f.key}`) ?? '').trim();
    if (!raw) return `${f.label}: a value is required.`;
    const n = f.kind === 'duration' ? parseDuration(raw) : /^\d+$/.test(raw) ? Number(raw) : null;
    if (n === null || !Number.isFinite(n)) return `${f.label}: "${raw}" is not ${f.kind === 'duration' ? 'a duration (30s, 10m, 24h, 7d)' : 'a whole number'}.`;
    if (n < (f.key === 'signatureLimit' ? 0 : 1)) return `${f.label}: must be at least ${f.key === 'signatureLimit' ? 0 : 1}.`;
    if (f.kind === 'duration' && n > 30 * 86_400) return `${f.label}: at most 30 days.`;
    limits[f.key] = n;
  }
  const doc = runtimeOverridesOf(await readRuntimeSettings(c.env));
  await writeRuntimeSettings(c.env, { ...doc, limits });
  c.invalidateRuntime();
  return 'ok';
}

/** Clears a ban in KV and the IP list and tells the channels; shared by the link and the page. */
async function unbanAddress(c: Ctx, ip: string, how: string): Promise<void> {
  await clearBan(c.env, ip);
  const edge = await listRemove(c.env, c.deps.fetch, c.cfg.listId, ip).catch(() => false);
  await emit(c.env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${c.cfg.siteName}: unbanned ${ip}`, text: `${how}.${edge ? ' Removed from the IP list.' : ''}` }, c.deps.now());
}

async function liftLockdownAndTell(c: Ctx, how: string): Promise<void> {
  await liftLockdown(c.env);
  await emit(c.env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${c.cfg.siteName}: lockdown lifted`, text: `${how}.` }, c.deps.now());
}

/** The signed link from a notification: lifts one address's ban, or the lockdown when `ip=*`. */
async function unban(c: Ctx): Promise<Result> {
  const { env, cfg, url } = c;
  if (!c.auth.cookieSecret) return [html(messagePage('Unavailable', 'The Worker has no secrets configured.'), 503), 'reject'];
  const ip = url.searchParams.get('ip') ?? '';
  const exp = Number(url.searchParams.get('exp'));
  const at = Number(url.searchParams.get('at'));
  const sig = url.searchParams.get('sig') ?? '';
  const now = Math.floor(c.deps.now() / 1000);
  if (!ip || !Number.isFinite(exp) || !Number.isFinite(at) || exp < now || !safeEqual(sig, await signUnban(c.auth.cookieSecret, ip, exp, at))) {
    return [html(messagePage('Invalid link', 'This unban link is invalid or has expired.'), 400), 'reject'];
  }
  // The link lifts the ban it was sent for, once: a later ban of the same address needs its own link.
  const current = ip === LOCKDOWN_IP ? await readLockdown(env) : await readBan(env, ip);
  if (!current || current.at !== at) return [html(messagePage('Nothing to lift', ip === LOCKDOWN_IP ? 'There is no lockdown this link belongs to.' : `${ip} is not banned by the ban this link belongs to.`), 410), 'reject'];
  if (ip === LOCKDOWN_IP) {
    await liftLockdownAndTell(c, `Clicked from ${c.ip}`);
    return [html(messagePage('Lockdown lifted', 'Password entry is open again.'), 200), 'unban'];
  }
  await unbanAddress(c, ip, `Clicked from ${c.ip}`);
  return [html(messagePage('Unbanned', `${ip} can try the password again.`), 200), 'unban'];
}
