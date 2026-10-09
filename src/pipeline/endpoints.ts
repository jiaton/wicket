import { listRemove } from '../cloudflare/lists';
import { parseChannels } from '../config/channels';
import { DEFAULT_POLICY, isDelivery, mergePolicy, POLICY_KINDS, type NotifyPolicy } from '../config/notifications';
import { cookieValue, ENDPOINT_PREFIX, safeNext, sameOrigin, setCookie } from '../core/credentials';
import { safeEqual, signSession, signUnban, verifySession, type Role } from '../core/crypto';
import { ipAllowed } from '../core/ip';
import { emit, queueStatus } from '../notify';
import { resolvePolicy } from '../notify/policy';
import { clearBan, clearFailures, isBanned, isLockedDown, liftLockdown, listBans, LOCKDOWN_IP, readBan, readLockdown, type BanKind } from '../store/bans';
import { clearNotifySettings, writeNotifySettings } from '../store/settings';
import { loginPage, messagePage } from '../ui/pages';
import { settingsPage, type BanRow } from '../ui/settings';
import type { Ctx, Result } from './context';
import { registerFailure } from './failures';
import { html } from './respond';

const LOGIN_ACTION = `${ENDPOINT_PREFIX}login`;
const SETTINGS_PATH = `${ENDPOINT_PREFIX}settings`;

/** `/__wicket/*`: login (GET form, POST check), logout, unban. Answers every request under the prefix. */
export async function endpoints(c: Ctx): Promise<Result | null> {
  if (!c.url.pathname.startsWith(ENDPOINT_PREFIX)) return null;
  const route = c.url.pathname.slice(ENDPOINT_PREFIX.length);

  if (route === 'unban' && c.req.method === 'GET') return unban(c);
  if (route === 'logout') {
    return [html(messagePage('Signed out', 'The password cookie was cleared.'), 200, { 'set-cookie': setCookie('', c.cfg, 0) }), 'logout'];
  }
  if (route === 'login' && c.req.method === 'POST') return login(c);
  if (route === 'settings') return settings(c);
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
  const allowed = ipAllowed(ip, cfg.allowIps);
  if (!allowed && (await isBanned(env, ip))) return [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'banned'];
  if (!allowed && (await isLockedDown(env))) {
    return [html(messagePage('Locked', 'Too many wrong passwords from the internet lately; password entry is paused for a while. Existing sessions keep working.'), 403), 'locked'];
  }
  if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site login is not allowed.'), 403), 'reject'];

  const form = await c.req.formData().catch(() => null);
  const password = String(form?.get('password') ?? '');
  const next = safeNext(String(form?.get('next') ?? ''));
  // No honeypot field: browsers autofill hidden inputs no matter what they are called
  // (seen with "email" and "website"), and a human rejected that way looks like a brute-forcer.

  // Fail closed: with the secret missing (e.g. a deploy that dropped secrets), comparing
  // against `undefined` would otherwise accept the literal password "undefined".
  if (!env.OWNER_PASSWORD || !env.COOKIE_SECRET) {
    return [html(messagePage('Unavailable', 'Password entry is disabled: the Worker has no secrets configured.'), 503), 'reject'];
  }

  let role: Role | null = null;
  if (password) {
    if (safeEqual(password, env.OWNER_PASSWORD)) role = 'owner';
    else if (env.FRIEND_PASSWORD && safeEqual(password, env.FRIEND_PASSWORD)) role = 'friend';
  }
  if (!role) {
    console.warn('login rejected', url.hostname, ip, allowed ? 'allow-listed, not counted' : 'counted');
    if (allowed) return [html(loginPage({ host: url.hostname, action: LOGIN_ACTION, next, error: 'Wrong password.' }), 401), 'reject'];
    return registerFailure(c, 'password', next);
  }

  c.exec.waitUntil(clearFailures(env, ip));
  const issuedAt = Math.floor(c.deps.now() / 1000);
  const value = await signSession(env.COOKIE_SECRET, role === 'owner' ? env.OWNER_PASSWORD : env.FRIEND_PASSWORD!, role, issuedAt);
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
  const s = await verifySession(
    cookieValue(c.req),
    c.env.COOKIE_SECRET,
    { owner: c.env.OWNER_PASSWORD, friend: c.env.FRIEND_PASSWORD },
    Math.floor(c.deps.now() / 1000),
    c.cfg.cookieSeconds,
  );
  return s?.role ?? null;
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

  const [policy, queues, lockdown, bans] = await Promise.all([resolvePolicy(c.env), queueStatus(c.env, now), readLockdown(c.env), listBans(c.env)]);
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
  const notice =
    ok === 'saved' ? 'Saved. Applies to the next event.' : ok === 'reset' ? 'Reset to the deploy-time config.' : ok === 'test' ? 'Test message sent to every channel.' : ok === 'unbanned' ? 'Unbanned.' : ok === 'lifted' ? 'Lockdown lifted.' : undefined;
  return [
    html(
      settingsPage({
        host: c.url.hostname,
        action: SETTINGS_PATH,
        logout: `${ENDPOINT_PREFIX}logout`,
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

/** Clears a ban in KV and the IP list and tells the channels; shared by the link and the page. */
async function unbanAddress(c: Ctx, ip: string, how: string): Promise<void> {
  await clearBan(c.env, ip);
  const edge = await listRemove(c.env, c.deps.fetch, ip).catch(() => false);
  await emit(c.env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${c.cfg.siteName}: unbanned ${ip}`, text: `${how}.${edge ? ' Removed from the IP list.' : ''}` }, c.deps.now());
}

async function liftLockdownAndTell(c: Ctx, how: string): Promise<void> {
  await liftLockdown(c.env);
  await emit(c.env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${c.cfg.siteName}: lockdown lifted`, text: `${how}.` }, c.deps.now());
}

/** The signed link from a notification: lifts one address's ban, or the lockdown when `ip=*`. */
async function unban(c: Ctx): Promise<Result> {
  const { env, cfg, url } = c;
  const ip = url.searchParams.get('ip') ?? '';
  const exp = Number(url.searchParams.get('exp'));
  const sig = url.searchParams.get('sig') ?? '';
  const now = Math.floor(c.deps.now() / 1000);
  if (!ip || !Number.isFinite(exp) || exp < now || !safeEqual(sig, await signUnban(env.COOKIE_SECRET, ip, exp))) {
    return [html(messagePage('Invalid link', 'This unban link is invalid or has expired.'), 400), 'reject'];
  }
  if (ip === LOCKDOWN_IP) {
    await liftLockdownAndTell(c, `Clicked from ${c.ip}`);
    return [html(messagePage('Lockdown lifted', 'Password entry is open again.'), 200), 'unban'];
  }
  await unbanAddress(c, ip, `Clicked from ${c.ip}`);
  return [html(messagePage('Unbanned', `${ip} can try the password again.`), 200), 'unban'];
}
