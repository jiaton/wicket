import { listRemove } from '../cloudflare/lists';
import { parseChannels } from '../config/channels';
import { DEFAULT_POLICY, isDelivery, mergePolicy, POLICY_KINDS, type NotifyPolicy } from '../config/notifications';
import { cookieValue, ENDPOINT_PREFIX, safeNext, sameOrigin, setCookie } from '../core/credentials';
import { safeEqual, signSession, signUnban, verifySession, type Role } from '../core/crypto';
import { ipAllowed } from '../core/ip';
import { emit } from '../notify';
import { resolvePolicy } from '../notify/policy';
import { clearBan, clearFailures, isBanned, isLockedDown, liftLockdown, listBans, LOCKDOWN_IP } from '../store/bans';
import { clearNotifySettings, writeNotifySettings } from '../store/settings';
import { loginPage, messagePage } from '../ui/pages';
import { settingsPage } from '../ui/settings';
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
  // Honeypot for dumb bots. Named so that browser and password-manager autofill (which key
  // off "email"/"username" labels) leave it alone; a real person never sees it.
  const honeypot = String(form?.get('website') ?? '');

  // Fail closed: with the secret missing (e.g. a deploy that dropped secrets), comparing
  // against `undefined` would otherwise accept the literal password "undefined".
  if (!env.OWNER_PASSWORD || !env.COOKIE_SECRET) {
    return [html(messagePage('Unavailable', 'Password entry is disabled: the Worker has no secrets configured.'), 503), 'reject'];
  }

  // A filled honeypot means a bot, or a browser that autofilled a hidden field. Either way:
  // do not check the password (no oracle for the bot) and do not count a strike (no ban for
  // the person). Just show the form again.
  if (honeypot) return [html(loginPage({ host: url.hostname, action: LOGIN_ACTION, next, error: 'Wrong password.' }), 401), 'reject'];

  let role: Role | null = null;
  if (password) {
    if (safeEqual(password, env.OWNER_PASSWORD)) role = 'owner';
    else if (env.FRIEND_PASSWORD && safeEqual(password, env.FRIEND_PASSWORD)) role = 'friend';
  }
  if (!role) {
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
 * /__wicket/settings — owner only. GET shows the notification policy; POST saves it to KV
 * (overriding wicket.yaml until reset), resets it, or sends a test message.
 */
async function settings(c: Ctx): Promise<Result> {
  const role = await sessionRole(c);
  if (role !== 'owner') {
    if (role === 'friend') return [html(messagePage('Owner only', 'Settings are for the owner password.'), 403), 'reject'];
    return [html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: SETTINGS_PATH }), 401), 'reject'];
  }

  if (c.req.method === 'POST') {
    if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site request.'), 403), 'reject'];
    const form = await c.req.formData().catch(() => null);
    const action = String(form?.get('action') ?? '');
    let notice = 'saved';
    if (action === 'reset') {
      await clearNotifySettings(c.env);
      notice = 'reset';
    } else if (action === 'test') {
      await emit(
        c.env,
        c.deps.fetch,
        { kind: 'test', severity: 'info', title: `${c.cfg.siteName}: test message`, text: `Sent from the settings page on ${c.url.hostname} by ${c.ip}.` },
        c.deps.now(),
      );
      notice = 'test';
    } else {
      const base = mergePolicy(DEFAULT_POLICY, c.env.NOTIFY_POLICY_JSON);
      const kinds = { ...base.kinds };
      for (const k of POLICY_KINDS) {
        const v = form?.get(`kind.${k}`);
        if (isDelivery(v)) kinds[k] = v;
      }
      const digest = Number(form?.get('digest'));
      const policy: NotifyPolicy = mergePolicy(base, { kinds, digestSeconds: digest });
      await writeNotifySettings(c.env, policy);
    }
    return [new Response(null, { status: 303, headers: { location: `${c.url.origin}${SETTINGS_PATH}?ok=${notice}`, 'cache-control': 'no-store' } }), 'admin'];
  }

  const policy = await resolvePolicy(c.env);
  const bans: Record<string, number> = {};
  for (const b of await listBans(c.env)) bans[b.kind ?? 'older'] = (bans[b.kind ?? 'older'] ?? 0) + 1;
  const ok = c.url.searchParams.get('ok');
  const notice = ok === 'saved' ? 'Saved. Applies to the next event.' : ok === 'reset' ? 'Reset to the deploy-time config.' : ok === 'test' ? 'Test message sent to every channel.' : undefined;
  return [
    html(
      settingsPage({
        host: c.url.hostname,
        action: SETTINGS_PATH,
        policy,
        source: policy.source,
        channels: parseChannels(c.env).map((ch) => ch.type),
        bans,
        notice,
      }),
      200,
      { 'cache-control': 'no-store' },
    ),
    'admin',
  ];
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
    await liftLockdown(env);
    await emit(env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${cfg.siteName}: lockdown lifted`, text: `Clicked from ${c.ip}.` }, c.deps.now());
    return [html(messagePage('Lockdown lifted', 'Password entry is open again.'), 200), 'unban'];
  }
  await clearBan(env, ip);
  const edge = await listRemove(env, c.deps.fetch, ip).catch(() => false);
  await emit(env, c.deps.fetch, { kind: 'unban', severity: 'info', title: `${cfg.siteName}: unbanned ${ip}`, text: `Clicked from ${c.ip}.${edge ? ' Removed from the IP list.' : ''}` }, c.deps.now());
  return [html(messagePage('Unbanned', `${ip} can try the password again.`), 200), 'unban'];
}
