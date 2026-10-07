import { listRemove } from '../cloudflare/lists';
import { ENDPOINT_PREFIX, safeNext, sameOrigin, setCookie } from '../core/credentials';
import { safeEqual, signSession, signUnban, type Role } from '../core/crypto';
import { ipAllowed } from '../core/ip';
import { emit } from '../notify';
import { clearBan, clearFailures, isBanned, isLockedDown, liftLockdown, LOCKDOWN_IP } from '../store/bans';
import { loginPage, messagePage } from '../ui/pages';
import type { Ctx, Result } from './context';
import { registerFailure } from './failures';
import { html } from './respond';

const LOGIN_ACTION = `${ENDPOINT_PREFIX}login`;

/** `/__wicket/*`: login (GET form, POST check), logout, unban. Answers every request under the prefix. */
export async function endpoints(c: Ctx): Promise<Result | null> {
  if (!c.url.pathname.startsWith(ENDPOINT_PREFIX)) return null;
  const route = c.url.pathname.slice(ENDPOINT_PREFIX.length);

  if (route === 'unban' && c.req.method === 'GET') return unban(c);
  if (route === 'logout') {
    return [html(messagePage('Signed out', 'The password cookie was cleared.'), 200, { 'set-cookie': setCookie('', c.cfg, 0) }), 'logout'];
  }
  if (route === 'login' && c.req.method === 'POST') return login(c);
  if (route === 'login') {
    return [html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: safeNext(c.url.searchParams.get('next')) }), 200), 'reject'];
  }
  return [html(messagePage('Not found', ''), 404), 'reject'];
}

export const loginForm = (c: Ctx, status: number) =>
  html(loginPage({ host: c.url.hostname, action: LOGIN_ACTION, next: c.url.pathname + c.url.search }), status);

async function login(c: Ctx): Promise<Result> {
  const { env, cfg, url, ip } = c;
  if (ipAllowed(ip, cfg.allowIps)) return [Response.redirect(`${url.origin}/`, 303), 'allow'];
  if (await isBanned(env, ip)) return [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'banned'];
  if (await isLockedDown(env)) {
    return [html(messagePage('Locked', 'Too many wrong passwords from the internet lately; password entry is paused for a while. Existing sessions keep working.'), 403), 'locked'];
  }
  if (!sameOrigin(c.req)) return [html(messagePage('Rejected', 'Cross-site login is not allowed.'), 403), 'reject'];

  const form = await c.req.formData().catch(() => null);
  const password = String(form?.get('password') ?? '');
  const next = safeNext(String(form?.get('next') ?? ''));
  const honeypot = String(form?.get('email') ?? '');

  // Fail closed: with the secret missing (e.g. a deploy that dropped secrets), comparing
  // against `undefined` would otherwise accept the literal password "undefined".
  if (!env.OWNER_PASSWORD || !env.COOKIE_SECRET) {
    return [html(messagePage('Unavailable', 'Password entry is disabled: the Worker has no secrets configured.'), 503), 'reject'];
  }

  let role: Role | null = null;
  if (!honeypot && password) {
    if (safeEqual(password, env.OWNER_PASSWORD)) role = 'owner';
    else if (env.FRIEND_PASSWORD && safeEqual(password, env.FRIEND_PASSWORD)) role = 'friend';
  }
  if (!role) return registerFailure(c, 'password', next);

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
    await emit(env, c.deps.fetch, { severity: 'info', title: `${cfg.siteName}: lockdown lifted`, text: `Clicked from ${c.ip}.` });
    return [html(messagePage('Lockdown lifted', 'Password entry is open again.'), 200), 'unban'];
  }
  await clearBan(env, ip);
  const edge = await listRemove(env, c.deps.fetch, ip).catch(() => false);
  await emit(env, c.deps.fetch, { severity: 'info', title: `${cfg.siteName}: unbanned ${ip}`, text: `Clicked from ${c.ip}.${edge ? ' Removed from the IP list.' : ''}` });
  return [html(messagePage('Unbanned', `${ip} can try the password again.`), 200), 'unban'];
}
