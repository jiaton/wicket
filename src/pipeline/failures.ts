import { banAddress, lockDown } from '../actions/ban';
import { ENDPOINT_PREFIX } from '../core/credentials';
import { bumpFailures, bumpGlobalFailures, clearFailures } from '../store/bans';
import { loginPage, messagePage } from '../ui/pages';
import type { Ctx, Result } from './context';
import { html, json } from './respond';

/**
 * A wrong password or wrong explicit token. Two counters move: the global one (rotating-IP
 * guessing → lockdown) and the per-address one (→ permanent ban at FAIL_LIMIT).
 */
export async function registerFailure(c: Ctx, kind: 'password' | 'token', next = '/'): Promise<Result> {
  const global = await bumpGlobalFailures(c.env, c.deps.now(), c.cfg.failGlobalWindowSeconds);
  if (global.n >= c.cfg.failGlobalLimit) {
    await lockDown(c, global.n, Math.round((c.deps.now() - global.since) / 60_000));
  }

  const fails = await bumpFailures(c.env, c.ip, c.cfg.failWindowSeconds);
  if (fails >= c.cfg.failLimit) {
    await banAddress(c, c.ip, kind, fails);
    c.exec.waitUntil(clearFailures(c.env, c.ip));
    return [html(messagePage('Blocked', 'Too many failed attempts. This address has been blocked.'), 403), 'ban'];
  }
  if (kind === 'token') return [json({ error: 'invalid token' }, 401), 'fail'];
  return [
    html(loginPage({ host: c.url.hostname, action: `${ENDPOINT_PREFIX}login`, next, error: 'Wrong password.', remaining: c.cfg.failLimit - fails }), 401),
    'fail',
  ];
}
