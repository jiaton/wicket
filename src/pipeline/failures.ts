import { banAddress, lockDown } from '../actions/ban';
import { ENDPOINT_PREFIX } from '../core/credentials';
import { bumpFailures, bumpGlobalFailures, clearFailures } from '../store/bans';
import { isTrusted } from '../store/trust';
import { loginPage, messagePage } from '../ui/pages';
import type { Ctx, Result } from './context';
import { html, json } from './respond';
import { scannerSignature } from './signatures';

/** The answer while KV writes are failing: nothing is counted, so nothing is accepted either. */
export const failClosed = (kind: 'password' | 'token'): Result =>
  kind === 'token'
    ? [json({ error: 'temporarily unavailable' }, 503), 'locked']
    : [html(messagePage('Temporarily unavailable', 'Password entry is paused for a few minutes. Existing sessions keep working.'), 503), 'locked'];

/**
 * A wrong password or wrong explicit token. Two counters move: the global one (rotating-IP
 * guessing → lockdown) and the per-address one (→ permanent ban at FAIL_LIMIT).
 *
 * `global` is false for app-style carriers (`X-API-Key`, `?token=`…): scanners spray those
 * at many hosts from many addresses, and they must not be able to pause password entry
 * for everyone. Guesses at wicket's own carriers and at the password always count.
 *
 * If KV refuses the write (free-tier quota, outage) the request fails closed: an attacker
 * who could exhaust the quota must not get uncounted guesses afterwards.
 */
export async function registerFailure(c: Ctx, kind: 'password' | 'token', next = '/', global = true): Promise<Result> {
  // An address with a recent owner session is the household, not an attacker: say "wrong", count nothing.
  if (await isTrusted(c.env, c.ip)) {
    if (kind === 'token') return [json({ error: 'invalid token' }, 401), 'fail'];
    return [html(loginPage({ host: c.url.hostname, action: `${ENDPOINT_PREFIX}login`, next, error: 'Wrong password.' }), 401), 'fail'];
  }
  if (c.kv.down()) return failClosed(kind);

  let fails: number;
  try {
    if (global && !(kind === 'token' && scannerSignature(c))) {
      const g = await bumpGlobalFailures(c.env, c.deps.now(), c.cfg.failGlobalWindowSeconds);
      if (g.n >= c.cfg.failGlobalLimit) await lockDown(c, g.n, Math.round((c.deps.now() - g.since) / 60_000));
    }
    fails = await bumpFailures(c.env, c.ip, c.cfg.failWindowSeconds);
  } catch (err) {
    c.kv.failed('failure counter', err);
    return failClosed(kind);
  }

  if (fails >= c.cfg.failLimit) {
    await banAddress(c, c.ip, kind, fails);
    c.exec.waitUntil(clearFailures(c.env, c.ip).catch(() => undefined));
    return [html(messagePage('Blocked', 'Too many failed attempts. This address has been blocked.'), 403), 'ban'];
  }
  if (kind === 'token') return [json({ error: 'invalid token' }, 401), 'fail'];
  return [
    html(loginPage({ host: c.url.hostname, action: `${ENDPOINT_PREFIX}login`, next, error: 'Wrong password.', remaining: c.cfg.failLimit - fails }), 401),
    'fail',
  ];
}
