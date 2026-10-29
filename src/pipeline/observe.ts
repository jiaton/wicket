import { banAddress } from '../actions/ban';
import { watchMatches, type WatchRule } from '../config/hosts';
import { stripCredentials } from '../core/credentials';
import { recipeRules } from '../recipes';
import { bumpOriginFailures, clearOriginFailures } from '../store/bans';
import type { Ctx, Outcome, Result } from './context';
import { signatureStrike } from './signatures';

/** Origin answers that, in bursts from one address, mean "scanner" on a forwarded host. */
const SCAN_STATUSES = new Set([400, 404, 405]);

/**
 * Forward the request to the origin, then look at what it answered. A watch-rule match
 * (e.g. POST /api/auth/login → 401) counts as a login failure for this address; known
 * scanner paths and 4xx probe bursts count as scanning. The current response is always
 * returned as-is; the ban bites from the next request on. Shared by observe mode (every
 * request) and by pass-through (requests carrying the app's own credential on a gated host).
 *
 * A failed KV write (quota, outage) is not fatal here: the app already answered and the
 * request is logged; the gate itself fails closed on the next password or token attempt.
 */
export async function forwardAndWatch(c: Ctx, rules: WatchRule[], ok: Outcome): Promise<Result> {
  const res = await c.deps.fetch(stripCredentials(c.req));

  if (watchMatches(rules, c.req.method, c.url.pathname, res.status)) {
    let fails = 0;
    try {
      fails = await bumpOriginFailures(c.env, c.ip, c.cfg.originFailWindowSeconds);
    } catch (err) {
      c.kv.failed('origin failure counter', err);
      return [res, 'origin-fail'];
    }
    if (fails >= c.cfg.originFailLimit) {
      const banned = await banAddress(c, c.ip, 'origin', fails);
      c.exec.waitUntil(clearOriginFailures(c.env, c.ip).catch(() => undefined));
      if (banned) return [res, 'ban-origin'];
    }
    return [res, 'origin-fail'];
  }

  // Requests for `/.env`-style files are a strike whatever the app answered (a single-page
  // app serves its index for them too); login paths and scanner User-Agents only count
  // when the app rejected the request.
  const strike = await signatureStrike(c, res.status < 400 ? 'files' : 'all');
  if (strike) return [res, strike[1]];
  if (SCAN_STATUSES.has(res.status) && c.scanner.hit(c.ip, c.cfg.scanLimit, c.cfg.scanWindowSeconds * 1000)) {
    c.scanner.reset(c.ip);
    if (await banAddress(c, c.ip, 'scan', c.cfg.scanLimit)) return [res, 'ban-scan'];
  }
  return [res, ok];
}

/** Observe mode: the app keeps its own login; wicket only watches and bans. */
export const observe = (c: Ctx): Promise<Result> => forwardAndWatch(c, [...recipeRules(c.host.recipe), ...c.host.watch], 'observe');

/**
 * Pass-through on a gated host: the request carries the app's own credential (see
 * `hosts.<name>.passthrough`), so the app decides. Its rejection statuses (`passthrough.status`,
 * 401 by default) on any path, plus the host's recipe and watch rules, count as failed logins.
 */
export function passthrough(c: Ctx): Promise<Result> {
  const rejected: WatchRule = { path: '/', status: c.host.passthrough?.status ?? [401] };
  return forwardAndWatch(c, [...recipeRules(c.host.recipe), ...c.host.watch, rejected], 'app');
}
