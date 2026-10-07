import { banAddress } from '../actions/ban';
import { watchMatches } from '../config/hosts';
import { stripCredentials } from '../core/credentials';
import { recipeRules } from '../recipes';
import { bumpOriginFailures, clearOriginFailures } from '../store/bans';
import type { Ctx, Result } from './context';

/** Origin answers that, in bursts from one address, mean "scanner" on an observe host. */
const SCAN_STATUSES = new Set([400, 404, 405]);

/**
 * Observe mode: pass the request through, then look at what the origin answered.
 * A watch-rule match (e.g. POST /api/auth/login → 401) counts as a login failure for
 * this address; 4xx probe bursts count as scanning. The current response is always
 * returned as-is; the ban bites from the next request on.
 */
export async function observe(c: Ctx): Promise<Result> {
  const res = await c.deps.fetch(stripCredentials(c.req));
  const rules = [...recipeRules(c.host.recipe), ...c.host.watch];

  if (watchMatches(rules, c.req.method, c.url.pathname, res.status)) {
    const fails = await bumpOriginFailures(c.env, c.ip, c.cfg.originFailWindowSeconds);
    if (fails >= c.cfg.originFailLimit) {
      await banAddress(c, c.ip, 'origin', fails);
      c.exec.waitUntil(clearOriginFailures(c.env, c.ip));
    }
    return [res, 'origin-fail'];
  }

  if (SCAN_STATUSES.has(res.status) && c.scanner.hit(c.ip, c.cfg.scanLimit, c.cfg.scanWindowSeconds * 1000)) {
    c.scanner.reset(c.ip);
    c.exec.waitUntil(banAddress(c, c.ip, 'scan', c.cfg.scanLimit));
  }
  return [res, 'observe'];
}
