import { recordBan } from '../actions/ban';
import type { Env } from '../config/env';
import type { Settings } from '../config/settings';
import { createAllowCheck } from '../pipeline/allow';
import type { Fetch } from '../notify';
import { isBanned } from '../store/bans';
import { hostList, type Address } from './addresses';

/**
 * The slow scanner ban. The request-path counter (`limits.scanner`, in isolate memory, per
 * data centre) catches bursts; this catches what it cannot: a scanner probing a few times a
 * minute, or spread over several data centres. Probes are counted from Analytics Engine
 * across the whole network over the five-minute window. Runs before the detectors, which
 * then skip the address. Returns the addresses banned.
 */
export async function banSlowScanners(env: Env, doFetch: Fetch, now: number, cfg: Settings, addresses: Map<string, Address>): Promise<string[]> {
  const banned: string[] = [];
  const deps = { fetch: doFetch, now: () => now };
  const allowed = createAllowCheck(deps);
  for (const [ip, a] of addresses) {
    if (a.probes < cfg.scanningLimit || a.bannedNow) continue;
    if ((await allowed(env, cfg, ip)) || (await isBanned(env, ip))) continue;
    const ok = await recordBan(env, deps, cfg, {
      ip,
      host: hostList(a, (h) => h.probes).split(', ')[0] || '',
      country: a.country,
      kind: 'scan',
      fails: a.probes,
      reason: `${a.probes} anonymous probes in 5 min across the network (scanner)`,
    });
    if (!ok) continue;
    a.bannedNow = true;
    banned.push(ip);
  }
  return banned;
}
