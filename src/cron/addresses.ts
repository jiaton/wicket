import type { Row } from '../cloudflare/analytics';

/**
 * Per-address view of the last window, folded from Analytics Engine rows grouped by
 * (ip, country, outcome, host). What a request's `outcome` (blob5) tells us:
 *   fail / ban      wrong wicket password or token       → fails
 *   origin-fail / ban-origin  an app's own login failed  → appFails
 *   reject          anonymous probe answered 401         → probes
 *   observe + 4xx   anonymous probe at an observe host   → probes
 *   ban-scan        the probe that banned a scanner      → probes
 *   banned          already blocked                      → nothing
 * Every `ban*` outcome also marks the address as banned in this window, so detectors
 * leave it alone; only `ban` (a password/token ban) counts as a credential attempt.
 */
export interface HostCounts {
  fails: number;
  appFails: number;
  probes: number;
}

export interface Address {
  country: string;
  total: number;
  /** Wrong wicket passwords/tokens (outcomes fail + ban). */
  fails: number;
  /** This window contained the request that banned the address. */
  bannedNow: boolean;
  /** Matched app login failures on observe hosts. */
  appFails: number;
  /** Anonymous probes: 401 rejections on gated hosts, 4xx at observe hosts. */
  probes: number;
  hosts: Map<string, HostCounts>;
}

const num = (v: string | number | undefined) => Number(v ?? 0);

export function foldAddresses(rows: Row[]): Map<string, Address> {
  const out = new Map<string, Address>();
  for (const row of rows) {
    const ip = String(row.ip);
    const a = out.get(ip) ?? { country: String(row.country ?? '?'), total: 0, fails: 0, bannedNow: false, appFails: 0, probes: 0, hosts: new Map<string, HostCounts>() };
    const host = String(row.host ?? '');
    const h = a.hosts.get(host) ?? { fails: 0, appFails: 0, probes: 0 };
    const n = num(row.n);
    const errors = num(row.errors);
    const outcome = String(row.outcome);
    a.total += n;
    if (outcome.startsWith('ban-') || outcome === 'ban') a.bannedNow = true;
    if (outcome === 'fail' || outcome === 'ban') {
      a.fails += n;
      h.fails += n;
    } else if (outcome === 'origin-fail' || outcome === 'ban-origin') {
      a.appFails += n;
      h.appFails += n;
    } else if (outcome === 'reject' || outcome === 'ban-scan') {
      a.probes += n;
      h.probes += n;
    } else if (outcome === 'observe') {
      a.probes += errors;
      h.probes += errors;
    }
    a.hosts.set(host, h);
    out.set(ip, a);
  }
  return out;
}

/** Up to three hosts where `pick` is largest, for alert text. */
export const hostList = (a: Address, pick: (h: HostCounts) => number) =>
  [...a.hosts.entries()]
    .filter(([, h]) => pick(h) > 0)
    .sort((x, y) => pick(y[1]) - pick(x[1]))
    .map(([host]) => host)
    .slice(0, 3)
    .join(', ');

export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
