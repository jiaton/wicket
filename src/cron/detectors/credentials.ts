import { hostList, plural } from '../addresses';
import type { Detector } from './index';

/** Any wrong wicket password/token from an address: someone is after you, not the internet at large. */
export const credentials: Detector = {
  id: 'credentials',
  async run(ctx) {
    const alerts = [];
    for (const [ip, a] of ctx.addresses) {
      if (!a.fails || (await ctx.alreadyBanned(ip))) continue;
      const left = Math.max(0, ctx.cfg.failLimit - (await ctx.failureCount(ip)));
      alerts.push({
        key: `cred:${ip}`,
        kind: 'credentials' as const,
        severity: 'warn' as const,
        text: `${ip} (${a.country}) sent ${plural(a.fails, 'wrong wicket password/token')} on ${hostList(a, (h) => h.fails)} in 5 min${left ? ` (${left} more → ban)` : ''}`,
      });
    }
    return alerts;
  },
};
