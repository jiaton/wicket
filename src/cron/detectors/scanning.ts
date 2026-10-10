import { hostList } from '../addresses';
import type { Detector } from './index';

/** Anonymous probing below the ban line, or a plain request burst. Informational. */
export const scanning: Detector = {
  id: 'scanning',
  async run(ctx) {
    const alerts = [];
    for (const [ip, a] of ctx.addresses) {
      if (a.probes < ctx.cfg.alertIpErrors && a.total < ctx.cfg.alertIpRequests) continue;
      if (await ctx.alreadyBanned(ip)) continue;
      const what = a.probes >= ctx.cfg.alertIpErrors ? `${a.probes} anonymous probes on ${hostList(a, (h) => h.probes)} (scanning, not banned yet)` : `${a.total} requests`;
      alerts.push({ key: `scan:${ip}`, kind: 'traffic' as const, severity: 'info' as const, text: `${ip} (${a.country}) ${what} in 5 min` });
    }
    return alerts;
  },
};
