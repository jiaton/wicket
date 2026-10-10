import { hostList, plural } from '../addresses';
import type { Detector } from './index';

/** Failed logins at apps in observe mode (matched watch rules / recipes). */
export const appLogins: Detector = {
  id: 'app-logins',
  async run(ctx) {
    const alerts = [];
    for (const [ip, a] of ctx.addresses) {
      if (!a.appFails || (await ctx.alreadyBanned(ip))) continue;
      alerts.push({
        key: `app:${ip}`,
        kind: 'app_logins' as const,
        severity: 'warn' as const,
        text: `${ip} (${a.country}) failed ${plural(a.appFails, 'login')} at ${hostList(a, (h) => h.appFails)} in 5 min`,
      });
    }
    return alerts;
  },
};
