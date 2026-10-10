import type { Detector } from './index';

/** Wrong wicket credentials from several addresses at once: distributed guessing (the lockdown's early warning). */
export const guessing: Detector = {
  id: 'guessing',
  async run(ctx) {
    const guessers = [...ctx.addresses.entries()].filter(([, a]) => a.fails > 0);
    if (guessers.length < ctx.cfg.alertGuessIps) return [];
    const attempts = guessers.reduce((n, [, a]) => n + a.fails, 0);
    const ips = guessers.map(([ip]) => ip);
    return [
      {
        key: `guessing:${Math.floor(ctx.now / 3_600_000)}`,
        kind: 'credentials',
        severity: 'warn',
        text: `wicket password/token guessing from ${guessers.length} different addresses in 5 min (${attempts} attempts): ${ips.slice(0, 5).join(', ')}${ips.length > 5 ? ', …' : ''}`,
      },
    ];
  },
};
