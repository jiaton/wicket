import { WINDOW, type Detector } from './index';

const num = (v: string | number | undefined) => Number(v ?? 0);

/** Successful visits (cookie, token, login) from a country not seen in the last week. */
export const newCountry: Detector = {
  id: 'new-country',
  async run(ctx) {
    const ds = ctx.cfg.analyticsDataset;
    const recent = await ctx.query(`SELECT blob4 AS country, SUM(_sample_interval) AS n FROM ${ds} WHERE ${WINDOW} AND blob5 IN ('pass', 'token', 'login') GROUP BY country`);
    if (!recent.length) return [];
    const known = await ctx.query(
      `SELECT blob4 AS country FROM ${ds} WHERE timestamp > NOW() - INTERVAL '7' DAY AND timestamp <= NOW() - INTERVAL '5' MINUTE AND blob5 IN ('pass', 'token', 'login') GROUP BY country`,
    );
    const seen = new Set(known.map((r) => String(r.country)));
    return recent
      .filter((r) => !seen.has(String(r.country)))
      .map((r) => ({ key: `country:${String(r.country)}`, kind: 'traffic' as const, severity: 'info' as const, text: `first successful visits from ${String(r.country)} in a week (${num(r.n)} requests)` }));
  },
};
