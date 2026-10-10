import { WINDOW, type Detector } from './index';

const num = (v: string | number | undefined) => Number(v ?? 0);

export function localHour(now: number, timezone: string): number {
  const text = new Intl.DateTimeFormat('en-US', { hour: 'numeric', hour12: false, timeZone: timezone }).format(new Date(now));
  return Number(text) % 24;
}

export function inQuietHours(hour: number, range: [number, number] | null): boolean {
  if (!range) return false;
  const [from, to] = range;
  return from <= to ? hour >= from && hour <= to : hour >= from || hour <= to;
}

/** Successful use of an admin host during the configured quiet hours. */
export const quietHours: Detector = {
  id: 'quiet-hours',
  async run(ctx) {
    const { cfg } = ctx;
    if (!cfg.adminHosts.length || !inQuietHours(localHour(ctx.now, cfg.timezone), cfg.quietHours)) return [];
    const hosts = cfg.adminHosts.map((h) => `'${h.replace(/'/g, '')}'`).join(', ');
    const rows = await ctx.query(
      `SELECT blob1 AS host, blob3 AS ip, blob4 AS country, SUM(_sample_interval) AS n FROM ${cfg.analyticsDataset} WHERE ${WINDOW} AND blob1 IN (${hosts}) AND blob5 IN ('pass', 'token', 'login') GROUP BY host, ip, country`,
    );
    return rows.map((row) => ({
      key: `quiet:${String(row.host)}:${String(row.ip)}`,
      kind: 'traffic' as const,
      severity: 'info' as const,
      text: `${String(row.host)} used at night by ${String(row.ip)} (${String(row.country)}), ${num(row.n)} requests`,
    }));
  },
};
