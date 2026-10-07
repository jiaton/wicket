import { sql, type Row } from '../cloudflare/analytics';
import type { Env } from '../config/env';
import { settings, type Settings } from '../config/settings';
import { emit, type Fetch, type Severity } from '../notify';

/**
 * Cron pass over the last five minutes of traffic. Each alert kind is deduplicated
 * through KV for an hour so a sustained event pings once.
 *
 * Column map (see pipeline/handler.ts): blob1 host, blob2 path, blob3 ip, blob4 country,
 * blob5 outcome, blob6 method, double1 status, double2 duration ms.
 */
export interface Alert {
  key: string;
  text: string;
  /** Distributed guessing is `warn`; the rest is informational. */
  severity: Severity;
}

const WINDOW = "timestamp > NOW() - INTERVAL '5' MINUTE";
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

export async function findAlerts(env: Env, cfg: Settings, doFetch: Fetch, now: number): Promise<Alert[]> {
  const query = (q: string) => sql(env, doFetch, q);
  const DATASET = cfg.analyticsDataset;
  const alerts: Alert[] = [];

  const byIp: Row[] = await query(
    `SELECT blob3 AS ip, blob4 AS country, SUM(_sample_interval) AS n, SUM(IF(double1 >= 400, _sample_interval, 0)) AS errors FROM ${DATASET} WHERE ${WINDOW} GROUP BY ip, country ORDER BY n DESC LIMIT 50`,
  );
  for (const row of byIp) {
    const ip = String(row.ip);
    if (num(row.n) >= cfg.alertIpRequests) {
      alerts.push({ key: `burst:${ip}`, severity: 'info', text: `${ip} (${String(row.country)}) made ${num(row.n)} requests in 5 min` });
    }
    if (num(row.errors) >= cfg.alertIpErrors) {
      alerts.push({ key: `errors:${ip}`, severity: 'info', text: `${ip} (${String(row.country)}) hit ${num(row.errors)} 4xx/5xx responses in 5 min` });
    }
  }

  const guessing = await query(`SELECT blob3 AS ip, SUM(_sample_interval) AS n FROM ${DATASET} WHERE ${WINDOW} AND blob5 IN ('fail', 'ban') GROUP BY ip`);
  if (guessing.length >= cfg.alertGuessIps) {
    const total = guessing.reduce((sum, r) => sum + num(r.n), 0);
    alerts.push({
      key: `guessing:${Math.floor(now / 3_600_000)}`,
      severity: 'warn',
      text: `password/token guessing from ${guessing.length} different addresses in 5 min (${total} attempts): ${guessing.slice(0, 5).map((r) => String(r.ip)).join(', ')}${guessing.length > 5 ? ', …' : ''}`,
    });
  }

  const recentCountries = await query(`SELECT blob4 AS country, SUM(_sample_interval) AS n FROM ${DATASET} WHERE ${WINDOW} AND blob5 IN ('pass', 'token', 'login') GROUP BY country`);
  if (recentCountries.length) {
    const known = await query(
      `SELECT blob4 AS country FROM ${DATASET} WHERE timestamp > NOW() - INTERVAL '7' DAY AND timestamp <= NOW() - INTERVAL '5' MINUTE AND blob5 IN ('pass', 'token', 'login') GROUP BY country`,
    );
    const seen = new Set(known.map((r) => String(r.country)));
    for (const row of recentCountries) {
      const cc = String(row.country);
      if (!seen.has(cc)) alerts.push({ key: `country:${cc}`, severity: 'info', text: `first successful visits from ${cc} in a week (${num(row.n)} requests)` });
    }
  }

  if (cfg.adminHosts.length && inQuietHours(localHour(now, cfg.timezone), cfg.quietHours)) {
    const hosts = cfg.adminHosts.map((h) => `'${h.replace(/'/g, '')}'`).join(', ');
    const rows = await query(
      `SELECT blob1 AS host, blob3 AS ip, blob4 AS country, SUM(_sample_interval) AS n FROM ${DATASET} WHERE ${WINDOW} AND blob1 IN (${hosts}) AND blob5 IN ('pass', 'token', 'login') GROUP BY host, ip, country`,
    );
    for (const row of rows) {
      alerts.push({
        key: `quiet:${row.host}:${row.ip}`,
        severity: 'info',
        text: `${String(row.host)} used at night by ${String(row.ip)} (${String(row.country)}), ${num(row.n)} requests`,
      });
    }
  }

  return alerts;
}

export async function runAnalysis(env: Env, doFetch: Fetch, now: number): Promise<Alert[]> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return [];
  const cfg = settings(env);
  const fresh: Alert[] = [];
  for (const alert of await findAlerts(env, cfg, doFetch, now)) {
    const key = `alert:${alert.key}`;
    if (await env.STORE.get(key)) continue;
    await env.STORE.put(key, '1', { expirationTtl: 3600 });
    fresh.push(alert);
  }
  if (fresh.length) {
    // One message per tick; it carries the highest severity among its lines.
    const severity: Severity = fresh.some((a) => a.severity === 'warn') ? 'warn' : 'info';
    await emit(env, doFetch, { severity, title: `${cfg.siteName}: traffic`, text: fresh.map((a) => `• ${a.text}`).join('\n') });
  }
  return fresh;
}
