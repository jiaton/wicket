import { sql, type Row } from '../cloudflare/analytics';
import type { Env } from '../config/env';
import type { PolicyKind } from '../config/notifications';
import { settings } from '../config/settings';
import { emit, type Fetch, type Severity } from '../notify';
import { failureCount, isBanned } from '../store/bans';
import { foldAddresses } from './addresses';
import { DETECTORS, WINDOW, type Alert, type DetectorContext } from './detectors';

export type { Alert } from './detectors';
export { foldAddresses } from './addresses';
export { inQuietHours, localHour } from './detectors/quiet-hours';

/**
 * Five-minute pass over the last five minutes of traffic (Analytics Engine, one row per
 * request): one base query folded per address, then every detector in `DETECTORS`, then
 * one notification per kind. Each alert key is deduplicated through KV for an hour so a
 * sustained event pings once; the fixed window plus the dedup is what makes overlapping
 * runs harmless (no watermark needed, and late-arriving rows are still seen).
 *
 * Column map (see pipeline/handler.ts): blob1 host, blob2 path, blob3 ip, blob4 country,
 * blob5 outcome, blob6 method, double1 status, double2 duration ms.
 */
export async function findAlerts(env: Env, doFetch: Fetch, now: number): Promise<Alert[]> {
  const cfg = settings(env);
  const query = (q: string) => sql(env, doFetch, q);
  const rows: Row[] = await query(
    `SELECT blob3 AS ip, blob4 AS country, blob5 AS outcome, blob1 AS host, SUM(_sample_interval) AS n, SUM(IF(double1 >= 400, _sample_interval, 0)) AS errors FROM ${cfg.analyticsDataset} WHERE ${WINDOW} GROUP BY ip, country, outcome, host ORDER BY n DESC LIMIT 400`,
  );
  const addresses = foldAddresses(rows);
  const bannedCache = new Map<string, Promise<boolean>>();
  const ctx: DetectorContext = {
    cfg,
    now,
    addresses,
    query,
    alreadyBanned: (ip) => {
      let p = bannedCache.get(ip);
      if (!p) {
        p = addresses.get(ip)?.bannedNow ? Promise.resolve(true) : isBanned(env, ip);
        bannedCache.set(ip, p);
      }
      return p;
    },
    failureCount: (ip) => failureCount(env, ip),
  };
  const alerts: Alert[] = [];
  for (const d of DETECTORS) {
    try {
      alerts.push(...(await d.run(ctx)));
    } catch (err) {
      console.warn(`detector ${d.id} failed`, String(err));
    }
  }
  return alerts;
}

const TITLES: Record<string, string> = {
  credentials: 'wicket password/token attempts',
  app_logins: 'app login failures',
  traffic: 'traffic',
};

/** Runs the detectors, drops alerts already sent this hour, and emits one event per kind. */
export async function runAnalysis(env: Env, doFetch: Fetch, now: number): Promise<Alert[]> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return [];
  const cfg = settings(env);
  const fresh: Alert[] = [];
  for (const alert of await findAlerts(env, doFetch, now)) {
    const key = `alert:${alert.key}`;
    if (await env.STORE.get(key)) continue;
    await env.STORE.put(key, '1', { expirationTtl: 3600 });
    fresh.push(alert);
  }
  const byKind = new Map<PolicyKind, Alert[]>();
  for (const a of fresh) byKind.set(a.kind, [...(byKind.get(a.kind) ?? []), a]);
  for (const [kind, list] of byKind) {
    const severity: Severity = list.some((a) => a.severity === 'critical') ? 'critical' : list.some((a) => a.severity === 'warn') ? 'warn' : 'info';
    await emit(env, doFetch, { kind, severity, title: `${cfg.siteName}: ${TITLES[kind] ?? kind}`, text: list.map((a) => `• ${a.text}`).join('\n') }, now);
  }
  return fresh;
}
