import { sql, type Row } from '../cloudflare/analytics';
import type { Env } from '../config/env';
import type { PolicyKind } from '../config/notifications';
import { settings, type Settings } from '../config/settings';
import { emit, type Fetch, type Severity } from '../notify';
import { failureCount, isBanned } from '../store/bans';

/**
 * Five-minute pass over the last five minutes of traffic (Analytics Engine, one row per
 * request). Each alert is deduplicated through KV for an hour so a sustained event pings once.
 *
 * What a request's `outcome` (blob5) tells us, per address:
 *   fail / ban      wrong wicket password or token       → credentials (someone is after *you*)
 *   origin-fail     an app's own login failed (observe)  → app_logins
 *   reject          anonymous probe answered 401         → scanning (noise until it earns a ban)
 *   observe + 4xx   anonymous probe at an observe host   → scanning
 *   banned          already blocked                      → nothing to say
 *
 * Column map (see pipeline/handler.ts): blob1 host, blob2 path, blob3 ip, blob4 country,
 * blob5 outcome, blob6 method, double1 status, double2 duration ms.
 */
export interface Alert {
  key: string;
  text: string;
  severity: Severity;
  /** Which notification policy entry decides its delivery. */
  kind: PolicyKind;
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

interface HostCounts {
  fails: number;
  appFails: number;
  probes: number;
}

interface Address {
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

/** Folds the per-(ip, outcome, host) rows into one record per address. */
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
    if (outcome === 'fail' || outcome === 'ban') {
      a.fails += n;
      h.fails += n;
      if (outcome === 'ban') a.bannedNow = true;
    } else if (outcome === 'origin-fail') {
      a.appFails += n;
      h.appFails += n;
    } else if (outcome === 'reject') {
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

const hostList = (a: Address, pick: (h: HostCounts) => number) =>
  [...a.hosts.entries()]
    .filter(([, h]) => pick(h) > 0)
    .sort((x, y) => pick(y[1]) - pick(x[1]))
    .map(([host]) => host)
    .slice(0, 3)
    .join(', ');

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

export async function findAlerts(env: Env, cfg: Settings, doFetch: Fetch, now: number): Promise<Alert[]> {
  const query = (q: string) => sql(env, doFetch, q);
  const DATASET = cfg.analyticsDataset;
  const alerts: Alert[] = [];

  const rows: Row[] = await query(
    `SELECT blob3 AS ip, blob4 AS country, blob5 AS outcome, blob1 AS host, SUM(_sample_interval) AS n, SUM(IF(double1 >= 400, _sample_interval, 0)) AS errors FROM ${DATASET} WHERE ${WINDOW} GROUP BY ip, country, outcome, host ORDER BY n DESC LIMIT 400`,
  );
  const addresses = foldAddresses(rows);
  let guessers = 0;
  let attempts = 0;

  for (const [ip, a] of addresses) {
    if (a.fails) {
      guessers += 1;
      attempts += a.fails;
    }
    // A ban in this window was reported as a ban; an older ban's leftover 403s are not news.
    if (a.bannedNow || (await isBanned(env, ip))) continue;

    if (a.fails) {
      const counted = await failureCount(env, ip);
      const left = Math.max(0, cfg.failLimit - counted);
      alerts.push({
        key: `cred:${ip}`,
        kind: 'credentials',
        severity: 'warn',
        text: `${ip} (${a.country}) sent ${plural(a.fails, 'wrong wicket password/token')} on ${hostList(a, (h) => h.fails)} in 5 min${left ? ` (${left} more → ban)` : ''}`,
      });
    }
    if (a.appFails) {
      alerts.push({
        key: `app:${ip}`,
        kind: 'app_logins',
        severity: 'warn',
        text: `${ip} (${a.country}) failed ${plural(a.appFails, 'login')} at ${hostList(a, (h) => h.appFails)} in 5 min`,
      });
    }
    if (a.probes >= cfg.alertIpErrors || a.total >= cfg.alertIpRequests) {
      const what = a.probes >= cfg.alertIpErrors ? `${a.probes} anonymous probes on ${hostList(a, (h) => h.probes)} (scanning, not banned yet)` : `${a.total} requests`;
      alerts.push({ key: `scan:${ip}`, kind: 'traffic', severity: 'info', text: `${ip} (${a.country}) ${what} in 5 min` });
    }
  }

  if (guessers >= cfg.alertGuessIps) {
    const ips = [...addresses.entries()].filter(([, a]) => a.fails).map(([ip]) => ip);
    alerts.push({
      key: `guessing:${Math.floor(now / 3_600_000)}`,
      kind: 'credentials',
      severity: 'warn',
      text: `wicket password/token guessing from ${guessers} different addresses in 5 min (${attempts} attempts): ${ips.slice(0, 5).join(', ')}${ips.length > 5 ? ', …' : ''}`,
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
      if (!seen.has(cc)) alerts.push({ key: `country:${cc}`, kind: 'traffic', severity: 'info', text: `first successful visits from ${cc} in a week (${num(row.n)} requests)` });
    }
  }

  if (cfg.adminHosts.length && inQuietHours(localHour(now, cfg.timezone), cfg.quietHours)) {
    const hosts = cfg.adminHosts.map((h) => `'${h.replace(/'/g, '')}'`).join(', ');
    const quiet = await query(
      `SELECT blob1 AS host, blob3 AS ip, blob4 AS country, SUM(_sample_interval) AS n FROM ${DATASET} WHERE ${WINDOW} AND blob1 IN (${hosts}) AND blob5 IN ('pass', 'token', 'login') GROUP BY host, ip, country`,
    );
    for (const row of quiet) {
      alerts.push({
        key: `quiet:${row.host}:${row.ip}`,
        kind: 'traffic',
        severity: 'info',
        text: `${String(row.host)} used at night by ${String(row.ip)} (${String(row.country)}), ${num(row.n)} requests`,
      });
    }
  }

  return alerts;
}

const TITLES: Record<string, string> = {
  credentials: 'wicket password/token attempts',
  app_logins: 'app login failures',
  traffic: 'traffic',
};

/** Runs the analysis, drops alerts already sent this hour, and emits one event per kind. */
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
  const byKind = new Map<PolicyKind, Alert[]>();
  for (const a of fresh) byKind.set(a.kind, [...(byKind.get(a.kind) ?? []), a]);
  for (const [kind, list] of byKind) {
    const severity: Severity = list.some((a) => a.severity === 'critical') ? 'critical' : list.some((a) => a.severity === 'warn') ? 'warn' : 'info';
    await emit(env, doFetch, { kind, severity, title: `${cfg.siteName}: ${TITLES[kind] ?? kind}`, text: list.map((a) => `• ${a.text}`).join('\n') }, now);
  }
  return fresh;
}
