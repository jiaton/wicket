import type { Env } from '../config/env';
import type { Fetch } from '../notify';

export type Row = Record<string, string | number>;

/** Runs a SQL query against Workers Analytics Engine and returns the rows ([] when unconfigured or failing). */
export async function sql(env: Env, doFetch: Fetch, query: string): Promise<Row[]> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return [];
  const res = await doFetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN}` },
    body: query,
  });
  if (!res.ok) {
    console.warn('analytics sql failed', res.status, (await res.text()).slice(0, 300));
    return [];
  }
  const data = (await res.json()) as { data?: Row[] };
  return data.data ?? [];
}

export interface HostStats {
  requests: number;
  /** Requests that reached the app: sessions, shares, tokens, allow list, pass-through, observe, open. */
  visits: number;
  /** Anonymous probes answered 401/403 and scanner bans. */
  probes: number;
  /** Bans of any kind triggered on the host. */
  bans: number;
  /** Requests refused because the address was already banned or the country rule said no. */
  blocked: number;
}

const VISIT_OUTCOMES = new Set(['pass', 'share', 'token', 'allow', 'bypass', 'preflight', 'observe', 'app', 'open', 'login']);
const PROBE_OUTCOMES = new Set(['reject', 'ban-scan']);
const BLOCKED_OUTCOMES = new Set(['banned', 'geo', 'locked']);

/** Last 24 hours per host, from one grouped query; {} when unconfigured or failing. */
export async function hostStats(env: Env, doFetch: Fetch, dataset: string): Promise<Record<string, HostStats>> {
  const rows = await sql(env, doFetch, `SELECT blob1 AS host, blob5 AS outcome, SUM(_sample_interval) AS n FROM ${dataset} WHERE timestamp > NOW() - INTERVAL '1' DAY GROUP BY host, outcome`);
  const out: Record<string, HostStats> = {};
  for (const row of rows) {
    const host = String(row.host);
    const outcome = String(row.outcome);
    const n = Number(row.n ?? 0);
    const s = (out[host] ??= { requests: 0, visits: 0, probes: 0, bans: 0, blocked: 0 });
    s.requests += n;
    if (VISIT_OUTCOMES.has(outcome)) s.visits += n;
    if (PROBE_OUTCOMES.has(outcome)) s.probes += n;
    if (outcome === 'ban' || outcome === 'ban-scan' || outcome === 'ban-origin') s.bans += n;
    if (BLOCKED_OUTCOMES.has(outcome)) s.blocked += n;
  }
  return out;
}
