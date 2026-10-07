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
