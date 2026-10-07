import type { Env } from '../config/env';

/**
 * KV keys `job:<name>`: a time-boxed lock so a periodic job runs once per window even when
 * several isolates (or cron + the request-path fallback) try at the same time. KV is
 * eventually consistent, so two takers within the same second can both win; every job
 * behind this lock is idempotent, so that only costs a duplicate query, never a duplicate alert.
 */
export async function acquireJobLock(env: Env, name: string, seconds: number): Promise<boolean> {
  const key = `job:${name}`;
  if ((await env.STORE.get(key)) !== null) return false;
  await env.STORE.put(key, '1', { expirationTtl: Math.max(60, seconds) });
  return true;
}
