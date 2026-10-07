import type { Env } from '../config/env';
import { settings } from '../config/settings';
import { flushQueues, type Fetch } from '../notify';
import { acquireJobLock } from '../store/locks';
import { runAnalysis } from './analyze';
import { reconcile } from './reconcile';

export const TICK_SECONDS = 300;
export const RECONCILE_SECONDS = 3600;

/** The five-minute job: traffic alerts, then the batched notification digests. */
export async function fiveMinuteJob(env: Env, doFetch: Fetch, now: number): Promise<void> {
  await runAnalysis(env, doFetch, now);
  await flushQueues(env, doFetch, settings(env).siteName);
}

/** The hourly job. */
export async function hourlyJob(env: Env, doFetch: Fetch): Promise<void> {
  await reconcile(env, doFetch);
}

/**
 * Runs `job` unless another caller ran it within the window. Cron and the request-path
 * fallback share these locks, so whichever fires first does the work and the other skips.
 */
export async function runOnce(env: Env, name: 'tick' | 'reconcile', windowSeconds: number, job: () => Promise<unknown>): Promise<boolean> {
  // A little shorter than the window so a cron that is a few seconds early still wins.
  if (!(await acquireJobLock(env, name, windowSeconds - 30))) return false;
  await job();
  return true;
}

/** True when the periodic jobs have anything to do (analytics alerts or batched channels). */
const jobsConfigured = (env: Env) => Boolean((env.CF_API_TOKEN && env.CF_ACCOUNT_ID) || env.NOTIFY_JSON);

/**
 * Request-path fallback for the cron. Cloudflare's cron delivery has been seen to stay silent
 * for a Worker for hours while `/schedules` lists its triggers (this project, 2026-10, and
 * several community reports). Every request therefore also checks, on the isolate's own
 * clock, whether a window has passed; if so it takes the KV lock and runs the job in the
 * background. Cost: one KV read per window per isolate, one write per window overall.
 */
export function createFallbackTick(deps: { fetch: Fetch; now: () => number }) {
  let nextTick = 0;
  let nextReconcile = 0;
  return (env: Env, exec: ExecutionContext): void => {
    if (!jobsConfigured(env)) return;
    const now = deps.now();
    if (now >= nextTick) {
      nextTick = now + TICK_SECONDS * 1000;
      exec.waitUntil(runOnce(env, 'tick', TICK_SECONDS, () => fiveMinuteJob(env, deps.fetch, now)));
    }
    if (now >= nextReconcile) {
      nextReconcile = now + RECONCILE_SECONDS * 1000;
      exec.waitUntil(runOnce(env, 'reconcile', RECONCILE_SECONDS, () => hourlyJob(env, deps.fetch)));
    }
  };
}
