import type { Env } from './config/env';
import { settings } from './config/settings';
import { fiveMinuteJob, hourlyJob, RECONCILE_SECONDS, runOnce, TICK_SECONDS } from './cron';
import { createHandler } from './pipeline/handler';

const deps = { fetch: (input: RequestInfo | URL, init?: RequestInit) => fetch(input, init), now: () => Date.now() };

export default {
  fetch: createHandler(deps),
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    const cfg = settings(env);
    if (controller.cron === cfg.reconcileCron) {
      ctx.waitUntil(runOnce(env, 'reconcile', RECONCILE_SECONDS, () => hourlyJob(env, deps.fetch, Date.now())));
      return;
    }
    ctx.waitUntil(runOnce(env, 'tick', TICK_SECONDS, () => fiveMinuteJob(env, deps.fetch, Date.now())));
  },
} satisfies ExportedHandler<Env>;
