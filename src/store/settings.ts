import type { Env } from '../config/env';

/**
 * Settings the owner saved on /__wicket/settings. Absent = use the deploy-time config.
 *   settings:notify   the notification policy (full policy JSON, see config/notifications.ts)
 *   settings:runtime  hosts / access / limits overrides (see config/runtime.ts)
 */
const NOTIFY_KEY = 'settings:notify';
const RUNTIME_KEY = 'settings:runtime';

async function readJson(env: Env, key: string): Promise<unknown> {
  const raw = await env.STORE.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export const readNotifySettings = (env: Env): Promise<unknown> => readJson(env, NOTIFY_KEY);
export const writeNotifySettings = (env: Env, policy: unknown): Promise<void> => env.STORE.put(NOTIFY_KEY, JSON.stringify(policy));
export const clearNotifySettings = (env: Env): Promise<void> => env.STORE.delete(NOTIFY_KEY);

export const readRuntimeSettings = (env: Env): Promise<unknown> => readJson(env, RUNTIME_KEY);
export const writeRuntimeSettings = (env: Env, doc: unknown): Promise<void> => env.STORE.put(RUNTIME_KEY, JSON.stringify(doc));
export const clearRuntimeSettings = (env: Env): Promise<void> => env.STORE.delete(RUNTIME_KEY);
