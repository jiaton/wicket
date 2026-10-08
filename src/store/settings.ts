import type { Env } from '../config/env';

/**
 * KV key `settings:notify`: the notification policy the owner saved on /__wicket/settings.
 * Absent = use the deploy-time config. Stored as the full policy JSON (see config/notifications.ts).
 */
const KEY = 'settings:notify';

export async function readNotifySettings(env: Env): Promise<unknown> {
  const raw = await env.STORE.get(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function writeNotifySettings(env: Env, policy: unknown): Promise<void> {
  await env.STORE.put(KEY, JSON.stringify(policy));
}

export async function clearNotifySettings(env: Env): Promise<void> {
  await env.STORE.delete(KEY);
}
