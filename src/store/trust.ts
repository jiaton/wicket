import type { Env } from '../config/env';
import { addressKey } from '../core/ip';

/**
 * KV key `trust:<ip>`: an address that recently held a valid owner session. Trusted addresses
 * are never counted or banned (wrong passwords, scanner counters, the slow scanner) and may
 * log in during a lockdown. This is what protects a household on a dynamic or carrier-grade
 * NAT address that cannot be allow-listed. Written at owner login and refreshed (throttled)
 * while an owner cookie is in use; expires after `trust_window`.
 */
const key = (ip: string) => `trust:${addressKey(ip)}`;

export async function isTrusted(env: Env, ip: string): Promise<boolean> {
  return (await env.STORE.get(key(ip))) !== null;
}

export async function markTrusted(env: Env, ip: string, seconds: number): Promise<void> {
  if (seconds <= 0) return;
  await env.STORE.put(key(ip), '1', { expirationTtl: Math.max(60, seconds) });
}

/** Refreshes trust at most once per hour per address per isolate, so steady use costs ~no writes. */
export function createTrustRefresher(now: () => number) {
  const last = new Map<string, number>();
  return (env: Env, ip: string, seconds: number, exec: ExecutionContext): void => {
    if (seconds <= 0) return;
    const t = now();
    if ((last.get(ip) ?? 0) > t - 3_600_000) return;
    last.set(ip, t);
    exec.waitUntil(markTrusted(env, ip, seconds));
  };
}
