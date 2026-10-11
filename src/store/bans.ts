import type { Env } from '../config/env';

/**
 * Everything wicket keeps in KV, in one place. Keys:
 *   ban:<ip>    permanent ban (JSON record)          fail:<ip>   wrong passwords/tokens (TTL window)
 *   ofail:<ip>  origin login failures (TTL window)   gfail       global failure counter (TTL window)
 *   lockdown    password entry paused (TTL)          alert:<k>   cron alert dedup (1 h)
 *   nq:<i>      queued notifications per channel     edgeq       bans whose IP-list call failed
 */
export type BanKind = 'password' | 'token' | 'scan' | 'origin';

export interface BanRecord {
  at: number;
  host: string;
  country: string;
  kind: BanKind;
}

export const LOCKDOWN_IP = '*';
const banKey = (ip: string) => `ban:${ip}`;
const failKey = (ip: string) => `fail:${ip}`;
const originFailKey = (ip: string) => `ofail:${ip}`;
const GLOBAL_FAIL_KEY = 'gfail';
const LOCKDOWN_KEY = 'lockdown';

export async function isBanned(env: Env, ip: string): Promise<boolean> {
  return (await env.STORE.get(banKey(ip))) !== null;
}

/** What a key listing can see without reading the record (KV metadata, ≤1 KB). */
export interface BanMeta {
  kind: BanKind;
  at: number;
  host: string;
  country: string;
}

export async function writeBan(env: Env, ip: string, record: BanRecord): Promise<void> {
  // The summary also goes into KV metadata so listings can sort, count and page without reading records.
  const metadata: BanMeta = { kind: record.kind, at: record.at, host: record.host.slice(0, 120), country: record.country };
  await env.STORE.put(banKey(ip), JSON.stringify(record), { metadata });
}

export interface BanSummary extends Partial<BanMeta> {
  ip: string;
}

/** Every banned address in KV (the reconcile cron compares this with the Cloudflare IP list). */
export async function listBans(env: Env): Promise<BanSummary[]> {
  const bans: BanSummary[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.STORE.list<Partial<BanMeta>>({ prefix: 'ban:', cursor });
    for (const key of page.keys) bans.push({ ip: key.name.slice('ban:'.length), ...(key.metadata ?? {}) });
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return bans;
}

export async function readBan(env: Env, ip: string): Promise<BanRecord | null> {
  const raw = await env.STORE.get(banKey(ip));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as BanRecord;
  } catch {
    return null;
  }
}

/**
 * Bans written before the summary went into KV metadata (2026-10) lack it; rewrite up to
 * `max` of them per call so listings can sort and count. Returns how many were rewritten.
 */
export async function backfillBanMetadata(env: Env, max = 100): Promise<number> {
  let n = 0;
  for (const b of await listBans(env)) {
    if (b.at !== undefined || n >= max) continue;
    const record = await readBan(env, b.ip);
    if (!record) continue;
    await writeBan(env, b.ip, record);
    n += 1;
  }
  return n;
}

export async function clearBan(env: Env, ip: string): Promise<void> {
  await Promise.all([env.STORE.delete(banKey(ip)), env.STORE.delete(failKey(ip)), env.STORE.delete(originFailKey(ip))]);
}

/** Increments a windowed counter; returns the new count. */
async function bump(env: Env, key: string, windowSeconds: number): Promise<number> {
  const n = Number((await env.STORE.get(key)) ?? '0') + 1;
  await env.STORE.put(key, String(n), { expirationTtl: windowSeconds });
  return n;
}

export const bumpFailures = (env: Env, ip: string, windowSeconds: number) => bump(env, failKey(ip), windowSeconds);
/** Wrong passwords/tokens counted so far for an address (0 when none or expired). */
export const failureCount = async (env: Env, ip: string): Promise<number> => Number((await env.STORE.get(failKey(ip))) ?? '0');
export const clearFailures = (env: Env, ip: string) => env.STORE.delete(failKey(ip));
export const bumpOriginFailures = (env: Env, ip: string, windowSeconds: number) => bump(env, originFailKey(ip), windowSeconds);
export const clearOriginFailures = (env: Env, ip: string) => env.STORE.delete(originFailKey(ip));

export async function isLockedDown(env: Env): Promise<boolean> {
  return (await env.STORE.get(LOCKDOWN_KEY)) !== null;
}

export interface GlobalFailures {
  n: number;
  since: number;
}

/** Address-independent failure counter (rotating-IP guessing). Returns the updated state. */
export async function bumpGlobalFailures(env: Env, now: number, windowSeconds: number): Promise<GlobalFailures> {
  const raw = await env.STORE.get(GLOBAL_FAIL_KEY);
  const state: GlobalFailures = raw ? (JSON.parse(raw) as GlobalFailures) : { n: 0, since: now };
  state.n += 1;
  await env.STORE.put(GLOBAL_FAIL_KEY, JSON.stringify(state), { expirationTtl: windowSeconds });
  return state;
}

export async function startLockdown(env: Env, record: { at: number; host: string; fails: number }, seconds: number): Promise<void> {
  await env.STORE.put(LOCKDOWN_KEY, JSON.stringify(record), { expirationTtl: seconds });
  await env.STORE.delete(GLOBAL_FAIL_KEY);
}

export interface LockdownRecord {
  at: number;
  host: string;
  fails: number;
}

export async function readLockdown(env: Env): Promise<LockdownRecord | null> {
  const raw = await env.STORE.get(LOCKDOWN_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as LockdownRecord;
  } catch {
    return null;
  }
}

export async function liftLockdown(env: Env): Promise<void> {
  await Promise.all([env.STORE.delete(LOCKDOWN_KEY), env.STORE.delete(GLOBAL_FAIL_KEY)]);
}

const EDGE_PENDING_KEY = 'edgeq';

/** Remembers a banned address whose IP-list call failed, for the five-minute job to retry. */
export async function addPendingEdge(env: Env, ip: string): Promise<void> {
  const pending = new Set(await readPendingEdge(env));
  pending.add(ip);
  await env.STORE.put(EDGE_PENDING_KEY, JSON.stringify([...pending]), { expirationTtl: 86_400 });
}

export async function readPendingEdge(env: Env): Promise<string[]> {
  const raw = await env.STORE.get(EDGE_PENDING_KEY);
  if (!raw) return [];
  try {
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

export const clearPendingEdge = (env: Env) => env.STORE.delete(EDGE_PENDING_KEY);
