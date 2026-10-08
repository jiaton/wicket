import type { Env } from '../config/env';

/**
 * Everything wicket keeps in KV, in one place. Keys:
 *   ban:<ip>    permanent ban (JSON record)          fail:<ip>   wrong passwords/tokens (TTL window)
 *   ofail:<ip>  origin login failures (TTL window)   gfail       global failure counter (TTL window)
 *   lockdown    password entry paused (TTL)          alert:<k>   cron alert dedup (1 h)
 *   nq:<i>      queued notifications per channel
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

export async function writeBan(env: Env, ip: string, record: BanRecord): Promise<void> {
  // `kind` also goes into KV metadata so a key listing can count bans without reading each record.
  await env.STORE.put(banKey(ip), JSON.stringify(record), { metadata: { kind: record.kind } });
}

export interface BanSummary {
  ip: string;
  /** From KV metadata; records written before metadata existed have none. */
  kind?: BanKind;
}

/** Every banned address in KV (the reconcile cron compares this with the Cloudflare IP list). */
export async function listBans(env: Env): Promise<BanSummary[]> {
  const bans: BanSummary[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.STORE.list<{ kind?: BanKind }>({ prefix: 'ban:', cursor });
    for (const key of page.keys) bans.push({ ip: key.name.slice('ban:'.length), ...(key.metadata?.kind ? { kind: key.metadata.kind } : {}) });
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return bans;
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

export async function liftLockdown(env: Env): Promise<void> {
  await Promise.all([env.STORE.delete(LOCKDOWN_KEY), env.STORE.delete(GLOBAL_FAIL_KEY)]);
}
