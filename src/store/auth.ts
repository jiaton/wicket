import type { Env } from '../config/env';

/**
 * Credentials set on the setup or settings page instead of in the secrets:
 *   settings:auth        { owner, friend?, cookieSecret, at } — password hashes (core/password.ts) and the cookie secret
 *   settings:cloudflare  { token, accountId } — the API token given on the page (CF_API_TOKEN in the secrets wins)
 * Secrets uploaded with the deploy always take precedence; these exist so a deploy with
 * no secrets at all can be finished in the browser.
 */
const AUTH_KEY = 'settings:auth';
const CF_KEY = 'settings:cloudflare';

export interface StoredAuth {
  /** `pbkdf2$…` hash of the owner password. */
  owner: string;
  friend?: string;
  cookieSecret: string;
  /** When it was set (ms). */
  at: number;
}

export interface StoredCloudflare {
  token: string;
  accountId: string;
}

async function readJson<T>(env: Env, key: string, check: (v: unknown) => v is T): Promise<T | null> {
  const raw = await env.STORE.get(key);
  if (!raw) return null;
  try {
    const v: unknown = JSON.parse(raw);
    return check(v) ? v : null;
  } catch {
    return null;
  }
}

const isAuth = (v: unknown): v is StoredAuth =>
  !!v && typeof v === 'object' && typeof (v as StoredAuth).owner === 'string' && typeof (v as StoredAuth).cookieSecret === 'string';
const isCloudflare = (v: unknown): v is StoredCloudflare =>
  !!v && typeof v === 'object' && typeof (v as StoredCloudflare).token === 'string' && typeof (v as StoredCloudflare).accountId === 'string';

export const readAuth = (env: Env) => readJson(env, AUTH_KEY, isAuth);
export const writeAuth = (env: Env, auth: StoredAuth): Promise<void> => env.STORE.put(AUTH_KEY, JSON.stringify(auth));
export const readCloudflareCreds = (env: Env) => readJson(env, CF_KEY, isCloudflare);
export const writeCloudflareCreds = (env: Env, creds: StoredCloudflare): Promise<void> => env.STORE.put(CF_KEY, JSON.stringify(creds));
export const clearCloudflareCreds = (env: Env): Promise<void> => env.STORE.delete(CF_KEY);
