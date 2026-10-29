import type { Env } from '../config/env';
import { defaultMode, hostFor, hostTableOf, type HostConfig, type HostTable } from '../config/hosts';
import { applyHostOverrides, applyOverrides, runtimeOverridesOf, type RuntimeOverrides } from '../config/runtime';
import { settings, type Settings } from '../config/settings';
import { readAuth, readCloudflareCreds } from '../store/auth';
import { readRuntimeSettings } from '../store/settings';

/**
 * The effective configuration: deploy-time vars (wicket.yaml) and secrets, with what the
 * owner set in the browser layered on top: runtime overrides (hosts / access / limits /
 * cloudflare ids), passwords from the setup page, a Cloudflare token given on the page.
 * Three KV reads, cached per isolate for a short while, so a request costs nothing extra
 * in the steady state and a change on the settings page is live everywhere within `CACHE_MS`.
 */
export interface Auth {
  /** HMAC material per role: the plain password from the secrets, or its KV hash. Null = that role cannot log in. */
  owner: string | null;
  friend: string | null;
  /** How the owner password is checked: constant-time compare (secrets) or PBKDF2 (setup page). */
  kind: 'plain' | 'hash' | 'none';
  cookieSecret: string;
  /** True while no owner password exists anywhere and the setup page may claim it. */
  setupOpen: boolean;
}

export interface Runtime {
  /** Env with KV-stored credentials merged in where the secrets are absent. */
  env: Env;
  settings: Settings;
  hosts: HostTable;
  overrides: RuntimeOverrides;
  auth: Auth;
  /** True when KV holds any runtime overrides. */
  overridden: boolean;
}

export const CACHE_MS = 30_000;

export async function resolveRuntime(raw: Env): Promise<Runtime> {
  const [rawOverrides, stored, creds] = await Promise.all([readRuntimeSettings(raw), readAuth(raw), readCloudflareCreds(raw)]);
  const env: Env = {
    ...raw,
    ...(!raw.CF_API_TOKEN && creds ? { CF_API_TOKEN: creds.token, CF_ACCOUNT_ID: raw.CF_ACCOUNT_ID || creds.accountId } : {}),
    ...(!raw.COOKIE_SECRET && stored ? { COOKIE_SECRET: stored.cookieSecret } : {}),
  };
  const secrets = Boolean(raw.OWNER_PASSWORD && raw.COOKIE_SECRET);
  const auth: Auth = secrets
    ? { owner: raw.OWNER_PASSWORD, friend: raw.FRIEND_PASSWORD || null, kind: 'plain', cookieSecret: raw.COOKIE_SECRET, setupOpen: false }
    : stored
      ? { owner: stored.owner, friend: stored.friend ?? null, kind: 'hash', cookieSecret: stored.cookieSecret, setupOpen: false }
      : { owner: null, friend: null, kind: 'none', cookieSecret: '', setupOpen: raw.SETUP_ENABLED !== '0' && Boolean(raw.SETUP_TOKEN) };
  const overrides = runtimeOverridesOf(rawOverrides);
  return {
    env,
    settings: applyOverrides(settings(env), overrides),
    hosts: applyHostOverrides(hostTableOf(env.HOSTS_JSON), overrides),
    overrides,
    auth,
    overridden: rawOverrides !== null,
  };
}

export const hostOf = (env: Env, rt: Runtime, hostname: string): HostConfig => hostFor(rt.hosts, hostname, defaultMode(env));

/** Per-isolate cache around `resolveRuntime`; `invalidate()` after a save on the same isolate. */
export function createRuntimeCache(now: () => number) {
  let cached: { at: number; value: Promise<Runtime> } | null = null;
  const get = (env: Env): Promise<Runtime> => {
    const t = now();
    if (!cached || t - cached.at > CACHE_MS) {
      const value = resolveRuntime(env);
      cached = { at: t, value };
      value.catch(() => {
        cached = null;
      });
    }
    return cached.value;
  };
  const invalidate = () => {
    cached = null;
  };
  return { get, invalidate };
}
