import type { Env } from '../config/env';
import { defaultMode, hostFor, hostTableOf, type HostConfig, type HostTable } from '../config/hosts';
import { applyHostOverrides, applyOverrides, runtimeOverridesOf, type RuntimeOverrides } from '../config/runtime';
import { settings, type Settings } from '../config/settings';
import { readRuntimeSettings } from '../store/settings';

/**
 * The effective configuration: deploy-time vars (wicket.yaml) with the owner's runtime
 * changes from KV on top. One KV read, cached per isolate for a short while, so a request
 * costs nothing extra in the steady state and a change on the settings page is live
 * everywhere within `CACHE_MS`.
 */
export interface Runtime {
  settings: Settings;
  hosts: HostTable;
  overrides: RuntimeOverrides;
  /** True when KV holds any runtime overrides. */
  overridden: boolean;
}

export const CACHE_MS = 30_000;

export async function resolveRuntime(env: Env): Promise<Runtime> {
  const raw = await readRuntimeSettings(env);
  const overrides = runtimeOverridesOf(raw);
  return {
    settings: applyOverrides(settings(env), overrides),
    hosts: applyHostOverrides(hostTableOf(env.HOSTS_JSON), overrides),
    overrides,
    overridden: raw !== null,
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
