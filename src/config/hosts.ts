import type { Env } from './env';

/** A watch rule: the origin's answer to a matching request counts as a login failure. */
export interface WatchRule {
  /** Path prefix, e.g. "/api/auth/login". */
  path: string;
  /** HTTP methods; absent = any. */
  methods?: string[];
  /** Origin status codes that mean "failed", e.g. [401]. */
  status: number[];
}

export type HostMode = 'gated' | 'observe';

export interface HostConfig {
  mode: HostMode;
  /** Name of a built-in recipe (src/recipes) whose rules are prepended to `watch`. */
  recipe?: string;
  watch: WatchRule[];
}

const GATED: HostConfig = { mode: 'gated', watch: [] };

/**
 * Per-host configuration from HOSTS_JSON: `{"host": {"mode": "gated"|"observe", "recipe"?, "watch"?}}`.
 * Unknown or malformed hosts fall back to `gated`, so a typo can only make a host stricter.
 */
export function hostConfig(env: Env, hostname: string): HostConfig {
  if (!env.HOSTS_JSON) return GATED;
  let all: Record<string, unknown>;
  try {
    all = JSON.parse(env.HOSTS_JSON) as Record<string, unknown>;
  } catch {
    return GATED;
  }
  const raw = all[hostname];
  if (!raw || typeof raw !== 'object') return GATED;
  const r = raw as { mode?: unknown; recipe?: unknown; watch?: unknown };
  const mode: HostMode = r.mode === 'observe' ? 'observe' : 'gated';
  const watch: WatchRule[] = Array.isArray(r.watch)
    ? r.watch.filter(
        (w): w is WatchRule =>
          !!w && typeof w === 'object' && typeof (w as WatchRule).path === 'string' && Array.isArray((w as WatchRule).status),
      )
    : [];
  return { mode, recipe: typeof r.recipe === 'string' ? r.recipe : undefined, watch };
}

export function watchMatches(rules: WatchRule[], method: string, pathname: string, status: number): boolean {
  return rules.some(
    (w) => pathname.startsWith(w.path) && (!w.methods || w.methods.includes(method)) && w.status.includes(status),
  );
}
