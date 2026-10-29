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

/**
 * gated    password page unless a cookie, token or pass-through credential is present
 * observe  forwarded; the app's own login is watched and scanners are banned
 * open     forwarded untouched (bans still apply); for a host that only wants analytics
 * off      a maintenance page, nothing forwarded
 */
export type HostMode = 'gated' | 'observe' | 'open' | 'off';
export const HOST_MODES: HostMode[] = ['gated', 'observe', 'open', 'off'];
export const isHostMode = (v: unknown): v is HostMode => typeof v === 'string' && (HOST_MODES as string[]).includes(v);

/**
 * Carriers of the app's own credential. A request carrying one skips the password page and
 * reaches the app, which validates it itself; wicket keeps no copy. The app's 401 answers
 * count as failed logins for the address (`limits.origin`), so brute force is still banned.
 */
export interface Passthrough {
  /** Header names, lower-case (e.g. `authorization`, `x-api-key`). */
  headers: string[];
  /** Cookie names (an app session cookie). */
  cookies: string[];
  /** Query parameter names (e.g. `token`). */
  params: string[];
  /** Path prefixes the rule is limited to; empty = any path. */
  paths: string[];
}

/** `passthrough: api` — what most APIs, MCP servers and mobile apps send. */
export const PASSTHROUGH_PRESETS: Record<string, Passthrough> = {
  api: { headers: ['authorization', 'x-api-key', 'x-access-token'], cookies: [], params: ['token'], paths: [] },
};

export interface HostConfig {
  mode: HostMode;
  /** Name of a built-in recipe (src/recipes) whose rules are prepended to `watch`. */
  recipe?: string;
  watch: WatchRule[];
  /** Gated hosts only: requests with the app's own credential go to the app. */
  passthrough?: Passthrough;
}

export type HostTable = Record<string, HostConfig>;

const GATED: HostConfig = { mode: 'gated', watch: [] };

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : []);

export function passthroughOf(raw: unknown): Passthrough | undefined {
  if (typeof raw === 'string') return PASSTHROUGH_PRESETS[raw];
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const p: Passthrough = {
    headers: strings(r.headers).map((h) => h.toLowerCase()),
    cookies: strings(r.cookies),
    params: strings(r.params),
    paths: strings(r.paths),
  };
  return p.headers.length || p.cookies.length || p.params.length ? p : undefined;
}

/** One host's entry from JSON. Malformed → `gated`, so a typo can only make a host stricter. */
export function hostEntryOf(raw: unknown): HostConfig {
  if (!raw || typeof raw !== 'object') return GATED;
  const r = raw as { mode?: unknown; recipe?: unknown; watch?: unknown; passthrough?: unknown };
  const mode: HostMode = isHostMode(r.mode) ? r.mode : 'gated';
  const watch: WatchRule[] = Array.isArray(r.watch)
    ? r.watch.filter(
        (w): w is WatchRule =>
          !!w && typeof w === 'object' && typeof (w as WatchRule).path === 'string' && Array.isArray((w as WatchRule).status),
      )
    : [];
  const passthrough = mode === 'gated' ? passthroughOf(r.passthrough) : undefined;
  return { mode, recipe: typeof r.recipe === 'string' ? r.recipe : undefined, watch, ...(passthrough ? { passthrough } : {}) };
}

/** `{"host": {...}}` → table; anything unparseable → empty table. */
export function hostTableOf(raw: unknown): HostTable {
  let all: unknown = raw;
  if (typeof raw === 'string') {
    try {
      all = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!all || typeof all !== 'object') return {};
  const out: HostTable = {};
  for (const [host, v] of Object.entries(all as Record<string, unknown>)) out[host.toLowerCase()] = hostEntryOf(v);
  return out;
}

/** Mode for hosts that are routed but not configured (`default_mode`; `gated` unless the config says otherwise). */
export const defaultMode = (env: Env): HostMode => (isHostMode(env.DEFAULT_MODE) ? env.DEFAULT_MODE : 'gated');

export const hostFor = (table: HostTable, hostname: string, fallback: HostMode = 'gated'): HostConfig =>
  table[hostname] ?? (fallback === 'gated' ? GATED : { mode: fallback, watch: [] });

/** Per-host configuration from HOSTS_JSON alone (the deploy-time table; the runtime layer may override it). */
export function hostConfig(env: Env, hostname: string): HostConfig {
  return hostFor(hostTableOf(env.HOSTS_JSON), hostname, defaultMode(env));
}

export function watchMatches(rules: WatchRule[], method: string, pathname: string, status: number): boolean {
  return rules.some(
    (w) => pathname.startsWith(w.path) && (!w.methods || w.methods.includes(method)) && w.status.includes(status),
  );
}

/** Does the request carry one of the app's own credentials, on a path the rule covers? */
export function carriesAppCredential(p: Passthrough, req: Request, url: URL): boolean {
  if (p.paths.length && !p.paths.some((prefix) => url.pathname.startsWith(prefix))) return false;
  if (p.headers.some((h) => req.headers.has(h))) return true;
  if (p.params.some((name) => url.searchParams.has(name))) return true;
  if (p.cookies.length) {
    const names = (req.headers.get('cookie') ?? '').split(';').map((part) => part.trim().split('=')[0] ?? '');
    if (p.cookies.some((c) => names.includes(c))) return true;
  }
  return false;
}
