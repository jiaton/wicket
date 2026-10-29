import type { Env } from './env';
import { underPrefix } from '../core/paths.ts';

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
  /** Origin statuses that mean "the app rejected the credential" (counted toward `limits.origin`). */
  status: number[];
}

export const PASSTHROUGH_DEFAULT_STATUS = [401];
/** Where APIs, MCP servers and app back ends live; the `api` preset is limited to these so static pages and the app's own login stay gated. */
export const API_PATHS = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '/mcp', '/sse', '/rpc', '/ws'];

/** `passthrough: api` — what most APIs, MCP servers and mobile apps send. */
export const PASSTHROUGH_PRESETS: Record<string, Passthrough> = {
  api: { headers: ['authorization', 'x-api-key', 'x-access-token'], cookies: [], params: ['token'], paths: API_PATHS, status: PASSTHROUGH_DEFAULT_STATUS },
};

/** Country rule: either an allow list (everyone else is refused) or a deny list; ISO 3166-1 alpha-2, upper-case. */
export interface Countries {
  allow?: string[];
  deny?: string[];
}

const CC = /^[A-Z]{2}$/;
const codes = (v: unknown): string[] | undefined => {
  const list = strings(v).map((s) => s.toUpperCase()).filter((s) => CC.test(s));
  return list.length ? list : undefined;
};

export function countriesOf(raw: unknown): Countries | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const allow = codes(r.allow);
  const deny = codes(r.deny);
  if (!allow && !deny) return undefined;
  return allow ? { allow } : { deny };
}

/** Is a visitor from `cc` allowed on a host with this rule? Unknown countries (`??`, `T1`) pass a deny list and fail an allow list. */
export function countryAllowed(rule: Countries | undefined, cc: string): boolean {
  if (!rule) return true;
  if (rule.allow) return rule.allow.includes(cc);
  return !(rule.deny ?? []).includes(cc);
}

/** One-line form for the settings page: `allow:US,CA` or `deny:RU,CN`; empty = no rule. */
export function parseCountriesSpec(spec: string): Countries | undefined | string {
  const s = spec.trim();
  if (!s) return undefined;
  const m = s.match(/^(allow|deny)\s*:\s*(.+)$/i);
  if (!m) return 'use allow:US,CA or deny:RU,CN';
  const list = m[2]!.split(/[,\s]+/).map((x) => x.trim().toUpperCase()).filter(Boolean);
  if (list.some((x) => !CC.test(x))) return 'country codes are two letters (ISO 3166-1)';
  return m[1]!.toLowerCase() === 'allow' ? { allow: list } : { deny: list };
}

export const formatCountriesSpec = (c: Countries | undefined): string => (!c ? '' : c.allow ? `allow:${c.allow.join(',')}` : `deny:${(c.deny ?? []).join(',')}`);

export interface HostConfig {
  mode: HostMode;
  /** Name of a built-in recipe (src/recipes) whose rules are prepended to `watch`. */
  recipe?: string;
  watch: WatchRule[];
  /** Gated hosts only: requests with the app's own credential go to the app; `recipe`/`watch` then apply to those requests. */
  passthrough?: Passthrough;
  /** Visitors from other countries get 403 before anything else (allow-listed addresses excepted). */
  countries?: Countries;
}

export type HostTable = Record<string, HostConfig>;

const GATED: HostConfig = { mode: 'gated', watch: [] };

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : []);

export function passthroughOf(raw: unknown): Passthrough | undefined {
  if (typeof raw === 'string') return Object.hasOwn(PASSTHROUGH_PRESETS, raw) ? PASSTHROUGH_PRESETS[raw] : undefined;
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const p: Passthrough = {
    headers: strings(r.headers).map((h) => h.toLowerCase()),
    cookies: strings(r.cookies),
    params: strings(r.params),
    paths: strings(r.paths),
    status: Array.isArray(r.status) && r.status.every((n) => typeof n === 'number') && r.status.length ? (r.status as number[]) : PASSTHROUGH_DEFAULT_STATUS,
  };
  return p.headers.length || p.cookies.length || p.params.length ? p : undefined;
}

/**
 * One-line form of a rule for the settings page:
 * `headers=authorization,x-session; cookies=sid; params=token; paths=/api/,/mcp; status=401,403`.
 * Every part optional; at least one of headers/cookies/params. Returns an error message or the rule.
 */
export function parsePassthroughSpec(spec: string): Passthrough | string {
  const p: Passthrough = { headers: [], cookies: [], params: [], paths: [], status: PASSTHROUGH_DEFAULT_STATUS };
  for (const part of spec.split(';').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq < 0) return `"${part}" should look like headers=a,b`;
    const key = part.slice(0, eq).trim().toLowerCase();
    const values = part.slice(eq + 1).split(',').map((s) => s.trim()).filter(Boolean);
    if (!values.length) return `"${key}" has no values`;
    switch (key) {
      case 'headers':
        p.headers = values.map((v) => v.toLowerCase());
        if (p.headers.some((h) => h === 'cookie' || h === 'host' || !/^[a-z0-9-]+$/.test(h))) return 'headers must be header names (not cookie or host)';
        break;
      case 'cookies':
        p.cookies = values;
        break;
      case 'params':
        p.params = values;
        break;
      case 'paths':
        p.paths = values;
        if (p.paths.some((x) => !x.startsWith('/'))) return 'paths must start with /';
        break;
      case 'status':
        p.status = values.map(Number);
        if (p.status.some((n) => !Number.isInteger(n) || n < 100 || n > 599)) return 'status must be HTTP status codes';
        break;
      default:
        return `unknown part "${key}" (headers, cookies, params, paths, status)`;
    }
  }
  if (!p.headers.length && !p.cookies.length && !p.params.length) return 'at least one of headers, cookies or params is needed';
  return p;
}

export function formatPassthroughSpec(p: Passthrough): string {
  const parts: string[] = [];
  if (p.headers.length) parts.push(`headers=${p.headers.join(',')}`);
  if (p.cookies.length) parts.push(`cookies=${p.cookies.join(',')}`);
  if (p.params.length) parts.push(`params=${p.params.join(',')}`);
  if (p.paths.length) parts.push(`paths=${p.paths.join(',')}`);
  if (p.status.join(',') !== PASSTHROUGH_DEFAULT_STATUS.join(',')) parts.push(`status=${p.status.join(',')}`);
  return parts.join('; ');
}

/** One host's entry from JSON. Malformed → `gated`, so a typo can only make a host stricter. */
export function hostEntryOf(raw: unknown): HostConfig {
  if (!raw || typeof raw !== 'object') return GATED;
  const r = raw as { mode?: unknown; recipe?: unknown; watch?: unknown; passthrough?: unknown; countries?: unknown };
  const mode: HostMode = isHostMode(r.mode) ? r.mode : 'gated';
  const watch: WatchRule[] = Array.isArray(r.watch)
    ? r.watch.filter(
        (w): w is WatchRule =>
          !!w && typeof w === 'object' && typeof (w as WatchRule).path === 'string' && Array.isArray((w as WatchRule).status),
      )
    : [];
  const passthrough = mode === 'gated' ? passthroughOf(r.passthrough) : undefined;
  const countries = countriesOf(r.countries);
  return { mode, recipe: typeof r.recipe === 'string' ? r.recipe : undefined, watch, ...(passthrough ? { passthrough } : {}), ...(countries ? { countries } : {}) };
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
  if (p.paths.length && !p.paths.some((prefix) => underPrefix(url.pathname, prefix))) return false;
  if (p.headers.some((h) => req.headers.has(h))) return true;
  if (p.params.some((name) => url.searchParams.has(name))) return true;
  if (p.cookies.length) {
    const names = (req.headers.get('cookie') ?? '').split(';').map((part) => part.trim().split('=')[0] ?? '');
    if (p.cookies.some((c) => names.includes(c))) return true;
  }
  return false;
}
