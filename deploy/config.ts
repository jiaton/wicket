/**
 * Build-time loader for `wicket.yaml`, the one file a user edits.
 *
 * Workers have no filesystem, so the YAML is compiled when the config is evaluated:
 * `cloudflare.config.ts` (cf CLI) and `deploy/wrangler.ts` (wrangler) both call
 * `loadConfig()` and then `toVars()` / `toRoutes()`. This module runs in Node, never in
 * the Worker, so it may use `node:fs`; nothing under `src/` may import it.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';

import { HOST_MODES, isHostMode, PASSTHROUGH_DEFAULT_STATUS, PASSTHROUGH_PRESETS, type HostMode, type Passthrough, type WatchRule } from '../src/config/hosts.ts';
import { DEFAULT_POLICY, isDelivery, isPolicyKind, type NotifyPolicy } from '../src/config/notifications.ts';

export const DEFAULT_FILE = 'wicket.yaml';
export const EXAMPLE_FILE = 'wicket.example.yaml';
/** Separate from the alert tick so the Worker can tell the two apart (`controller.cron`). */
export const DEFAULT_RECONCILE_CRON = '17 * * * *';

export interface HostEntry {
  mode: HostMode;
  recipe?: string;
  watch?: WatchRule[];
  /** Gated hosts: carriers of the app's own credential that skip the password page. */
  passthrough?: Passthrough;
}

export interface Limit {
  count: number;
  /** seconds */
  window: number;
}

export interface WicketConfig {
  zone: string;
  worker: string;
  siteName: string;
  cookieDomain: string;
  cookieDays: number;
  hosts: Record<string, HostEntry>;
  /** `explicit`: one Workers route per listed host. `wildcard`: one route `*.zone/*`, unlisted hosts get `defaultMode`. */
  routes: 'explicit' | 'wildcard';
  defaultMode: HostMode;
  allowIps: string[];
  allowDns: string[];
  /** Seconds an address stays trusted after an owner login (0 = off). */
  trustWindow: number;
  bypass: string[];
  limits: {
    password: Limit;
    rotating: Limit & { lockdown: number };
    scanner: Limit;
    /** Slow scanner ban from the analysis; the window is the analysis window (5 min). */
    scanning: { count: number };
    /** Known scanner paths/agents from one address before a ban; count 0 disables. */
    signatures: Limit;
    origin: Limit;
  };
  alerts: {
    adminHosts: string[];
    quietHours: string;
    timezone: string;
    ipRequests: number;
    ipErrors: number;
    guessIps: number;
  };
  /** Extra scanner signatures (regular expression sources). */
  signatures: { paths: string[]; agents: string[] };
  cloudflare: {
    kvNamespaceId: string;
    analyticsDataset: string;
    cron: string;
    reconcileCron: string;
  };
  notifications: NotifyPolicy;
}

export class ConfigError extends Error {}

type Raw = Record<string, unknown>;

function fail(msg: string): never {
  throw new ConfigError(`wicket.yaml: ${msg}`);
}

const isObject = (v: unknown): v is Raw => !!v && typeof v === 'object' && !Array.isArray(v);

const str = (v: unknown, name: string, fallback?: string): string => {
  if (v === undefined || v === null) return fallback ?? fail(`${name} is required`);
  if (typeof v !== 'string' || !v.trim()) fail(`${name} must be a non-empty string`);
  return (v as string).trim();
};

/** Optional string that may be empty. */
const strOpt = (v: unknown, name: string, fallback: string): string => {
  if (v === undefined || v === null) return fallback;
  if (typeof v !== 'string') fail(`${name} must be a string`);
  return (v as string).trim();
};

const num = (v: unknown, name: string, fallback: number): number => {
  if (v === undefined || v === null) return fallback;
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) fail(`${name} must be a positive integer`);
  return v as number;
};

const strings = (v: unknown, name: string): string[] => {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) fail(`${name} must be a list of strings`);
  return (v as string[]).map((s) => s.trim()).filter(Boolean);
};

const UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86_400 };

/** `90`, `"90s"`, `"10m"`, `"24h"`, `"7d"` → seconds. */
export function duration(v: unknown, name: string, fallback: number): number {
  if (v === undefined || v === null) return fallback;
  if (typeof v === 'number') return num(v, name, fallback);
  const m = typeof v === 'string' ? v.trim().match(/^(\d+)\s*([smhd])?$/) : null;
  if (!m) fail(`${name} must be seconds or a duration like 10m, 24h, 7d`);
  return Number(m![1]) * UNITS[m![2] ?? 's']!;
}

const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/** Like `limit`, but `count: 0` is allowed and means off. */
function signatureLimit(v: unknown): Limit {
  const defaults: Limit = { count: 3, window: 600 };
  if (v === undefined || v === null) return defaults;
  if (!isObject(v)) fail('limits.signatures must be a mapping');
  const r = v as Raw;
  const count = r.count === 0 ? 0 : num(r.count, 'limits.signatures.count', defaults.count);
  return { count, window: duration(r.window, 'limits.signatures.window', defaults.window) };
}

function limit(v: unknown, name: string, defaults: Limit): Limit {
  if (v === undefined || v === null) return defaults;
  if (!isObject(v)) fail(`limits.${name} must be a mapping`);
  const r = v as Raw;
  return { count: num(r.count, `limits.${name}.count`, defaults.count), window: duration(r.window, `limits.${name}.window`, defaults.window) };
}

function watchRules(v: unknown, host: string): WatchRule[] | undefined {
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v)) fail(`hosts.${host}.watch must be a list`);
  return v.map((w, i) => {
    if (!isObject(w)) fail(`hosts.${host}.watch[${i}] must be a mapping`);
    const r = w as Raw;
    const path = str(r.path, `hosts.${host}.watch[${i}].path`);
    if (!path.startsWith('/')) fail(`hosts.${host}.watch[${i}].path must start with /`);
    const status = r.status;
    if (!Array.isArray(status) || !status.length || status.some((s) => typeof s !== 'number')) {
      fail(`hosts.${host}.watch[${i}].status must be a list of status codes`);
    }
    const methods = r.methods === undefined ? undefined : strings(r.methods, `hosts.${host}.watch[${i}].methods`).map((m) => m.toUpperCase());
    return { path, status: status as number[], ...(methods ? { methods } : {}) };
  });
}

function hostEntry(v: unknown, host: string, zone: string, recipes: ReadonlySet<string> | null): HostEntry {
  if (!HOSTNAME.test(host)) fail(`hosts: "${host}" is not a valid hostname`);
  if (host !== zone && !host.endsWith(`.${zone}`)) fail(`hosts: "${host}" is not inside zone "${zone}"`);
  const r: Raw = typeof v === 'string' ? { mode: v } : v === null ? {} : isObject(v) ? v : fail(`hosts.${host} must be "gated", "observe" or a mapping`);
  const mode = r.mode ?? 'gated';
  if (!isHostMode(mode)) fail(`hosts.${host}.mode must be one of ${HOST_MODES.join(', ')}`);
  const recipe = r.recipe === undefined ? undefined : str(r.recipe, `hosts.${host}.recipe`);
  if (recipe && recipes && !recipes.has(recipe)) fail(`hosts.${host}.recipe: unknown recipe "${recipe}" (known: ${[...recipes].join(', ')})`);
  if (mode !== 'gated' && r.passthrough !== undefined) fail(`hosts.${host}: passthrough only applies to mode: gated (other modes already forward everything or nothing)`);
  const passthrough = passthroughRule(r.passthrough, host);
  if (mode !== 'observe' && !passthrough && (recipe || r.watch !== undefined)) fail(`hosts.${host}: recipe/watch apply to mode: observe or to a gated host with passthrough`);
  const watch = watchRules(r.watch, host);
  return { mode, ...(recipe ? { recipe } : {}), ...(watch?.length ? { watch } : {}), ...(passthrough ? { passthrough } : {}) };
}

/** `passthrough: api` (a preset) or a mapping of headers / cookies / params / paths. */
function passthroughRule(v: unknown, host: string): Passthrough | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') {
    const preset = PASSTHROUGH_PRESETS[v];
    if (!preset) fail(`hosts.${host}.passthrough: unknown preset "${v}" (known: ${Object.keys(PASSTHROUGH_PRESETS).join(', ')}), or give a mapping`);
    return preset;
  }
  if (!isObject(v)) fail(`hosts.${host}.passthrough must be a preset name or a mapping`);
  const r = v as Raw;
  const p: Passthrough = {
    headers: r.headers === undefined ? [] : strings(r.headers, `hosts.${host}.passthrough.headers`).map((h) => h.toLowerCase()),
    cookies: r.cookies === undefined ? [] : strings(r.cookies, `hosts.${host}.passthrough.cookies`),
    params: r.params === undefined ? [] : strings(r.params, `hosts.${host}.passthrough.params`),
    paths: r.paths === undefined ? [] : strings(r.paths, `hosts.${host}.passthrough.paths`),
    status: r.status === undefined ? PASSTHROUGH_DEFAULT_STATUS : (r.status as number[]),
  };
  if (!Array.isArray(p.status) || !p.status.length || p.status.some((n) => typeof n !== 'number')) fail(`hosts.${host}.passthrough.status must be a list of status codes`);
  for (const h of p.headers) if (h === 'cookie' || h === 'host') fail(`hosts.${host}.passthrough.headers: "${h}" cannot be a credential carrier`);
  for (const path of p.paths) if (!path.startsWith('/')) fail(`hosts.${host}.passthrough.paths: "${path}" must start with /`);
  if (!p.headers.length && !p.cookies.length && !p.params.length) fail(`hosts.${host}.passthrough needs at least one of headers, cookies, params`);
  return p;
}

/** Validates the parsed YAML document. `recipes` = known recipe names, or null to skip that check. */
export function parseConfig(doc: unknown, recipes: ReadonlySet<string> | null = null): WicketConfig {
  if (!isObject(doc)) fail('top level must be a mapping');
  const zone = str(doc.zone, 'zone').toLowerCase();
  if (!HOSTNAME.test(zone)) fail(`zone "${zone}" is not a valid domain`);

  const routes = str(doc.routes, 'routes', 'explicit');
  if (routes !== 'explicit' && routes !== 'wildcard') fail('routes must be "explicit" (one route per host) or "wildcard" (*.zone/*)');
  const defaultMode = str(doc.default_mode, 'default_mode', 'gated');
  if (!isHostMode(defaultMode)) fail(`default_mode must be one of ${HOST_MODES.join(', ')}`);
  const hostsDoc = doc.hosts === undefined || doc.hosts === null ? {} : doc.hosts;
  if (!isObject(hostsDoc)) fail('hosts must be a mapping of hostnames');
  if (!Object.keys(hostsDoc).length && routes !== 'wildcard') fail('hosts must list at least one hostname (or set routes: wildcard)');
  const hosts: Record<string, HostEntry> = {};
  for (const [host, v] of Object.entries(hostsDoc)) hosts[host.toLowerCase()] = hostEntry(v, host.toLowerCase(), zone, recipes);

  const limits = isObject(doc.limits) ? doc.limits : {};
  const rotating = isObject(limits.rotating) ? limits.rotating : {};
  const alerts = isObject(doc.alerts) ? doc.alerts : {};
  const cf = isObject(doc.cloudflare) ? doc.cloudflare : {};
  const notifications = notifyPolicy(doc.notifications);
  const sigs = isObject(doc.signatures) ? doc.signatures : {};
  const signatures = { paths: strings(sigs.paths, 'signatures.paths'), agents: strings(sigs.agents, 'signatures.agents') };
  for (const re of [...signatures.paths, ...signatures.agents]) {
    try {
      new RegExp(re);
    } catch {
      fail(`signatures: "${re}" is not a valid regular expression`);
    }
  }

  const quiet = strOpt(alerts.quiet_hours, 'alerts.quiet_hours', '');
  if (quiet && !/^\d{1,2}-\d{1,2}$/.test(quiet)) fail('alerts.quiet_hours must look like "1-6" (local hours, inclusive)');

  const bypass = strings(doc.bypass, 'bypass');
  for (const b of bypass) {
    const host = b.split('/')[0]!;
    if (!hosts[host]) fail(`bypass: "${b}" names a host that is not under hosts`);
  }
  const adminHosts = strings(alerts.admin_hosts, 'alerts.admin_hosts');
  for (const h of adminHosts) if (!hosts[h]) fail(`alerts.admin_hosts: "${h}" is not under hosts`);

  return {
    zone,
    worker: str(doc.worker, 'worker', 'wicket'),
    siteName: str(doc.site_name, 'site_name', zone),
    cookieDomain: strOpt(doc.cookie_domain, 'cookie_domain', zone),
    cookieDays: num(doc.cookie_days, 'cookie_days', 365),
    hosts,
    routes,
    defaultMode,
    allowIps: strings(doc.allow_ips, 'allow_ips'),
    allowDns: strings(doc.allow_dns, 'allow_dns').map((n) => {
      const name = n.toLowerCase();
      if (!HOSTNAME.test(name)) fail(`allow_dns: "${n}" is not a valid hostname`);
      return name;
    }),
    trustWindow: doc.trust_window === 0 ? 0 : duration(doc.trust_window, 'trust_window', 86_400),
    bypass,
    limits: {
      password: limit(limits.password, 'password', { count: 3, window: 86_400 }),
      rotating: { ...limit(rotating, 'rotating', { count: 10, window: 600 }), lockdown: duration(rotating.lockdown, 'limits.rotating.lockdown', 3600) },
      scanner: limit(limits.scanner, 'scanner', { count: 100, window: 60 }),
      scanning: { count: num(isObject(limits.scanning) ? limits.scanning.count : limits.scanning, 'limits.scanning.count', 30) },
      signatures: signatureLimit(limits.signatures),
      origin: limit(limits.origin, 'origin', { count: 5, window: 600 }),
    },
    alerts: {
      adminHosts,
      quietHours: quiet,
      timezone: str(alerts.timezone, 'alerts.timezone', 'UTC'),
      ipRequests: num(alerts.ip_requests, 'alerts.ip_requests', 300),
      ipErrors: num(alerts.ip_errors, 'alerts.ip_errors', 30),
      guessIps: num(alerts.guess_ips, 'alerts.guess_ips', 3),
    },
    cloudflare: {
      kvNamespaceId: strOpt(cf.kv_namespace_id, 'cloudflare.kv_namespace_id', ''),
      analyticsDataset: str(cf.analytics_dataset, 'cloudflare.analytics_dataset', 'wicket_traffic'),
      cron: str(cf.cron, 'cloudflare.cron', '*/5 * * * *'),
      reconcileCron: str(cf.reconcile_cron, 'cloudflare.reconcile_cron', DEFAULT_RECONCILE_CRON),
    },
    notifications,
    signatures,
  };
}

/** `notifications:` → per-kind delivery (immediate | digest | off) and the digest window. */
function notifyPolicy(v: unknown): NotifyPolicy {
  if (v === undefined || v === null) return DEFAULT_POLICY;
  if (!isObject(v)) fail('notifications must be a mapping');
  const r = v as Raw;
  const kinds = { ...DEFAULT_POLICY.kinds };
  for (const [k, d] of Object.entries(r)) {
    if (k === 'digest_every') continue;
    if (!isPolicyKind(k)) fail(`notifications.${k}: unknown kind (known: ${Object.keys(kinds).join(', ')}, digest_every)`);
    if (!isDelivery(d)) fail(`notifications.${k} must be immediate, digest or off`);
    kinds[k] = d;
  }
  const digestSeconds = duration(r.digest_every, 'notifications.digest_every', DEFAULT_POLICY.digestSeconds);
  if (digestSeconds < 300 || digestSeconds > 86_400) fail('notifications.digest_every must be between 5m and 24h');
  return { kinds, digestSeconds };
}

/**
 * Which file to read: `$WICKET_CONFIG`, else `./wicket.yaml`, else the shipped example
 * (so `npm run check` and CI work on a fresh clone; a deploy with the example would
 * fail at Cloudflare anyway because `example.com` is not your zone).
 */
export function configPath(cwd = process.cwd()): string {
  const fromEnv = process.env.WICKET_CONFIG;
  if (fromEnv) return resolve(cwd, fromEnv);
  const local = resolve(cwd, DEFAULT_FILE);
  if (existsSync(local)) return local;
  console.warn(`[wicket] no ${DEFAULT_FILE} found, using ${EXAMPLE_FILE}; copy it to ${DEFAULT_FILE} and edit it`);
  return resolve(cwd, EXAMPLE_FILE);
}

/**
 * `$WICKET_YAML` carries the whole config as text, for builds that have no file to read
 * (Workers Builds, where the fork must not contain the config): the YAML itself, or its
 * base64 when the variable field cannot hold newlines. Decoded only when the raw text
 * is not YAML with a `zone` key, so a plain config is never mistaken for base64.
 */
export function configText(env: NodeJS.ProcessEnv = process.env): { text: string; label: string } | null {
  const raw = env.WICKET_YAML?.trim();
  if (!raw) return null;
  const isConfig = (s: string) => {
    try {
      const doc = parse(s);
      return typeof doc === 'object' && doc !== null && 'zone' in doc;
    } catch {
      return false;
    }
  };
  if (isConfig(raw)) return { text: raw, label: '$WICKET_YAML' };
  const decoded = Buffer.from(raw, 'base64').toString('utf8').trim();
  if (isConfig(decoded)) return { text: decoded, label: '$WICKET_YAML (base64)' };
  fail('$WICKET_YAML is neither wicket.yaml text nor its base64');
}

/** Where the config comes from, for log lines and generated-file headers. */
export function configSource(): string {
  return configText()?.label ?? configPath();
}

export function loadConfig(path?: string, recipes: ReadonlySet<string> | null = null): WicketConfig {
  let doc: unknown;
  try {
    const inline = path === undefined ? configText() : null;
    doc = parse(inline ? inline.text : readFileSync(path ?? configPath(), 'utf8'));
  } catch (err) {
    fail(`cannot read ${path ?? configSource()}: ${(err as Error).message}`);
  }
  return parseConfig(doc, recipes);
}

/** The Worker's plain-text vars, exactly as `src/config/env.ts` names them. */
export function toVars(cfg: WicketConfig): Record<string, string> {
  const hostsJson: Record<string, unknown> = {};
  for (const [host, h] of Object.entries(cfg.hosts)) {
    if (h.mode === 'observe') hostsJson[host] = { mode: 'observe', ...(h.recipe ? { recipe: h.recipe } : {}), ...(h.watch ? { watch: h.watch } : {}) };
    else if (h.passthrough) hostsJson[host] = { mode: 'gated', passthrough: h.passthrough };
    else if (h.mode !== 'gated' || cfg.defaultMode !== 'gated') hostsJson[host] = { mode: h.mode };
  }
  return {
    ALLOW_IPS: cfg.allowIps.join(','),
    ALLOW_DNS: cfg.allowDns.join(','),
    TRUST_SECONDS: String(cfg.trustWindow),
    BYPASS_PREFIXES: cfg.bypass.join(','),
    FAIL_LIMIT: String(cfg.limits.password.count),
    FAIL_WINDOW_SECONDS: String(cfg.limits.password.window),
    FAIL_GLOBAL_LIMIT: String(cfg.limits.rotating.count),
    FAIL_GLOBAL_WINDOW_SECONDS: String(cfg.limits.rotating.window),
    LOCKDOWN_SECONDS: String(cfg.limits.rotating.lockdown),
    SCAN_LIMIT: String(cfg.limits.scanner.count),
    SCAN_WINDOW_SECONDS: String(cfg.limits.scanner.window),
    SCANNING_LIMIT: String(cfg.limits.scanning.count),
    SIGNATURE_LIMIT: String(cfg.limits.signatures.count),
    SIGNATURE_WINDOW_SECONDS: String(cfg.limits.signatures.window),
    SIGNATURE_PATHS: cfg.signatures.paths.join('\n'),
    SIGNATURE_AGENTS: cfg.signatures.agents.join('\n'),
    ORIGIN_FAIL_LIMIT: String(cfg.limits.origin.count),
    ORIGIN_FAIL_WINDOW_SECONDS: String(cfg.limits.origin.window),
    HOSTS_JSON: JSON.stringify(hostsJson),
    DEFAULT_MODE: cfg.defaultMode,
    ZONE: cfg.zone,
    COOKIE_DAYS: String(cfg.cookieDays),
    COOKIE_DOMAIN: cfg.cookieDomain,
    ADMIN_HOSTS: cfg.alerts.adminHosts.join(','),
    QUIET_HOURS: cfg.alerts.quietHours,
    TIMEZONE: cfg.alerts.timezone,
    ALERT_IP_REQUESTS: String(cfg.alerts.ipRequests),
    ALERT_IP_ERRORS: String(cfg.alerts.ipErrors),
    ALERT_GUESS_IPS: String(cfg.alerts.guessIps),
    SITE_NAME: cfg.siteName,
    ANALYTICS_DATASET: cfg.cloudflare.analyticsDataset,
    RECONCILE_CRON: cfg.cloudflare.reconcileCron,
    NOTIFY_POLICY_JSON: JSON.stringify(cfg.notifications),
  };
}

/** One Workers route per host; the Worker only runs where it is routed. */
export function toRoutes(cfg: WicketConfig): { pattern: string; zone: string }[] {
  if (cfg.routes === 'wildcard') return [{ pattern: `*.${cfg.zone}/*`, zone: cfg.zone }];
  return Object.keys(cfg.hosts).map((host) => ({ pattern: `${host}/*`, zone: cfg.zone }));
}

export function toCrons(cfg: WicketConfig): string[] {
  return [...new Set([cfg.cloudflare.cron, cfg.cloudflare.reconcileCron])];
}
