import { ipv6ToBigInt } from '../core/ip';
import { hostEntryOf, hostTableOf, type HostTable } from './hosts';
import type { Settings } from './settings';

/**
 * What the owner may change at runtime on /__wicket/settings, stored as one KV document
 * (`settings:runtime`, see store/settings.ts) and layered over the deploy-time config:
 *
 *   hosts    per-host entries that replace or add to HOSTS_JSON (same shape)
 *   access   allow_ips, allow_dns, trust_window, bypass
 *   limits   the numeric limits (counts and windows, in seconds)
 *
 * Pure functions only: parsing, validation, merging. Reading KV is runtime/'s job.
 */
export interface RuntimeOverrides {
  hosts?: Record<string, unknown>;
  access?: Partial<AccessOverride>;
  limits?: Partial<Record<LimitKey, number>>;
}

export interface AccessOverride {
  allowIps: string[];
  allowDns: string[];
  trustSeconds: number;
  /** `host/prefix` entries, as in wicket.yaml. */
  bypass: string[];
}

export const LIMIT_KEYS = [
  'failLimit',
  'failWindowSeconds',
  'failGlobalLimit',
  'failGlobalWindowSeconds',
  'lockdownSeconds',
  'scanLimit',
  'scanWindowSeconds',
  'scanningLimit',
  'signatureLimit',
  'signatureWindowSeconds',
  'originFailLimit',
  'originFailWindowSeconds',
] as const;
export type LimitKey = (typeof LIMIT_KEYS)[number];

/** Limits that may be 0 (= off). Everything else must be ≥ 1. */
const ZERO_OK: ReadonlySet<LimitKey> = new Set<LimitKey>(['signatureLimit']);

const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string').map((s) => s.trim()).filter(Boolean) : []);

/** Parses the stored document; anything malformed is dropped field by field, never fatal. */
export function runtimeOverridesOf(raw: unknown): RuntimeOverrides {
  let doc: unknown = raw;
  if (typeof raw === 'string') {
    try {
      doc = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!doc || typeof doc !== 'object') return {};
  const d = doc as Record<string, unknown>;
  const out: RuntimeOverrides = {};
  if (d.hosts && typeof d.hosts === 'object') out.hosts = d.hosts as Record<string, unknown>;
  if (d.access && typeof d.access === 'object') {
    const a = d.access as Record<string, unknown>;
    const access: Partial<AccessOverride> = {};
    if (Array.isArray(a.allowIps)) access.allowIps = strings(a.allowIps);
    if (Array.isArray(a.allowDns)) access.allowDns = strings(a.allowDns).map((s) => s.toLowerCase()).filter((s) => HOSTNAME.test(s));
    if (typeof a.trustSeconds === 'number' && Number.isFinite(a.trustSeconds) && a.trustSeconds >= 0) access.trustSeconds = Math.floor(a.trustSeconds);
    if (Array.isArray(a.bypass)) access.bypass = strings(a.bypass);
    out.access = access;
  }
  if (d.limits && typeof d.limits === 'object') {
    const l = d.limits as Record<string, unknown>;
    const limits: Partial<Record<LimitKey, number>> = {};
    for (const k of LIMIT_KEYS) {
      const v = l[k];
      if (typeof v === 'number' && Number.isFinite(v) && v >= (ZERO_OK.has(k) ? 0 : 1)) limits[k] = Math.floor(v);
    }
    out.limits = limits;
  }
  return out;
}

/** Deploy-time settings with the owner's runtime changes on top. */
export function applyOverrides(base: Settings, o: RuntimeOverrides): Settings {
  const s: Settings = { ...base };
  if (o.access) {
    if (o.access.allowIps) s.allowIps = o.access.allowIps;
    if (o.access.allowDns) s.allowDns = o.access.allowDns;
    if (o.access.trustSeconds !== undefined) s.trustSeconds = o.access.trustSeconds;
    if (o.access.bypass) {
      s.bypass = o.access.bypass.map((entry) => {
        const slash = entry.indexOf('/');
        return slash < 0 ? { host: entry, prefix: '/' } : { host: entry.slice(0, slash), prefix: entry.slice(slash) };
      });
    }
  }
  if (o.limits) for (const k of LIMIT_KEYS) if (o.limits[k] !== undefined) s[k] = o.limits[k]!;
  return s;
}

/** `90`, `90s`, `10m`, `24h`, `7d` → seconds; null when malformed. */
export function parseDuration(v: string): number | null {
  const m = v.trim().match(/^(\d+)\s*([smhd])?$/);
  if (!m) return null;
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86_400 };
  return Number(m[1]) * units[m[2] ?? 's']!;
}

/** Human form of a seconds value for the settings page: `3600` → `1h`. */
export function formatDuration(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Labels and grouping for the limits form; `window` keys take durations, the rest counts. */
export const LIMIT_FIELDS: { key: LimitKey; label: string; kind: 'count' | 'duration' }[] = [
  { key: 'failLimit', label: 'Wrong passwords/tokens per address before a ban', kind: 'count' },
  { key: 'failWindowSeconds', label: '… counted within', kind: 'duration' },
  { key: 'failGlobalLimit', label: 'Failures from any address before a lockdown', kind: 'count' },
  { key: 'failGlobalWindowSeconds', label: '… counted within', kind: 'duration' },
  { key: 'lockdownSeconds', label: 'Lockdown length', kind: 'duration' },
  { key: 'scanLimit', label: 'Anonymous probes per address (burst) before a ban', kind: 'count' },
  { key: 'scanWindowSeconds', label: '… counted within', kind: 'duration' },
  { key: 'scanningLimit', label: 'Probes per address in the five-minute analysis before a ban', kind: 'count' },
  { key: 'signatureLimit', label: 'Known scanner paths/agents per address before a ban (0 = off)', kind: 'count' },
  { key: 'signatureWindowSeconds', label: '… counted within', kind: 'duration' },
  { key: 'originFailLimit', label: "Failed logins at the app (observe / pass-through) before a ban", kind: 'count' },
  { key: 'originFailWindowSeconds', label: '… counted within', kind: 'duration' },
];

/** An allow-list entry the page accepts: IPv4, IPv4 CIDR, IPv6, IPv6 CIDR. */
export function validAllowEntry(s: string): boolean {
  const [net, bits] = s.split('/');
  if (!net) return false;
  if (net.includes(':')) return ipv6ToBigInt(net) !== null && (bits === undefined || (/^\d{1,3}$/.test(bits) && Number(bits) <= 128));
  if (!/^(\d{1,3})(\.\d{1,3}){3}$/.test(net) || net.split('.').some((p) => Number(p) > 255)) return false;
  return bits === undefined || (/^\d{1,2}$/.test(bits) && Number(bits) <= 32);
}

export const validHostname = (s: string): boolean => HOSTNAME.test(s);

/** Deploy-time host table with runtime entries replacing or adding hosts. */
export function applyHostOverrides(base: HostTable, o: RuntimeOverrides): HostTable {
  if (!o.hosts) return base;
  const out: HostTable = { ...base };
  for (const [host, v] of Object.entries(o.hosts)) {
    const name = host.toLowerCase();
    if (!HOSTNAME.test(name)) continue;
    out[name] = hostEntryOf(v);
  }
  return out;
}

export { hostTableOf };
