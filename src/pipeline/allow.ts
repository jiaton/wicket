import type { Env } from '../config/env';
import type { Settings } from '../config/settings';
import { ipAllowed } from '../core/ip';
import type { Fetch } from '../notify';

/** How long one DNS answer is used before it is looked up again. */
export const DNS_TTL_MS = 5 * 60_000;
const DOH = 'https://cloudflare-dns.com/dns-query';

export type AllowCheck = (env: Env, cfg: Settings, ip: string) => Promise<boolean>;

/** Resolves a hostname's A and AAAA records over DNS-over-HTTPS (JSON); empty on any failure. */
export async function resolveAddresses(doFetch: Fetch, name: string): Promise<string[]> {
  const out: string[] = [];
  for (const type of ['A', 'AAAA']) {
    try {
      const res = await doFetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
      if (!res.ok) continue;
      const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
      for (const a of data.Answer ?? []) if ((a.type === 1 || a.type === 28) && a.data) out.push(a.data.toLowerCase());
    } catch {
      /* unreachable resolver: keep what we have */
    }
  }
  return out;
}

/**
 * The allow list, static entries plus `allow_dns` names. Names are resolved at most once per
 * `DNS_TTL_MS` per isolate; a failed lookup keeps the previous answer, so a resolver hiccup
 * never turns the password page on for the household. Build one per isolate (or per job).
 */
export function createAllowCheck(deps: { fetch: Fetch; now: () => number }): AllowCheck {
  let cache: { key: string; at: number; ips: string[] } | null = null;
  return async (env, cfg, ip) => {
    if (ipAllowed(ip, cfg.allowIps)) return true;
    if (!cfg.allowDns.length) return false;
    const key = cfg.allowDns.join(',');
    const now = deps.now();
    if (!cache || cache.key !== key || now - cache.at >= DNS_TTL_MS) {
      const ips = (await Promise.all(cfg.allowDns.map((n) => resolveAddresses(deps.fetch, n)))).flat();
      cache = { key, at: now, ips: ips.length || !cache || cache.key !== key ? ips : cache.ips };
    }
    return ipAllowed(ip.toLowerCase(), cache.ips);
  };
}
