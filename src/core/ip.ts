/** The visitor's address as Cloudflare saw it. */
export const clientIp = (req: Request): string => req.headers.get('cf-connecting-ip') ?? '0.0.0.0';

/** Two-letter country code from the request's `cf` object (or the header, in tests). */
export const country = (req: Request): string =>
  ((req as { cf?: { country?: string } }).cf?.country ?? req.headers.get('cf-ipcountry') ?? '??').toUpperCase();

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!/^\d{1,3}$/.test(p) || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

/** Exact IPv4/IPv6 literals and IPv4 CIDRs; anything malformed never matches. */
export function ipAllowed(ip: string, allow: string[]): boolean {
  for (const entry of allow) {
    if (entry === ip) return true;
    const [net, bits] = entry.split('/');
    if (!net || bits === undefined) continue;
    const a = ipv4ToInt(ip);
    const b = ipv4ToInt(net);
    const len = Number(bits);
    if (a === null || b === null || !(len >= 0 && len <= 32)) continue;
    const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
    if (((a & mask) >>> 0) === ((b & mask) >>> 0)) return true;
  }
  return false;
}
