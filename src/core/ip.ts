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

/** IPv6 literal (with `::` compression, optional embedded IPv4) → 128-bit integer; null when malformed. */
export function ipv6ToBigInt(ip: string): bigint | null {
  if (!ip.includes(':') || /[^0-9a-fA-F:.]/.test(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const expand = (s: string): number[] | null => {
    if (!s) return [];
    const out: number[] = [];
    for (const part of s.split(':')) {
      if (part.includes('.')) {
        const v4 = ipv4ToInt(part);
        if (v4 === null) return null;
        out.push(v4 >>> 16, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
        out.push(Number.parseInt(part, 16));
      }
    }
    return out;
  };
  const head = expand(halves[0]!);
  const tail = halves.length === 2 ? expand(halves[1]!) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array<number>(missing).fill(0), ...tail];
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}

const MASK128 = (1n << 128n) - 1n;

/** `2001:db8:1:2::/64` style text for a /64 network. */
function ipv6Prefix64(n: bigint): string {
  const net = n >> 64n;
  const groups = [48n, 32n, 16n, 0n].map((shift) => ((net >> shift) & 0xffffn).toString(16));
  return `${groups.join(':')}::/64`;
}

/**
 * The key wicket counts, bans and trusts by. IPv4: the address itself. IPv6: the /64,
 * because one subscriber holds a whole /64 and rotates privacy addresses inside it
 * (per-address limits would be trivial to evade, and the household's devices would each
 * need their own trust); Cloudflare IP lists accept IPv6 only as CIDRs down to /64 anyway.
 * Malformed input is returned unchanged so it can still be logged and banned as a literal.
 */
export function addressKey(ip: string): string {
  if (!ip.includes(':')) return ip;
  const n = ipv6ToBigInt(ip.split('/')[0]!);
  return n === null ? ip : ipv6Prefix64(n);
}

const IPV4_CIDR = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/;

/**
 * Allow-list match for an address or its key: exact IPv4, IPv4 CIDR, IPv6 literal or IPv6
 * CIDR. An IPv6 literal in the list matches its whole /64 (the key wicket works with);
 * anything malformed never matches.
 */
export function ipAllowed(ip: string, allow: string[]): boolean {
  const subject = ip.split('/')[0]!;
  if (!subject.includes(':')) {
    const a = ipv4ToInt(subject);
    if (a === null) return false;
    for (const entry of allow) {
      const m = entry.match(IPV4_CIDR);
      if (!m) continue;
      const b = ipv4ToInt(m[1]!);
      const len = m[2] === undefined ? 32 : Number(m[2]);
      if (b === null || len > 32) continue;
      const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
      if (((a & mask) >>> 0) === ((b & mask) >>> 0)) return true;
    }
    return false;
  }
  const a = ipv6ToBigInt(subject);
  if (a === null) return false;
  for (const entry of allow) {
    if (!entry.includes(':')) continue;
    const [net, bits] = entry.split('/');
    const b = ipv6ToBigInt(net!);
    const len = bits === undefined ? 64 : Number(bits);
    if (b === null || !Number.isInteger(len) || len < 0 || len > 128) continue;
    const mask = len === 0 ? 0n : (MASK128 << BigInt(128 - len)) & MASK128;
    if ((a & mask) === (b & mask)) return true;
  }
  return false;
}
