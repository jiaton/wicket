import { safeEqual } from './crypto';

/**
 * Password hashing for passwords set on the setup/settings page (kept in KV). PBKDF2-SHA256
 * with 20,000 iterations: 4–5 ms of CPU on a slow core, inside the free plan's 10 ms budget
 * even when both roles are checked; the real brute-force protection is the three-strikes
 * ban (which must run *after* the check, so the check must never be killed for CPU time),
 * the hash only has to survive a KV leak. Owner and friend hashes share one salt, so a wrong
 * password costs one derivation, not two. Format: `pbkdf2$<iterations>$<salt hex>$<hash hex>`.
 */
const ITERATIONS = 20_000;
const enc = new TextEncoder();

const hex = (buf: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations }, key, 256));
}

/** `sharedWith`: an existing hash whose salt and iteration count this one should reuse (one derivation checks both). */
export async function hashPassword(password: string, sharedWith?: string): Promise<string> {
  const shared = sharedWith ? parseStored(sharedWith) : null;
  const salt = shared ? fromHex(shared.salt) : crypto.getRandomValues(new Uint8Array(16));
  const iterations = shared ? shared.iterations : ITERATIONS;
  return `pbkdf2$${iterations}$${hex(salt)}$${await derive(password, salt, iterations)}`;
}

function parseStored(stored: string): { iterations: number; salt: string; hash: string } | null {
  const [scheme, iter, salt, hash] = stored.split('$');
  if (scheme !== 'pbkdf2' || !iter || !salt || !hash) return null;
  const iterations = Number(iter);
  if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 1_000_000) return null;
  return { iterations, salt, hash };
}

/**
 * Which of several stored hashes the password matches (index), or -1. Hashes that share salt
 * and iterations are checked with one derivation.
 */
export async function matchPasswords(password: string, stored: (string | null | undefined)[]): Promise<number> {
  const derived = new Map<string, string>();
  for (const [i, s] of stored.entries()) {
    if (!s) continue;
    const parsed = parseStored(s);
    if (!parsed) continue;
    const k = `${parsed.iterations}$${parsed.salt}`;
    let d = derived.get(k);
    if (d === undefined) {
      d = await derive(password, fromHex(parsed.salt), parsed.iterations);
      derived.set(k, d);
    }
    if (safeEqual(d, parsed.hash)) return i;
  }
  return -1;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  return (await matchPasswords(password, [stored])) === 0;
}

/** 32 random bytes as hex: cookie secrets, setup tokens. */
export const randomSecret = (): string => hex(crypto.getRandomValues(new Uint8Array(32)));
