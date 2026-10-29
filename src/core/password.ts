import { safeEqual } from './crypto';

/**
 * Password hashing for passwords set on the setup/settings page (kept in KV). PBKDF2-SHA256
 * with 40,000 iterations: about 5 ms of CPU, inside the free plan's 10 ms budget; the real
 * brute-force protection is the three-strikes ban, the hash only has to survive a KV leak.
 * Format: `pbkdf2$<iterations>$<salt hex>$<hash hex>`.
 */
const ITERATIONS = 40_000;
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

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITERATIONS}$${hex(salt)}$${await derive(password, salt, ITERATIONS)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iter, salt, hash] = stored.split('$');
  if (scheme !== 'pbkdf2' || !iter || !salt || !hash) return false;
  const iterations = Number(iter);
  if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 1_000_000) return false;
  return safeEqual(await derive(password, fromHex(salt), iterations), hash);
}

/** 32 random bytes as hex: cookie secrets, setup tokens. */
export const randomSecret = (): string => hex(crypto.getRandomValues(new Uint8Array(32)));
