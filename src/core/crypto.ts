const enc = new TextEncoder();

const toHex = (buf: ArrayBuffer) =>
  Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

export async function hmacHex(key: string, message: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', k, enc.encode(message)));
}

/** Constant-time string equality; a length difference still returns false without an early exit on content. */
export function safeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i % x.length] ?? 0) ^ (y[i % y.length] ?? 0);
  return diff === 0;
}

export type Role = 'owner' | 'friend';

export const COOKIE_NAME = '__wicket';

/**
 * Cookie value `role.issuedAt.sig`. The HMAC key mixes the role's password in, so
 * changing a password silently logs that role's browsers out.
 */
export async function signSession(secret: string, password: string, role: Role, issuedAt: number): Promise<string> {
  const body = `${role}.${issuedAt}`;
  return `${body}.${await hmacHex(`${secret}\n${role}\n${password}`, body)}`;
}

export interface Session {
  role: Role;
  issuedAt: number;
}

export async function verifySession(
  value: string | undefined,
  secret: string,
  passwords: Record<Role, string | undefined>,
  now: number,
  maxAgeSeconds: number,
): Promise<Session | null> {
  if (!value) return null;
  const [role, issued, sig] = value.split('.');
  if ((role !== 'owner' && role !== 'friend') || !issued || !sig) return null;
  const password = passwords[role];
  if (!password) return null;
  const issuedAt = Number(issued);
  if (!Number.isFinite(issuedAt) || issuedAt > now + 60 || now - issuedAt > maxAgeSeconds) return null;
  const expected = await hmacHex(`${secret}\n${role}\n${password}`, `${role}.${issuedAt}`);
  return safeEqual(sig, expected) ? { role, issuedAt } : null;
}

/** Share links and share cookies: `id.exp.sig`, bound to one host. */
export async function signShare(secret: string, id: string, host: string, exp: number): Promise<string> {
  return hmacHex(`${secret}\nshare`, `${id}.${host}.${exp}`);
}

/** Signed, expiring parameters for the one-click Unban / Lift-lockdown link. */
export async function signUnban(secret: string, ip: string, exp: number, at: number): Promise<string> {
  return hmacHex(`${secret}\nunban`, `${ip}.${exp}.${at}`);
}
