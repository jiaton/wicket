import type { Env } from '../config/env';

/**
 * KV key `share:<id>`: a share the owner created for one host. The link and the cookie carry
 * a signature (core/crypto.ts signShare) so the Worker can reject forgeries without KV; the
 * record exists so the owner can revoke a share (delete) and see what is out there (list).
 * The key expires with the share, so nothing lingers.
 */
export interface ShareRecord {
  host: string;
  label: string;
  /** Seconds since epoch. */
  exp: number;
  /** Created, ms since epoch. */
  at: number;
}

export interface Share extends ShareRecord {
  id: string;
}

const key = (id: string) => `share:${id}`;

export async function writeShare(env: Env, id: string, record: ShareRecord, now: number): Promise<void> {
  await env.STORE.put(key(id), JSON.stringify(record), { expirationTtl: Math.max(60, record.exp - Math.floor(now / 1000)), metadata: record });
}

export async function readShare(env: Env, id: string): Promise<ShareRecord | null> {
  if (!/^[0-9a-f]{16}$/.test(id)) return null;
  const raw = await env.STORE.get(key(id));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ShareRecord;
  } catch {
    return null;
  }
}

export const revokeShare = (env: Env, id: string): Promise<void> => env.STORE.delete(key(id));

/** Every live share (from key metadata, no record reads). */
export async function listShares(env: Env): Promise<Share[]> {
  const out: Share[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.STORE.list<ShareRecord>({ prefix: 'share:', cursor });
    for (const k of page.keys) if (k.metadata) out.push({ id: k.name.slice('share:'.length), ...k.metadata });
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out.sort((a, b) => a.exp - b.exp);
}
