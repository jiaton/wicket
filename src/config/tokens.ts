import { safeEqual } from '../core/crypto';
import { list, type Env } from './env';

export interface ApiToken {
  name: string;
  token: string;
  /** Hostnames the token is valid for; empty = any gated host. */
  hosts: string[];
}

/** `name:token` entries, comma-separated; `name:token@host1|host2` limits a token to those hosts. */
export function apiTokens(env: Env): ApiToken[] {
  return list(env.API_TOKENS).flatMap((entry) => {
    const colon = entry.indexOf(':');
    if (colon <= 0) return [];
    const name = entry.slice(0, colon);
    const [token, hostPart] = entry.slice(colon + 1).split('@');
    if (!token) return [];
    return [{ name, token, hosts: (hostPart ?? '').split('|').map((h) => h.trim()).filter(Boolean) }];
  });
}

/** Constant-time lookup: every token is compared so timing does not reveal which ones exist. */
export function matchToken(value: string, host: string, tokens: ApiToken[]): ApiToken | null {
  let hit: ApiToken | null = null;
  for (const t of tokens) {
    const equal = safeEqual(value, t.token);
    if (equal && (t.hosts.length === 0 || t.hosts.includes(host))) hit = t;
  }
  return hit;
}
