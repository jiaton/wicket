import { banAddress } from '../actions/ban';
import { compileExtra, matchSignature, type SignatureSets } from '../recipes/signatures';
import { messagePage } from '../ui/pages';
import type { Ctx, Result } from './context';
import { html } from './respond';

let cache: { key: string; sets: SignatureSets } | null = null;

/** The user's extra patterns, compiled once per isolate (per distinct var value). */
function extraSets(c: Ctx): SignatureSets {
  const key = `${c.env.SIGNATURE_PATHS ?? ''}\n--\n${c.env.SIGNATURE_AGENTS ?? ''}`;
  if (!cache || cache.key !== key) cache = { key, sets: compileExtra(c.env.SIGNATURE_PATHS, c.env.SIGNATURE_AGENTS) };
  return cache.sets;
}

/**
 * Called for an anonymous request that was rejected (gated) or answered 4xx by the origin
 * (observe). If the path or User-Agent is a known scanner signature, counts it per address
 * in isolate memory; at `limits.signatures` hits inside the window the address is banned
 * as a scanner. Returns the ban response, or null to let the normal answer go out.
 */
export async function signatureStrike(c: Ctx): Promise<Result | null> {
  if (!c.cfg.signatureLimit) return null;
  const sig = matchSignature(c.url.pathname, c.req.headers.get('user-agent') ?? '', extraSets(c));
  if (!sig) return null;
  if (!c.signatures.hit(c.ip, c.cfg.signatureLimit, c.cfg.signatureWindowSeconds * 1000)) return null;
  c.signatures.reset(c.ip);
  const banned = await banAddress(c, c.ip, 'scan', c.cfg.signatureLimit, `${c.cfg.signatureLimit} requests for known scanner paths/agents in ${c.cfg.signatureWindowSeconds}s (last: ${sig})`);
  return banned ? [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'ban'] : null;
}
