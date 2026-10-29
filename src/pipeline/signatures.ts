import { banAddress } from '../actions/ban';
import { compileExtra, matchSensitive, matchSignature, type SignatureSets } from '../recipes/signatures';
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
 * Which signatures count. `all`: paths, files and User-Agents (a request wicket or the app
 * rejected). `files`: only the restricted-files class (`/.env`, `/.git/…`, credentials and
 * configs), for a request an observe host answered 2xx/3xx: a single-page app serves its
 * index for `/.env` too, and that request is still a scanner's — whereas `/wp-login.php`
 * answered 200 is a blog with a login page, and a scanner-like User-Agent on a page that
 * worked is not evidence.
 */
export type SignatureScope = 'all' | 'files';

/** The signature this request matches within `scope`, or null. */
export function scannerSignature(c: Ctx, scope: SignatureScope = 'all'): string | null {
  if (scope === 'files') return matchSensitive(c.url.pathname);
  return matchSignature(c.url.pathname, c.req.headers.get('user-agent') ?? '', extraSets(c));
}

/**
 * Called for an anonymous request that was rejected (gated) or passed through an observe
 * host. If the request matches a known scanner signature within `scope`, counts it per
 * address in isolate memory; at `limits.signatures` hits inside the window the address is
 * banned as a scanner. Returns the ban response, or null to let the normal answer go out.
 */
export async function signatureStrike(c: Ctx, scope: SignatureScope = 'all'): Promise<Result | null> {
  if (!c.cfg.signatureLimit) return null;
  const sig = scannerSignature(c, scope);
  if (!sig) return null;
  if (!c.signatures.hit(c.ip, c.cfg.signatureLimit, c.cfg.signatureWindowSeconds * 1000)) return null;
  c.signatures.reset(c.ip);
  const banned = await banAddress(c, c.ip, 'scan', c.cfg.signatureLimit, `${c.cfg.signatureLimit} requests for known scanner paths/agents in ${c.cfg.signatureWindowSeconds}s (last: ${sig})`);
  return banned ? [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'ban-scan'] : null;
}
