import type { Env } from '../config/env';
import type { Fetch } from '../notify';

/**
 * The Cloudflare-side wiring wicket needs beyond the Worker itself, checked and created
 * from the settings page so nobody has to find the right dashboard screens:
 *   - an API token (verify it, read its permissions)
 *   - Analytics Engine answering SQL (the account switch)
 *   - the IP list for edge bans, and the zone WAF rule that blocks it
 * Everything here is a thin REST client; decisions live in pipeline/endpoints.ts.
 */
const API = 'https://api.cloudflare.com/client/v4';

const headers = (env: Env) => ({ authorization: `Bearer ${env.CF_API_TOKEN}`, 'content-type': 'application/json' });

interface ApiResponse<T> {
  success?: boolean;
  result?: T;
  errors?: { code: number; message: string }[];
}

async function call<T>(env: Env, doFetch: Fetch, method: string, path: string, body?: unknown): Promise<{ ok: true; result: T } | { ok: false; status: number; error: string }> {
  const res = await doFetch(`${API}${path}`, { method, headers: headers(env), ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  let data: ApiResponse<T> | null = null;
  try {
    data = (await res.json()) as ApiResponse<T>;
  } catch {
    /* non-JSON error body */
  }
  if (!res.ok || !data?.success) return { ok: false, status: res.status, error: data?.errors?.map((e) => `${e.code}: ${e.message}`).join('; ') || `HTTP ${res.status}` };
  return { ok: true, result: data.result as T };
}

export type TokenState = { state: 'missing' } | { state: 'invalid'; error: string } | { state: 'active' | 'expired' | 'disabled'; id: string };

/** `GET /user/tokens/verify`: whether the token wicket holds is usable at all. */
export async function verifyToken(env: Env, doFetch: Fetch): Promise<TokenState> {
  if (!env.CF_API_TOKEN) return { state: 'missing' };
  const r = await call<{ id: string; status: string }>(env, doFetch, 'GET', '/user/tokens/verify');
  if (!r.ok) return { state: 'invalid', error: r.error };
  const status = r.result.status === 'active' || r.result.status === 'expired' || r.result.status === 'disabled' ? r.result.status : 'invalid';
  return status === 'invalid' ? { state: 'invalid', error: `status ${r.result.status}` } : { state: status, id: r.result.id };
}

/** One cheap SQL query: is Analytics Engine enabled and the token allowed to read it? */
export async function analyticsReachable(env: Env, doFetch: Fetch, dataset: string): Promise<{ ok: true; rows: number } | { ok: false; error: string }> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { ok: false, error: 'CF_API_TOKEN or CF_ACCOUNT_ID missing' };
  const res = await doFetch(`${API}/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN}` },
    body: `SELECT count() AS n FROM ${dataset} WHERE timestamp > NOW() - INTERVAL '1' DAY`,
  });
  if (!res.ok) return { ok: false, error: `HTTP ${res.status}: ${(await res.text()).slice(0, 160)}` };
  const data = (await res.json().catch(() => ({}))) as { data?: { n?: string | number }[] };
  return { ok: true, rows: Number(data.data?.[0]?.n ?? 0) };
}

export interface ListInfo {
  id: string;
  name: string;
  items: number;
}

/** The account IP lists the token can see. */
export async function listLists(env: Env, doFetch: Fetch): Promise<ListInfo[] | null> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return null;
  const r = await call<{ id: string; name: string; kind: string; num_items?: number }[]>(env, doFetch, 'GET', `/accounts/${env.CF_ACCOUNT_ID}/rules/lists`);
  if (!r.ok) return null;
  return r.result.filter((l) => l.kind === 'ip').map((l) => ({ id: l.id, name: l.name, items: l.num_items ?? 0 }));
}

/** Creates (or finds) the account IP list wicket writes bans to; returns its id. */
export async function ensureList(env: Env, doFetch: Fetch, name: string): Promise<{ ok: true; id: string; created: boolean } | { ok: false; error: string }> {
  const existing = (await listLists(env, doFetch))?.find((l) => l.name === name);
  if (existing) return { ok: true, id: existing.id, created: false };
  const r = await call<{ id: string }>(env, doFetch, 'POST', `/accounts/${env.CF_ACCOUNT_ID}/rules/lists`, { name, kind: 'ip', description: 'Addresses banned by wicket (and fail2ban, if you use the companion action)' });
  return r.ok ? { ok: true, id: r.result.id, created: true } : { ok: false, error: r.error };
}

/** The zone id for a zone name, if the token may read zones. */
export async function findZone(env: Env, doFetch: Fetch, zone: string): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  const r = await call<{ id: string; name: string }[]>(env, doFetch, 'GET', `/zones?name=${encodeURIComponent(zone)}`);
  if (!r.ok) return r;
  const hit = r.result.find((z) => z.name === zone);
  return hit ? { ok: true, id: hit.id } : { ok: false, error: `zone ${zone} not visible to this token` };
}

interface Ruleset {
  id: string;
  rules?: { id: string; expression: string; action: string; description?: string }[];
}

export const WAF_EXPRESSION = (listName: string) => `ip.src in $${listName}`;

/** The zone's custom WAF rules entrypoint, or null when it does not exist yet. */
async function customRules(env: Env, doFetch: Fetch, zoneId: string): Promise<{ ok: true; ruleset: Ruleset | null } | { ok: false; error: string }> {
  const r = await call<Ruleset>(env, doFetch, 'GET', `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`);
  if (r.ok) return { ok: true, ruleset: r.result };
  return r.status === 404 ? { ok: true, ruleset: null } : r;
}

/** Is there a WAF custom rule blocking the list? `unknown` when the token cannot read zone rulesets. */
export async function wafRuleState(env: Env, doFetch: Fetch, zoneId: string, listName: string): Promise<'present' | 'missing' | 'unknown'> {
  const r = await customRules(env, doFetch, zoneId);
  if (!r.ok) return 'unknown';
  return r.ruleset?.rules?.some((rule) => rule.action === 'block' && rule.expression.replace(/\s+/g, ' ').includes(WAF_EXPRESSION(listName))) ? 'present' : 'missing';
}

/** Adds the blocking rule to the zone's custom WAF ruleset (creating the ruleset if needed). */
export async function ensureWafRule(env: Env, doFetch: Fetch, zoneId: string, listName: string): Promise<{ ok: true; created: boolean } | { ok: false; error: string }> {
  const state = await wafRuleState(env, doFetch, zoneId, listName);
  if (state === 'present') return { ok: true, created: false };
  const rule = { action: 'block', expression: WAF_EXPRESSION(listName), description: 'wicket: addresses banned at the edge', enabled: true };
  const current = await customRules(env, doFetch, zoneId);
  if (!current.ok) return current;
  const r = current.ruleset
    ? await call<Ruleset>(env, doFetch, 'POST', `/zones/${zoneId}/rulesets/${current.ruleset.id}/rules`, rule)
    : await call<Ruleset>(env, doFetch, 'PUT', `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`, { rules: [rule] });
  return r.ok ? { ok: true, created: true } : { ok: false, error: r.error };
}
