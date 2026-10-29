import type { Env } from '../config/env';
import type { Fetch } from '../notify';

const API = 'https://api.cloudflare.com/client/v4';

const configured = (env: Env, listId: string) => Boolean(env.CF_API_TOKEN && env.CF_ACCOUNT_ID && listId);

const headers = (env: Env) => ({
  authorization: `Bearer ${env.CF_API_TOKEN}`,
  'content-type': 'application/json',
});

/**
 * Every item wicket writes starts its comment with this, so the reconcile cron can tell its
 * own entries from fail2ban's or manual ones in a shared list.
 */
export const LIST_COMMENT_MARKER = 'wicket ';

const itemsUrl = (env: Env, listId: string) => `${API}/accounts/${env.CF_ACCOUNT_ID}/rules/lists/${listId}/items`;

export interface ListItem {
  id: string;
  ip: string;
  comment: string;
  /** Milliseconds since epoch, from the API's `created_on`; undefined when absent. */
  createdAt?: number;
}

/** Appends the IP to the account IP list; a zone WAF rule referencing the list blocks it at the edge. */
export async function listAdd(env: Env, doFetch: Fetch, listId: string, ip: string, comment: string): Promise<boolean> {
  return listAddMany(env, doFetch, listId, [{ ip, comment }]);
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * One POST for several addresses. The Lists API takes one operation per list at a time and
 * answers 429 to the next one, which happens whenever two bans land within seconds; one
 * short retry covers that. Anything still failing is left to the pending-edge retry.
 */
export async function listAddMany(env: Env, doFetch: Fetch, listId: string, items: { ip: string; comment: string }[], retryDelayMs = 2000): Promise<boolean> {
  if (!configured(env, listId) || !items.length) return false;
  const body = JSON.stringify(items.map((it) => ({ ip: it.ip, comment: it.comment.slice(0, 500) })));
  for (let attempt = 0; ; attempt++) {
    const res = await doFetch(itemsUrl(env, listId), { method: 'POST', headers: headers(env), body });
    if (res.ok) return true;
    const text = (await res.text()).slice(0, 200);
    if (res.status === 429 && attempt === 0) {
      await sleep(retryDelayMs);
      continue;
    }
    console.warn('cf list add failed', res.status, text);
    return false;
  }
}

/** Removes every list item whose ip matches. */
export async function listRemove(env: Env, doFetch: Fetch, listId: string, ip: string): Promise<boolean> {
  if (!configured(env, listId)) return false;
  const found = await doFetch(`${itemsUrl(env, listId)}?search=${encodeURIComponent(ip)}`, { headers: headers(env) });
  if (!found.ok) return false;
  const data = (await found.json()) as { result?: { id: string; ip?: string }[] };
  const ids = (data.result ?? []).filter((it) => it.ip === ip).map((it) => it.id);
  if (!ids.length) return true;
  return listRemoveIds(env, doFetch, listId, ids);
}

export async function listRemoveIds(env: Env, doFetch: Fetch, listId: string, ids: string[]): Promise<boolean> {
  if (!configured(env, listId) || !ids.length) return false;
  const res = await doFetch(itemsUrl(env, listId), { method: 'DELETE', headers: headers(env), body: JSON.stringify({ items: ids.map((id) => ({ id })) }) });
  if (!res.ok) console.warn('cf list remove failed', res.status, (await res.text()).slice(0, 200));
  return res.ok;
}

/** Every IP item in the list (paginated by cursor). Returns null when unconfigured or on error. */
export async function listItems(env: Env, doFetch: Fetch, listId: string): Promise<ListItem[] | null> {
  if (!configured(env, listId)) return null;
  const items: ListItem[] = [];
  let cursor: string | undefined;
  do {
    const res = await doFetch(`${itemsUrl(env, listId)}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, { headers: headers(env) });
    if (!res.ok) {
      console.warn('cf list read failed', res.status, (await res.text()).slice(0, 200));
      return null;
    }
    const data = (await res.json()) as { result?: { id: string; ip?: string; comment?: string; created_on?: string }[]; result_info?: { cursors?: { after?: string } } };
    for (const it of data.result ?? []) {
      if (!it.ip) continue;
      const createdAt = it.created_on ? Date.parse(it.created_on) : NaN;
      items.push({ id: it.id, ip: it.ip, comment: it.comment ?? '', ...(Number.isFinite(createdAt) ? { createdAt } : {}) });
    }
    cursor = data.result_info?.cursors?.after || undefined;
  } while (cursor);
  return items;
}
