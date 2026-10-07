import type { Env } from '../config/env';
import type { Fetch } from '../notify';

const API = 'https://api.cloudflare.com/client/v4';

const configured = (env: Env) => Boolean(env.CF_API_TOKEN && env.CF_ACCOUNT_ID && env.CF_LIST_ID);

const headers = (env: Env) => ({
  authorization: `Bearer ${env.CF_API_TOKEN}`,
  'content-type': 'application/json',
});

/**
 * Every item wicket writes starts its comment with this, so the reconcile cron can tell its
 * own entries from fail2ban's or manual ones in a shared list.
 */
export const LIST_COMMENT_MARKER = 'wicket ';

const itemsUrl = (env: Env) => `${API}/accounts/${env.CF_ACCOUNT_ID}/rules/lists/${env.CF_LIST_ID}/items`;

export interface ListItem {
  id: string;
  ip: string;
  comment: string;
}

/** Appends the IP to the account IP list; a zone WAF rule referencing the list blocks it at the edge. */
export async function listAdd(env: Env, doFetch: Fetch, ip: string, comment: string): Promise<boolean> {
  return listAddMany(env, doFetch, [{ ip, comment }]);
}

/** One POST for several addresses (the reconcile cron). */
export async function listAddMany(env: Env, doFetch: Fetch, items: { ip: string; comment: string }[]): Promise<boolean> {
  if (!configured(env) || !items.length) return false;
  const res = await doFetch(itemsUrl(env), {
    method: 'POST',
    headers: headers(env),
    body: JSON.stringify(items.map((it) => ({ ip: it.ip, comment: it.comment.slice(0, 500) }))),
  });
  if (!res.ok) console.warn('cf list add failed', res.status, (await res.text()).slice(0, 200));
  return res.ok;
}

/** Removes every list item whose ip matches. */
export async function listRemove(env: Env, doFetch: Fetch, ip: string): Promise<boolean> {
  if (!configured(env)) return false;
  const found = await doFetch(`${itemsUrl(env)}?search=${encodeURIComponent(ip)}`, { headers: headers(env) });
  if (!found.ok) return false;
  const data = (await found.json()) as { result?: { id: string; ip?: string }[] };
  const ids = (data.result ?? []).filter((it) => it.ip === ip).map((it) => it.id);
  if (!ids.length) return true;
  return listRemoveIds(env, doFetch, ids);
}

export async function listRemoveIds(env: Env, doFetch: Fetch, ids: string[]): Promise<boolean> {
  if (!configured(env) || !ids.length) return false;
  const res = await doFetch(itemsUrl(env), { method: 'DELETE', headers: headers(env), body: JSON.stringify({ items: ids.map((id) => ({ id })) }) });
  if (!res.ok) console.warn('cf list remove failed', res.status, (await res.text()).slice(0, 200));
  return res.ok;
}

/** Every IP item in the list (paginated by cursor). Returns null when unconfigured or on error. */
export async function listItems(env: Env, doFetch: Fetch): Promise<ListItem[] | null> {
  if (!configured(env)) return null;
  const items: ListItem[] = [];
  let cursor: string | undefined;
  do {
    const res = await doFetch(`${itemsUrl(env)}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, { headers: headers(env) });
    if (!res.ok) {
      console.warn('cf list read failed', res.status, (await res.text()).slice(0, 200));
      return null;
    }
    const data = (await res.json()) as { result?: { id: string; ip?: string; comment?: string }[]; result_info?: { cursors?: { after?: string } } };
    for (const it of data.result ?? []) if (it.ip) items.push({ id: it.id, ip: it.ip, comment: it.comment ?? '' });
    cursor = data.result_info?.cursors?.after || undefined;
  } while (cursor);
  return items;
}
