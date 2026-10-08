import { LIST_COMMENT_MARKER, listAddMany, listItems, listRemoveIds } from '../cloudflare/lists';
import type { Env } from '../config/env';
import { settings } from '../config/settings';
import { emit, type Fetch } from '../notify';
import { listBans } from '../store/bans';

/**
 * Hourly: make the Cloudflare IP list agree with KV, the source of truth for wicket's bans.
 *
 * - A KV ban missing from the list (the API call failed when the ban happened, or the list
 *   was recreated) is added.
 * - A list item that wicket wrote (its comment starts with `wicket `) whose KV ban is gone
 *   (deleted by hand, or an unban whose list removal failed) is removed.
 * - Items written by anyone else — fail2ban's `cloudflare-list` action, manual entries —
 *   are never touched, so one list can serve several writers.
 */
export interface ReconcileResult {
  added: string[];
  removed: string[];
}

export async function reconcile(env: Env, doFetch: Fetch, now: number): Promise<ReconcileResult | null> {
  const cfg = settings(env);
  const items = await listItems(env, doFetch);
  if (items === null) return null;

  const banned = new Set((await listBans(env)).map((b) => b.ip));
  const listed = new Set(items.map((it) => it.ip));
  const added = [...banned].filter((ip) => !listed.has(ip));
  const stale = items.filter((it) => it.comment.startsWith(LIST_COMMENT_MARKER) && !banned.has(it.ip));

  const result: ReconcileResult = { added: [], removed: [] };
  if (added.length && (await listAddMany(env, doFetch, added.map((ip) => ({ ip, comment: `${LIST_COMMENT_MARKER}${cfg.siteName}: restored by reconcile` }))))) {
    result.added = added;
  }
  if (stale.length && (await listRemoveIds(env, doFetch, stale.map((it) => it.id)))) {
    result.removed = [...new Set(stale.map((it) => it.ip))];
  }

  if (result.added.length || result.removed.length) {
    await emit(env, doFetch, {
      kind: 'reconcile',
      severity: 'info',
      title: `${cfg.siteName}: IP list reconciled`,
      text: [
        result.added.length ? `added ${result.added.length}: ${result.added.slice(0, 10).join(', ')}` : '',
        result.removed.length ? `removed ${result.removed.length}: ${result.removed.slice(0, 10).join(', ')}` : '',
      ]
        .filter(Boolean)
        .join('\n'),
    }, now);
  }
  return result;
}
