import { LIST_COMMENT_MARKER, listAddMany, listItems, listRemoveIds } from '../cloudflare/lists';
import type { Env } from '../config/env';
import { resolveRuntime } from '../runtime';
import { emit, type Fetch } from '../notify';
import { clearPendingEdge, isBanned, listBans, readPendingEdge } from '../store/bans';

/**
 * Hourly: make the Cloudflare IP list agree with KV, the source of truth for wicket's bans.
 *
 * - A KV ban missing from the list (the API call failed when the ban happened, or the list
 *   was recreated) is added.
 * - A list item that wicket wrote (its comment starts with `wicket `) whose KV ban is gone
 *   (deleted by hand, or an unban whose list removal failed) is removed — unless the item
 *   is younger than `LIST_GRACE_MS`: KV listings are eventually consistent, so a ban written
 *   a minute ago may be in the list and not yet in the listing, and removing it would undo
 *   a real ban (seen live in 2026-10).
 * - Items written by anyone else — fail2ban's `cloudflare-list` action, manual entries —
 *   are never touched, so one list can serve several writers.
 */
export interface ReconcileResult {
  added: string[];
  removed: string[];
}

export const LIST_GRACE_MS = 10 * 60_000;

export async function reconcile(env: Env, doFetch: Fetch, now: number): Promise<ReconcileResult | null> {
  const cfg = (await resolveRuntime(env)).settings;
  const items = await listItems(env, doFetch, cfg.listId);
  if (items === null) return null;

  const banned = new Set((await listBans(env)).map((b) => b.ip));
  const listed = new Set(items.map((it) => it.ip));
  const added = [...banned].filter((ip) => !listed.has(ip));
  const settled = (it: { createdAt?: number }) => it.createdAt === undefined || now - it.createdAt > LIST_GRACE_MS;
  const stale = items.filter((it) => it.comment.startsWith(LIST_COMMENT_MARKER) && !banned.has(it.ip) && settled(it));

  const result: ReconcileResult = { added: [], removed: [] };
  if (added.length && (await listAddMany(env, doFetch, cfg.listId, added.map((ip) => ({ ip, comment: `${LIST_COMMENT_MARKER}${cfg.siteName}: restored by reconcile` }))))) {
    result.added = added;
  }
  if (stale.length && (await listRemoveIds(env, doFetch, cfg.listId, stale.map((it) => it.id)))) {
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

/**
 * Five-minute: retry the IP-list call for bans whose call failed when they happened
 * (the Lists API answers 429 when two bans land within seconds). One KV read when
 * nothing is pending; the hourly reconcile remains the backstop.
 */
export async function repairEdge(env: Env, doFetch: Fetch): Promise<string[]> {
  const pending = await readPendingEdge(env);
  if (!pending.length) return [];
  const cfg = (await resolveRuntime(env)).settings;
  const still: string[] = [];
  for (const ip of pending) if (await isBanned(env, ip)) still.push(ip);
  if (still.length && !(await listAddMany(env, doFetch, cfg.listId, still.map((ip) => ({ ip, comment: `${LIST_COMMENT_MARKER}${cfg.siteName}: added after a failed list call` }))))) return [];
  await clearPendingEdge(env);
  return still;
}
