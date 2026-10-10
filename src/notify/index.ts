import { parseChannels, RANK, type Channel, type Severity } from '../config/channels';
import type { Env } from '../config/env';
import { KIND_LABELS, type Delivery, type EventKind, type PolicyKind } from '../config/notifications';
import { send } from './adapters';
import { resolvePolicy } from './policy';

export type { Severity } from '../config/channels';
export type Fetch = typeof fetch;

/** One thing worth telling the owner. `text` is plain; adapters do their own markup. */
export interface Event {
  kind: EventKind;
  severity: Severity;
  title: string;
  text: string;
  /** A one-click action, e.g. the signed Unban link. */
  link?: { text: string; url: string };
  /** For compact digest lines (bans). */
  ip?: string;
  cc?: string;
  host?: string;
}

interface Queue {
  since: number;
  dropped: number;
  events: Event[];
}

const QUEUE_MAX = 100;
const queueKey = (index: number) => `nq:${index}`;

/**
 * Fan an event out: every channel whose severity threshold it meets gets it either now,
 * in the next digest, or not at all, as the notification policy says for its kind.
 * A channel with `batch: true` takes digests for everything below `critical`.
 */
export async function emit(env: Env, doFetch: Fetch, event: Event, now: number): Promise<void> {
  const channels = parseChannels(env);
  if (!channels.length) return;
  const policy = await resolvePolicy(env);
  const byPolicy: Delivery = event.kind === 'test' ? 'immediate' : policy.kinds[event.kind as PolicyKind];
  await Promise.all(
    channels.map(async (ch, i) => {
      if (RANK[event.severity] < RANK[ch.min]) return;
      const delivery: Delivery = ch.batch && event.severity !== 'critical' ? (byPolicy === 'off' ? 'off' : 'digest') : byPolicy;
      if (delivery === 'off') return;
      if (delivery === 'digest') return enqueue(env, i, event, now);
      await send(ch, event, doFetch);
    }),
  );
}

async function readQueue(env: Env, index: number): Promise<Queue | null> {
  const raw = await env.STORE.get(queueKey(index));
  if (!raw) return null;
  try {
    const q = JSON.parse(raw) as Partial<Queue>;
    return { since: Number(q.since) || 0, dropped: Number(q.dropped) || 0, events: Array.isArray(q.events) ? q.events : [] };
  } catch {
    return null;
  }
}

async function enqueue(env: Env, index: number, event: Event, now: number): Promise<void> {
  const q = (await readQueue(env, index)) ?? { since: now, dropped: 0, events: [] };
  if (q.events.length >= QUEUE_MAX) q.dropped += 1;
  else q.events.push(event);
  await env.STORE.put(queueKey(index), JSON.stringify(q), { expirationTtl: 2 * 86_400 });
}

const duration = (seconds: number) => (seconds % 3600 === 0 ? `${seconds / 3600} h` : `${Math.round(seconds / 60)} min`);

/** One digest message from queued events: bans of one kind collapse to a single line. */
export function digestEvent(siteName: string, q: Queue, windowSeconds: number): Event {
  const groups = new Map<EventKind, Event[]>();
  for (const e of q.events) groups.set(e.kind, [...(groups.get(e.kind) ?? []), e]);
  const lines: string[] = [];
  const banLine = (label: string, list: Event[]) => {
    const shown = list.slice(0, 12).map((e) => `${e.ip ?? '?'}${e.cc ? ` (${e.cc})` : ''}${e.host ? ` ${e.host}` : ''}`);
    return `${label} (${list.length}): ${shown.join(', ')}${list.length > 12 ? ', …' : ''}`;
  };
  for (const [kind, list] of groups) {
    // Ban events carry ip/cc/host → one line per kind. Analysis events carry their own
    // bulleted lines → the kind's label once, then the lines. Anything else: title — text.
    const bans = list.filter((e) => e.ip);
    const rest = list.filter((e) => !e.ip);
    if (bans.length) {
      lines.push(banLine(kind === 'scanner' ? 'Scanners banned' : kind === 'credentials' ? 'Wrong-credential bans' : kind === 'app_logins' ? 'App-login bans' : 'Banned', bans));
    }
    if (rest.length) {
      const label = kind in KIND_LABELS ? KIND_LABELS[kind as PolicyKind].label : kind;
      lines.push(label);
      for (const e of rest) {
        if (e.text.startsWith('•')) lines.push(e.text);
        else lines.push(`• ${e.title.replace(/^[^:]+: /, '')}${e.text ? ` — ${e.text}` : ''}${e.link ? ` (${e.link.url})` : ''}`);
      }
    }
  }
  if (q.dropped) lines.push(`(${q.dropped} more events not kept)`);
  const n = q.events.length + q.dropped;
  const severity: Severity = q.events.some((e) => e.severity === 'critical') ? 'critical' : q.events.some((e) => e.severity === 'warn') ? 'warn' : 'info';
  return { kind: 'traffic', severity, title: `${siteName}: ${n} event${n === 1 ? '' : 's'} in the last ${duration(windowSeconds)}`, text: lines.join('\n') };
}

export interface QueueStatus {
  type: string;
  min: Severity;
  waiting: number;
  /** Seconds until the digest is due (0 = with the next five-minute job); null when nothing waits. */
  dueInSeconds: number | null;
}

/** What each channel has waiting for its digest (for the settings page). */
export async function queueStatus(env: Env, now: number): Promise<QueueStatus[]> {
  const channels = parseChannels(env);
  if (!channels.length) return [];
  const policy = await resolvePolicy(env);
  const out: QueueStatus[] = [];
  for (const [i, ch] of channels.entries()) {
    const q = await readQueue(env, i);
    const waiting = q ? q.events.length + q.dropped : 0;
    out.push({ type: ch.type, min: ch.min, waiting, dueInSeconds: q && waiting ? Math.max(0, Math.round((q.since + policy.digestSeconds * 1000 - now) / 1000)) : null });
  }
  return out;
}

/**
 * Five-minute hook: send each channel's queue as one digest once its window has passed
 * (the window starts with the first queued event). Returns the number of digests sent.
 */
export async function flushQueues(env: Env, doFetch: Fetch, siteName: string, now: number): Promise<number> {
  const channels = parseChannels(env);
  if (!channels.length) return 0;
  const policy = await resolvePolicy(env);
  let sent = 0;
  for (const [i, ch] of channels.entries()) {
    const q = await readQueue(env, i);
    if (!q) continue;
    if (now - q.since < policy.digestSeconds * 1000) continue;
    await env.STORE.delete(queueKey(i));
    if (!q.events.length && !q.dropped) continue;
    await send(ch as Channel, digestEvent(siteName, q, policy.digestSeconds), doFetch);
    sent += 1;
  }
  return sent;
}
