import { parseChannels, RANK, type Channel, type Severity } from '../config/channels';
import type { Env } from '../config/env';
import { send } from './adapters';

export type { Severity } from '../config/channels';
export type Fetch = typeof fetch;

/** One thing worth telling the owner. `text` is plain; adapters do their own markup. */
export interface Event {
  severity: Severity;
  title: string;
  text: string;
  /** A one-click action, e.g. the signed Unban link. */
  link?: { text: string; url: string };
}

const queueKey = (index: number) => `nq:${index}`;

/** Fan an event out to every channel whose threshold it meets; `info` may be batched. */
export async function emit(env: Env, doFetch: Fetch, event: Event): Promise<void> {
  const channels = parseChannels(env);
  await Promise.all(
    channels.map(async (ch, i) => {
      if (RANK[event.severity] < RANK[ch.min]) return;
      if (ch.batch && event.severity === 'info') return enqueue(env, i, event);
      await send(ch, event, doFetch);
    }),
  );
}

async function enqueue(env: Env, index: number, event: Event): Promise<void> {
  const key = queueKey(index);
  let queue: Event[] = [];
  try {
    queue = JSON.parse((await env.STORE.get(key)) ?? '[]') as Event[];
  } catch {
    queue = [];
  }
  queue.push(event);
  await env.STORE.put(key, JSON.stringify(queue.slice(-50)), { expirationTtl: 86_400 });
}

/** Cron hook: turn each channel's queued `info` events into one digest message. Returns digests sent. */
export async function flushQueues(env: Env, doFetch: Fetch, siteName: string): Promise<number> {
  let sent = 0;
  for (const [i, ch] of parseChannels(env).entries()) {
    if (!ch.batch) continue;
    const raw = await env.STORE.get(queueKey(i));
    if (!raw) continue;
    let queue: Event[] = [];
    try {
      queue = JSON.parse(raw) as Event[];
    } catch {
      queue = [];
    }
    await env.STORE.delete(queueKey(i));
    if (!queue.length) continue;
    const lines = queue.map((e) => `• ${e.title}${e.text ? ` — ${e.text}` : ''}${e.link ? ` (${e.link.url})` : ''}`);
    await send(ch as Channel, { severity: 'info', title: `${siteName}: ${queue.length} event${queue.length === 1 ? '' : 's'}`, text: lines.join('\n') }, doFetch);
    sent += 1;
  }
  return sent;
}
