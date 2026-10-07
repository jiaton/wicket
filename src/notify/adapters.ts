import type { Channel } from '../config/channels';
import type { Event, Fetch } from './index';

/**
 * One adapter per channel type; each is a single HTTP call and never throws.
 * Adding a channel: extend ChannelType in config/channels.ts, add a case here, add a test.
 */
export async function send(ch: Channel, e: Event, doFetch: Fetch): Promise<void> {
  switch (ch.type) {
    case 'telegram':
      return telegram(ch, e, doFetch);
    case 'ntfy':
      return ntfy(ch, e, doFetch);
    case 'discord':
      return discord(ch, e, doFetch);
    case 'slack':
      return slack(ch, e, doFetch);
    case 'apprise':
      return apprise(ch, e, doFetch);
    case 'webhook':
      return webhook(ch, e, doFetch);
  }
}

export const escapeHtml = (s: string) =>
  s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c] ?? c);

const json = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

async function post(doFetch: Fetch, url: string, init: RequestInit, label: string): Promise<void> {
  try {
    const res = await doFetch(url, init);
    if (!res.ok) console.warn(`${label} failed`, res.status, (await res.text()).slice(0, 200));
  } catch (err) {
    console.warn(`${label} unreachable`, String(err));
  }
}

function telegram(ch: Channel, e: Event, doFetch: Fetch) {
  const body: Record<string, unknown> = {
    chat_id: ch.chat_id,
    text: `<b>${escapeHtml(e.title)}</b>${e.text ? `\n${escapeHtml(e.text)}` : ''}`,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };
  if (e.link) body.reply_markup = { inline_keyboard: [[{ text: e.link.text, url: e.link.url }]] };
  return post(doFetch, `https://api.telegram.org/bot${ch.token}/sendMessage`, json(body), 'telegram');
}

function ntfy(ch: Channel, e: Event, doFetch: Fetch) {
  const headers: Record<string, string> = {
    Title: e.title,
    Priority: e.severity === 'critical' ? '5' : e.severity === 'warn' ? '4' : '3',
    Tags: e.severity === 'critical' ? 'rotating_light' : e.severity === 'warn' ? 'no_entry' : 'information_source',
  };
  if (e.link) headers.Actions = `view, ${e.link.text}, ${e.link.url}`;
  return post(doFetch, ch.url!, { method: 'POST', headers, body: e.text }, 'ntfy');
}

function discord(ch: Channel, e: Event, doFetch: Fetch) {
  const content = `**${e.title}**${e.text ? `\n${e.text}` : ''}${e.link ? `\n${e.link.text}: ${e.link.url}` : ''}`.slice(0, 2000);
  return post(doFetch, ch.url!, json({ content }), 'discord');
}

function slack(ch: Channel, e: Event, doFetch: Fetch) {
  const text = `*${e.title}*${e.text ? `\n${e.text}` : ''}${e.link ? `\n<${e.link.url}|${e.link.text}>` : ''}`;
  return post(doFetch, ch.url!, json({ text }), 'slack');
}

/** Apprise API (`/notify/<key>`): type is info | warning | failure. */
function apprise(ch: Channel, e: Event, doFetch: Fetch) {
  const type = e.severity === 'critical' ? 'failure' : e.severity === 'warn' ? 'warning' : 'info';
  const body = `${e.text}${e.link ? `\n${e.link.text}: ${e.link.url}` : ''}`;
  return post(doFetch, ch.url!, json({ title: e.title, body, type, ...(ch.tag ? { tag: ch.tag } : {}) }), 'apprise');
}

function webhook(ch: Channel, e: Event, doFetch: Fetch) {
  return post(doFetch, ch.url!, json({ severity: e.severity, title: e.title, text: e.text, link: e.link ?? null, at: new Date().toISOString() }), 'webhook');
}
