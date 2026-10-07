import type { Env } from './env';

export type Severity = 'info' | 'warn' | 'critical';
export const RANK: Record<Severity, number> = { info: 0, warn: 1, critical: 2 };

export type ChannelType = 'telegram' | 'ntfy' | 'discord' | 'slack' | 'webhook' | 'apprise';

export interface Channel {
  type: ChannelType;
  /** Lowest severity this channel receives. Default: info. */
  min: Severity;
  /** When true, `info` events are queued in KV and sent as one digest by the cron (≤5 min). */
  batch: boolean;
  /** telegram */
  token?: string;
  chat_id?: string;
  /** ntfy / discord / slack / webhook / apprise: the POST target. */
  url?: string;
  /** apprise: optional tag(s) for the Apprise API. */
  tag?: string;
}

const isSeverity = (v: unknown): v is Severity => v === 'info' || v === 'warn' || v === 'critical';
const TYPES: ChannelType[] = ['telegram', 'ntfy', 'discord', 'slack', 'webhook', 'apprise'];

/**
 * Channels from the NOTIFY_JSON secret (an array of channel objects). Without it, the
 * legacy TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID pair becomes one Telegram channel that
 * receives everything, so a minimal deployment needs no channel config at all.
 */
export function parseChannels(env: Env): Channel[] {
  if (env.NOTIFY_JSON) {
    try {
      const raw = JSON.parse(env.NOTIFY_JSON) as unknown;
      if (Array.isArray(raw)) {
        return raw.flatMap((c): Channel[] => {
          if (!c || typeof c !== 'object') return [];
          const r = c as Record<string, unknown>;
          if (!TYPES.includes(r.type as ChannelType)) return [];
          const ch: Channel = {
            type: r.type as ChannelType,
            min: isSeverity(r.min) ? r.min : 'info',
            batch: r.batch === true,
            token: typeof r.token === 'string' ? r.token : undefined,
            chat_id: r.chat_id !== undefined ? String(r.chat_id) : undefined,
            url: typeof r.url === 'string' ? r.url : undefined,
            tag: typeof r.tag === 'string' ? r.tag : undefined,
          };
          const complete = ch.type === 'telegram' ? Boolean(ch.token && ch.chat_id) : Boolean(ch.url);
          return complete ? [ch] : [];
        });
      }
    } catch {
      console.warn('NOTIFY_JSON is not valid JSON; falling back to TELEGRAM_* vars');
    }
  }
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    return [{ type: 'telegram', min: 'info', batch: false, token: env.TELEGRAM_BOT_TOKEN, chat_id: env.TELEGRAM_CHAT_ID }];
  }
  return [];
}
