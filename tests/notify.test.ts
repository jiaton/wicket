import { describe, expect, it } from 'vitest';
import { parseChannels } from '../src/config/channels';
import { emit, flushQueues, type Event } from '../src/notify';
import { FakeAnalytics, FakeKV, fakeNetwork, makeEnv } from './helpers';

const NOW = 1_800_000_000_000;
const warnEvent: Event = { kind: 'credentials', severity: 'warn', title: 'site: banned 1.2.3.4 (US)', text: '3 wrong passwords on nas.', link: { text: 'Unban', url: 'https://nas.example.test/__wicket/unban?x' }, ip: '1.2.3.4', cc: 'US' };
const infoEvent: Event = { kind: 'scanner', severity: 'info', title: 'site: banned 5.6.7.8 (DE)', text: '100 anonymous probes (scanner).', ip: '5.6.7.8', cc: 'DE' };

function setup(notifyJson?: unknown, extra: Record<string, string | undefined> = {}) {
  const kv = new FakeKV();
  const net = fakeNetwork();
  const env = makeEnv(kv, new FakeAnalytics(), { NOTIFY_JSON: notifyJson === undefined ? undefined : JSON.stringify(notifyJson), ...extra });
  return { kv, net, env };
}

describe('parseChannels', () => {
  it('falls back to the TELEGRAM_* pair when NOTIFY_JSON is absent or broken', () => {
    expect(parseChannels(makeEnv(new FakeKV(), new FakeAnalytics()))).toEqual([{ type: 'telegram', min: 'info', batch: false, token: 'bot', chat_id: '1' }]);
    expect(parseChannels(makeEnv(new FakeKV(), new FakeAnalytics(), { NOTIFY_JSON: '{nope' }))).toHaveLength(1);
    expect(parseChannels(makeEnv(new FakeKV(), new FakeAnalytics(), { TELEGRAM_BOT_TOKEN: undefined }))).toEqual([]);
  });

  it('drops incomplete or unknown channels and defaults min/batch', () => {
    const chans = parseChannels(
      makeEnv(new FakeKV(), new FakeAnalytics(), {
        NOTIFY_JSON: JSON.stringify([
          { type: 'ntfy', url: 'https://ntfy.example.test/gate', min: 'warn' },
          { type: 'telegram', token: 't' }, // no chat_id → dropped
          { type: 'pigeon', url: 'x' }, // unknown → dropped
          { type: 'discord', url: 'https://discord.com/api/webhooks/1/abc', batch: true },
        ]),
      }),
    );
    expect(chans.map((c) => [c.type, c.min, c.batch])).toEqual([
      ['ntfy', 'warn', false],
      ['discord', 'info', true],
    ]);
  });
});

describe('emit', () => {
  it('respects each channel threshold and formats per adapter', async () => {
    const { net, env } = setup([
      { type: 'telegram', token: 'bot', chat_id: '1', min: 'info' },
      { type: 'ntfy', url: 'https://ntfy.example.test/gate', min: 'warn' },
      { type: 'discord', url: 'https://discord.com/api/webhooks/1/abc', min: 'critical' },
      { type: 'slack', url: 'https://hooks.slack.com/services/x', min: 'info' },
      { type: 'webhook', url: 'https://hooks.example.test/gate', min: 'info' },
      { type: 'apprise', url: 'https://apprise.example.test/notify/gate', min: 'info', tag: 'home' },
    ]);
    await emit(env, net.doFetch, warnEvent, NOW);
    const by = (host: string) => net.sent.find((s) => s.url.includes(host));
    expect(net.sent.map((s) => new URL(s.url).hostname).sort()).toEqual(['api.telegram.org', 'apprise.example.test', 'hooks.example.test', 'hooks.slack.com', 'ntfy.example.test']);

    const tg = by('telegram')!.body as { text: string; parse_mode: string; reply_markup: { inline_keyboard: { url: string }[][] } };
    expect(tg.parse_mode).toBe('HTML');
    expect(tg.text).toBe('<b>site: banned 1.2.3.4 (US)</b>\n3 wrong passwords on nas.');
    expect(tg.reply_markup.inline_keyboard[0]![0]!.url).toContain('/__wicket/unban');

    const ntfy = by('ntfy')!;
    const h = new Headers(ntfy.init?.headers as HeadersInit);
    expect(h.get('Title')).toBe(warnEvent.title);
    expect(h.get('Priority')).toBe('4');
    expect(h.get('Actions')).toBe('view, Unban, https://nas.example.test/__wicket/unban?x');
    expect(ntfy.body).toBe('3 wrong passwords on nas.');

    expect((by('slack')!.body as { text: string }).text).toContain('<https://nas.example.test/__wicket/unban?x|Unban>');
    expect(by('hooks.example.test')!.body).toMatchObject({ severity: 'warn', title: warnEvent.title, link: warnEvent.link });
    expect(by('apprise')!.body).toMatchObject({ type: 'warning', title: warnEvent.title, tag: 'home' });
  });

  it('a channel with batch: true takes digests; the digest goes out once the window has passed', async () => {
    const { kv, net, env } = setup([
      { type: 'telegram', token: 'bot', chat_id: '1', min: 'info', batch: true },
      { type: 'ntfy', url: 'https://ntfy.example.test/gate', min: 'info' },
    ]);
    await emit(env, net.doFetch, infoEvent, NOW);
    await emit(env, net.doFetch, { ...infoEvent, title: 'site: banned 9.9.9.9 (FR)', ip: '9.9.9.9', cc: 'FR', host: 'nas' }, NOW + 1000);
    // ntfy got both immediately; telegram got nothing yet.
    expect(net.sent.filter((s) => s.url.includes('ntfy'))).toHaveLength(2);
    expect(net.telegram()).toHaveLength(0);
    expect(JSON.parse((await kv.get('nq:0'))!).events).toHaveLength(2);

    // A warn event is digested too on a batch channel; critical is not.
    await emit(env, net.doFetch, warnEvent, NOW + 2000);
    expect(net.telegram()).toHaveLength(0);
    await emit(env, net.doFetch, { ...warnEvent, kind: 'lockdown', severity: 'critical' }, NOW + 3000);
    expect(net.telegram()).toHaveLength(1);

    // Window (1 h by default) not over yet.
    expect(await flushQueues(env, net.doFetch, 'site', NOW + 30 * 60_000)).toBe(0);
    expect(await flushQueues(env, net.doFetch, 'site', NOW + 61 * 60_000)).toBe(1);
    const digest = net.telegram().at(-1)!.body as { text: string };
    expect(digest.text).toContain('<b>site: 3 events in the last 1 h</b>');
    expect(digest.text).toContain('Scanners banned (2): 5.6.7.8 (DE), 9.9.9.9 (FR) nas');
    expect(digest.text).toContain('Wrong-credential bans (1): 1.2.3.4 (US)');
    expect(await kv.get('nq:0')).toBeNull();
    expect(await flushQueues(env, net.doFetch, 'site', NOW + 62 * 60_000)).toBe(0);
  });

  it('a failing channel does not break the others or the caller', async () => {
    const { net, env } = setup([
      { type: 'ntfy', url: 'https://ntfy.example.test/gate' },
      { type: 'slack', url: 'https://hooks.slack.com/services/x' },
    ]);
    const failing = fakeNetwork({ 'ntfy.example.test': () => new Response('boom', { status: 500 }) });
    await emit(env, failing.doFetch, warnEvent, NOW);
    expect(failing.sent).toHaveLength(2);
    void net;
  });
});
