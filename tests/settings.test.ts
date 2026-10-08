import { describe, expect, it } from 'vitest';
import { COOKIE_NAME } from '../src/core/crypto';
import { DEFAULT_POLICY, mergePolicy } from '../src/config/notifications';
import { emit, flushQueues } from '../src/notify';
import { resolvePolicy } from '../src/notify/policy';
import { FakeAnalytics, FakeKV, fakeNetwork, harness, makeEnv } from './helpers';

const NOW = 1_800_000_000_000;
const scannerBan = { kind: 'scanner' as const, severity: 'info' as const, title: 't: banned 1.1.1.1 (SG)', text: 'probes', ip: '1.1.1.1', cc: 'SG', host: 'nas' };
const credentialBan = { kind: 'credentials' as const, severity: 'warn' as const, title: 't: banned 2.2.2.2 (US)', text: '3 wrong passwords', ip: '2.2.2.2', cc: 'US', host: 'nas' };

describe('notification policy', () => {
  it('merges defaults ← config ← saved settings and ignores junk', async () => {
    expect(mergePolicy(DEFAULT_POLICY, '{nope')).toEqual(DEFAULT_POLICY);
    expect(mergePolicy(DEFAULT_POLICY, { kinds: { scanner: 'off', bogus: 'off', traffic: 'sometimes' }, digestSeconds: 10 })).toEqual({
      ...DEFAULT_POLICY,
      kinds: { ...DEFAULT_POLICY.kinds, scanner: 'off' },
    });

    const kv = new FakeKV();
    const env = makeEnv(kv, new FakeAnalytics(), { NOTIFY_POLICY_JSON: JSON.stringify({ kinds: { scanner: 'off' }, digestSeconds: 900 }) });
    expect(await resolvePolicy(env)).toMatchObject({ source: 'config', digestSeconds: 900, kinds: { scanner: 'off', credentials: 'immediate' } });
    await kv.put('settings:notify', JSON.stringify({ kinds: { scanner: 'digest' } }));
    expect(await resolvePolicy(env)).toMatchObject({ source: 'saved', digestSeconds: 900, kinds: { scanner: 'digest' } });
  });

  it('routes by kind: scanner bans digested, credential bans immediate, off dropped', async () => {
    const kv = new FakeKV();
    const net = fakeNetwork();
    const env = makeEnv(kv, new FakeAnalytics(), { NOTIFY_POLICY_JSON: JSON.stringify({ kinds: { scanner: 'digest', unban: 'off' }, digestSeconds: 1800 }) });
    await emit(env, net.doFetch, scannerBan, NOW);
    await emit(env, net.doFetch, { ...scannerBan, ip: '1.1.1.2' }, NOW + 1000);
    await emit(env, net.doFetch, credentialBan, NOW + 2000);
    await emit(env, net.doFetch, { kind: 'unban', severity: 'info', title: 't: unbanned', text: '' }, NOW + 3000);
    expect(net.telegram().map((m) => (m.body as { text: string }).text)).toEqual(['<b>t: banned 2.2.2.2 (US)</b>\n3 wrong passwords']);

    expect(await flushQueues(env, net.doFetch, 't', NOW + 20 * 60_000)).toBe(0);
    expect(await flushQueues(env, net.doFetch, 't', NOW + 31 * 60_000)).toBe(1);
    const digest = (net.telegram().at(-1)!.body as { text: string }).text;
    expect(digest).toContain('2 events in the last 30 min');
    expect(digest).toContain('Scanners banned (2): 1.1.1.1 (SG) nas, 1.1.1.2 (SG) nas');
  });
});

describe('/__wicket/settings', () => {
  const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(
      h.request('/__wicket/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
        body: new URLSearchParams(fields),
      }),
    );

  it('is owner-only', async () => {
    const h = harness();
    expect((await h.run(h.request('/__wicket/settings'))).status).toBe(401);
    const friend = cookieOf(await h.login('friend-pw'));
    expect(friend).toContain(COOKIE_NAME);
    expect((await h.run(h.request('/__wicket/settings', { headers: { cookie: friend } }))).status).toBe(403);
    const owner = cookieOf(await h.login('owner-pw'));
    const res = await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }));
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('name="kind.scanner"');
    expect(body).toContain('Channels in use: telegram');
    expect(h.analytics.outcomes().at(-1)).toBe('admin');
  });

  it('saves, applies, resets and sends a test message', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));

    const saved = await post(h, owner, { action: 'save', 'kind.scanner': 'off', 'kind.credentials': 'digest', digest: '900' });
    expect(saved.status).toBe(303);
    expect(saved.headers.get('location')).toContain('/__wicket/settings?ok=saved');
    expect(await resolvePolicy(h.env)).toMatchObject({ source: 'saved', digestSeconds: 900, kinds: { scanner: 'off', credentials: 'digest', lockdown: 'immediate' } });

    const before = h.net.telegram().length;
    await emit(h.env, h.net.doFetch, scannerBan, h.time());
    await emit(h.env, h.net.doFetch, credentialBan, h.time());
    expect(h.net.telegram()).toHaveLength(before);
    expect(JSON.parse((await h.kv.get('nq:0'))!).events).toHaveLength(1);

    const page = await (await h.run(h.request('/__wicket/settings?ok=saved', { headers: { cookie: owner } }))).text();
    expect(page).toContain('Saved.');
    expect(page).toContain('override wicket.yaml');

    await post(h, owner, { action: 'test' });
    expect((h.net.telegram().at(-1)!.body as { text: string }).text).toContain('test message');

    await post(h, owner, { action: 'reset' });
    expect(await h.kv.get('settings:notify')).toBeNull();
    expect((await resolvePolicy(h.env)).source).toBe('config');
  });

  it('rejects cross-site posts', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    const res = await h.run(
      h.request('/__wicket/settings', { method: 'POST', headers: { cookie: owner, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'cross-site' }, body: new URLSearchParams({ action: 'reset' }) }),
    );
    expect(res.status).toBe(403);
  });
});
