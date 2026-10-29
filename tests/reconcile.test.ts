import { describe, expect, it } from 'vitest';
import { reconcile, repairEdge } from '../src/cron/reconcile';
import { listAddMany } from '../src/cloudflare/lists';
import { recordBan } from '../src/actions/ban';
import { settings } from '../src/config/settings';
import { backfillBanMetadata, listBans } from '../src/store/bans';
import { FakeAnalytics, FakeKV, fakeNetwork, makeEnv } from './helpers';

const LIST_ENV = { CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list', SITE_NAME: 'test' };

const ban = (kv: FakeKV, ip: string) => kv.put(`ban:${ip}`, JSON.stringify({ at: 1, host: 'nas.example.test', country: 'US', kind: 'password' }));

/** A fake IP list with cursor pagination (one item per page). */
function listServer(items: { id: string; ip: string; comment: string }[]) {
  return {
    'rules/lists/list/items': (req: Request) => {
      const url = new URL(req.url);
      if (req.method === 'GET') {
        const i = Number(url.searchParams.get('cursor') ?? '0');
        const after = i + 1 < items.length ? String(i + 1) : undefined;
        return new Response(JSON.stringify({ result: items.slice(i, i + 1), result_info: { cursors: { after } } }));
      }
      return new Response(JSON.stringify({ result: { operation_id: 'op' } }));
    },
  };
}

describe('listBans', () => {
  it('walks every KV page', async () => {
    const kv = new FakeKV();
    for (const ip of ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5']) await ban(kv, ip);
    await kv.put('fail:9.9.9.9', '1');
    const env = makeEnv(kv, new FakeAnalytics());
    expect((await listBans(env)).map((b) => b.ip).sort()).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5']);
  });
});

describe('backfillBanMetadata', () => {
  it('adds kind metadata to records that lack it', async () => {
    const kv = new FakeKV();
    await kv.put('ban:1.1.1.1', JSON.stringify({ at: 1, host: 'h', country: 'US', kind: 'scan' }));
    await kv.put('ban:2.2.2.2', JSON.stringify({ at: 1, host: 'h', country: 'US', kind: 'token' }), { metadata: { kind: 'token', at: 1, host: 'h', country: 'US' } });
    const env = makeEnv(kv, new FakeAnalytics());
    expect(await backfillBanMetadata(env)).toBe(1);
    expect((await listBans(env)).map((b) => [b.ip, b.kind])).toEqual([['1.1.1.1', 'scan'], ['2.2.2.2', 'token']]);
    expect(await backfillBanMetadata(env)).toBe(0);
  });
});

describe('reconcile', () => {
  it('does nothing without list credentials', async () => {
    const env = makeEnv(new FakeKV(), new FakeAnalytics());
    const net = fakeNetwork();
    expect(await reconcile(env, net.doFetch, 1_800_000_000_000)).toBeNull();
    expect(net.sent).toHaveLength(0);
  });

  it('adds missing KV bans, removes stale wicket items, leaves other writers alone', async () => {
    const kv = new FakeKV();
    await ban(kv, '10.0.0.1'); // in KV, in list → fine
    await ban(kv, '10.0.0.2'); // in KV, not in list → add
    const net = fakeNetwork(
      listServer([
        { id: 'a', ip: '10.0.0.1', comment: 'wicket test: 3 wrong passwords on nas.example.test' },
        { id: 'b', ip: '10.0.0.3', comment: 'wicket test: 3 wrong passwords on nas.example.test' }, // not in KV → remove
        { id: 'c', ip: '10.0.0.4', comment: 'fail2ban home-caddy-auth 2026-10-03T01:00Z' }, // someone else's → keep
      ]),
    );
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);

    const result = await reconcile(env, net.doFetch, 1_800_000_000_000);
    expect(result).toEqual({ added: ['10.0.0.2'], removed: ['10.0.0.3'] });

    const writes = net.sent.filter((s) => s.url.includes('rules/lists') && s.init?.method && s.init.method !== 'GET');
    expect(writes.map((w) => w.init?.method)).toEqual(['POST', 'DELETE']);
    expect(writes[0]!.body).toEqual([{ ip: '10.0.0.2', comment: 'wicket test: restored by reconcile' }]);
    expect(writes[1]!.body).toEqual({ items: [{ id: 'b' }] });

    const tg = net.telegram();
    expect(tg).toHaveLength(1);
    expect(String((tg[0]!.body as { text: string }).text)).toContain('added 1');
    expect(String((tg[0]!.body as { text: string }).text)).toContain('removed 1');
  });

  it('stays quiet when everything agrees', async () => {
    const kv = new FakeKV();
    await ban(kv, '10.0.0.1');
    const net = fakeNetwork(listServer([{ id: 'a', ip: '10.0.0.1', comment: 'wicket test: scanner' }]));
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);
    expect(await reconcile(env, net.doFetch, 1_800_000_000_000)).toEqual({ added: [], removed: [] });
    expect(net.telegram()).toHaveLength(0);
  });

  it('leaves wicket items younger than the grace period alone (KV listings lag behind writes)', async () => {
    const kv = new FakeKV();
    const now = 1_800_000_000_000;
    const net = fakeNetwork(
      listServer([
        { id: 'young', ip: '10.0.0.5', comment: 'wicket test: 3 requests for known scanner paths', created_on: new Date(now - 2 * 60_000).toISOString() },
        { id: 'old', ip: '10.0.0.6', comment: 'wicket test: 3 requests for known scanner paths', created_on: new Date(now - 15 * 60_000).toISOString() },
      ] as never),
    );
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);
    expect(await reconcile(env, net.doFetch, now)).toEqual({ added: [], removed: ['10.0.0.6'] });
  });

  it('gives up without changes when the list cannot be read', async () => {
    const kv = new FakeKV();
    await ban(kv, '10.0.0.1');
    const net = fakeNetwork({ 'rules/lists/list/items': () => new Response('nope', { status: 500 }) });
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);
    expect(await reconcile(env, net.doFetch, 1_800_000_000_000)).toBeNull();
    expect(net.sent.filter((s) => s.init?.method === 'POST' && s.url.includes('rules/lists'))).toHaveLength(0);
  });
});

describe('IP list writes', () => {
  it('retries once after a 429 (one operation per list at a time)', async () => {
    let calls = 0;
    const net = fakeNetwork({ 'rules/lists/list/items': () => (calls++ === 0 ? new Response('{"errors":[{"code":10000}]}', { status: 429 }) : new Response('{"result":{}}')) });
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), LIST_ENV);
    expect(await listAddMany(env, net.doFetch, 'list', [{ ip: '10.0.0.1', comment: 'wicket test: x' }], 0)).toBe(true);
    expect(calls).toBe(2);
    const always429 = fakeNetwork({ 'rules/lists/list/items': () => new Response('busy', { status: 429 }) });
    expect(await listAddMany(env, always429.doFetch, 'list', [{ ip: '10.0.0.1', comment: 'wicket test: x' }], 0)).toBe(false);
  });

  it('a ban whose list call failed is remembered and added by the five-minute repair', async () => {
    const kv = new FakeKV();
    let fail = true;
    const net = fakeNetwork({ 'rules/lists/list/items': () => (fail ? new Response('busy', { status: 429 }) : new Response('{"result":{}}')) });
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);
    const deps = { fetch: net.doFetch, now: () => 1_800_000_000_000 };
    expect(await recordBan(env, deps, settings(env), { ip: '10.0.0.7', host: 'nas.example.test', country: 'US', kind: 'scan', fails: 3 })).toBe(true);
    expect(await kv.get('edgeq')).toBe('["10.0.0.7"]');
    expect(await repairEdge(env, net.doFetch)).toEqual([]); // still failing: kept for next time
    expect(await kv.get('edgeq')).toBe('["10.0.0.7"]');
    fail = false;
    expect(await repairEdge(env, net.doFetch)).toEqual(['10.0.0.7']);
    expect(await kv.get('edgeq')).toBeNull();
    const posts = net.sent.filter((s) => s.url.includes('rules/lists') && s.init?.method === 'POST');
    expect(posts.at(-1)!.body).toEqual([{ ip: '10.0.0.7', comment: 'wicket test: added after a failed list call' }]);
    expect(await repairEdge(env, net.doFetch)).toEqual([]); // nothing pending: one KV read, no list call
    expect(net.sent.filter((s) => s.url.includes('rules/lists') && s.init?.method === 'POST')).toHaveLength(posts.length);
  });
});
