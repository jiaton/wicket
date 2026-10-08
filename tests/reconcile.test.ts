import { describe, expect, it } from 'vitest';
import { reconcile } from '../src/cron/reconcile';
import { listBans } from '../src/store/bans';
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

  it('gives up without changes when the list cannot be read', async () => {
    const kv = new FakeKV();
    await ban(kv, '10.0.0.1');
    const net = fakeNetwork({ 'rules/lists/list/items': () => new Response('nope', { status: 500 }) });
    const env = makeEnv(kv, new FakeAnalytics(), LIST_ENV);
    expect(await reconcile(env, net.doFetch, 1_800_000_000_000)).toBeNull();
    expect(net.sent.filter((s) => s.init?.method === 'POST' && s.url.includes('rules/lists'))).toHaveLength(0);
  });
});
