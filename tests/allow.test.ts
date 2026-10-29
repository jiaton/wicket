import { describe, expect, it } from 'vitest';
import { settings } from '../src/config/settings';
import { createAllowCheck, DNS_TTL_MS, resolveAddresses } from '../src/pipeline/allow';
import { FakeAnalytics, FakeKV, fakeNetwork, harness, makeEnv } from './helpers';

const dns = (answers: Record<string, string[]>, fail = false) => ({
  'cloudflare-dns.com': (req: Request) => {
    if (fail) return new Response('nope', { status: 502 });
    const url = new URL(req.url);
    const name = url.searchParams.get('name')!;
    const type = url.searchParams.get('type');
    const list = (answers[name] ?? []).filter((a) => (type === 'AAAA') === a.includes(':'));
    return new Response(JSON.stringify({ Answer: list.map((data) => ({ type: data.includes(':') ? 28 : 1, data })) }));
  },
});

describe('allow_dns', () => {
  it('resolves A and AAAA over DoH and tolerates failures', async () => {
    const net = fakeNetwork(dns({ 'home.example.test': ['203.0.113.9', '2001:db8::9'] }));
    expect(await resolveAddresses(net.doFetch, 'home.example.test')).toEqual(['203.0.113.9', '2001:db8::9']);
    expect(await resolveAddresses(fakeNetwork(dns({}, true)).doFetch, 'home.example.test')).toBeNull(); // resolver unreachable
    expect(await resolveAddresses(net.doFetch, 'gone.example.test')).toEqual([]); // answered, no records
  });

  it('caches the answer for five minutes and keeps it when the resolver fails', async () => {
    let now = 1_800_000_000_000;
    let failing = false;
    let lookups = 0;
    const net = fakeNetwork({
      'cloudflare-dns.com': (req) => {
        lookups += 1;
        return dns({ 'home.example.test': ['203.0.113.9'] }, failing)['cloudflare-dns.com'](req);
      },
    });
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), { ALLOW_DNS: 'home.example.test' });
    const cfg = settings(env);
    const allowed = createAllowCheck({ fetch: net.doFetch, now: () => now });
    expect(await allowed(env, cfg, '203.0.113.9')).toBe(true);
    expect(await allowed(env, cfg, '203.0.113.10')).toBe(false);
    expect(lookups).toBe(2); // A + AAAA, once
    now += DNS_TTL_MS + 1;
    failing = true;
    expect(await allowed(env, cfg, '203.0.113.9')).toBe(true); // stale answer kept
    expect(lookups).toBe(4);
  });

  it('lets a request from the resolved address through without a cookie, and logs it in without counting', async () => {
    const h = harness({ ALLOW_DNS: 'home.example.test' }, dns({ 'home.example.test': ['203.0.113.9'] }));
    expect(await (await h.run(h.request('/x', { ip: '203.0.113.9' }))).text()).toBe('origin:/x');
    expect((await h.run(h.request('/x', { ip: '203.0.113.10' }))).status).toBe(401);
    expect(h.analytics.outcomes()).toEqual(['allow', 'reject']);
    expect((await h.login('nope', {}, { ip: '203.0.113.9' })).status).toBe(401);
    expect(await h.kv.get('fail:203.0.113.9')).toBeNull();
  });
});
