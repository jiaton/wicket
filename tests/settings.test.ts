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
    await emit(env, net.doFetch, scannerBan, NOW + 1500); // the same ban recorded again from another data centre: one line, counted once
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
    expect(body).toContain('telegram (min info): nothing waiting');
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

  it('lists recent bans with working Unban buttons, shows queues and the lockdown, lifts it', async () => {
    const h = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list', NOTIFY_POLICY_JSON: JSON.stringify({ kinds: { scanner: 'digest' } }) });
    const owner = cookieOf(await h.login('owner-pw'));
    // Two bans of different kinds, one queued scanner event, an active lockdown.
    await h.kv.put('ban:198.51.100.1', JSON.stringify({ at: h.time() - 120_000, host: 'nas.example.test', country: 'SG', kind: 'scan' }), { metadata: { kind: 'scan' } });
    await h.kv.put('ban:198.51.100.2', JSON.stringify({ at: h.time() - 60_000, host: 'nas.example.test', country: 'US', kind: 'password' }));
    await emit(h.env, h.net.doFetch, scannerBan, h.time());
    await h.kv.put('lockdown', JSON.stringify({ at: h.time() - 600_000, host: 'nas.example.test', fails: 10 }), { expirationTtl: 3000 });

    const page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('2 total: 1 scanner · 1 unknown');
    expect(page).toContain('2 total, newest first, 30 per page');
    expect(page).not.toContain('page 1 of');
    // Newest first by metadata; a record without metadata (not yet backfilled) sorts last but still shows its details.
    expect(page.indexOf('198.51.100.1')).toBeLessThan(page.indexOf('198.51.100.2'));
    expect(page).toContain('wrong password · nas.example.test · 1 min ago');
    expect(page).toContain('telegram (min info): 1 waiting, digest in about 60 min');
    expect(page).toContain('<b>Active</b>, started 10 min ago');
    expect(page).toContain('value="lift"');

    const unban = await post(h, owner, { action: 'unban', ip: '198.51.100.1' });
    expect(unban.headers.get('location')).toContain('ok=unbanned');
    expect(await h.kv.get('ban:198.51.100.1')).toBeNull();
    expect(h.net.sent.some((s) => s.url.includes('rules/lists') && s.init?.method === 'DELETE' || (s.url.includes('search=198.51.100.1')))).toBe(true);
    expect((h.net.telegram().at(-1)!.body as { text: string }).text).toContain('unbanned 198.51.100.1');
    expect((await post(h, owner, { action: 'unban', ip: '198.51.100.1' })).status).toBe(404);

    const lift = await post(h, owner, { action: 'lift' });
    expect(lift.headers.get('location')).toContain('ok=lifted');
    expect(await h.kv.get('lockdown')).toBeNull();
  });

  it('pages through many bans, newest first', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    for (let i = 1; i <= 35; i++) {
      const ip = `203.0.113.${i}`;
      const at = h.time() - i * 60_000; // .1 is the newest
      await h.kv.put(`ban:${ip}`, JSON.stringify({ at, host: 'nas.example.test', country: 'US', kind: 'scan' }), { metadata: { kind: 'scan', at, host: 'nas.example.test', country: 'US' } });
    }
    const p1 = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(p1).toContain('35 total: 35 scanner');
    expect(p1).toContain('page 1 of 2');
    expect(p1).toContain('<code>203.0.113.1</code>');
    expect(p1).toContain('<code>203.0.113.30</code>');
    expect(p1).not.toContain('<code>203.0.113.31</code>');
    expect(p1).toContain('href="?page=2"');
    const p2 = await (await h.run(h.request('/__wicket/settings?page=2', { headers: { cookie: owner } }))).text();
    expect(p2).toContain('page 2 of 2');
    expect(p2).toContain('<code>203.0.113.31</code>');
    expect(p2).toContain('<code>203.0.113.35</code>');
    expect(p2).not.toContain('<code>203.0.113.30</code>');
    expect((p2.match(/value="unban"/g) ?? []).length).toBe(5 + 1); // five rows + the free-form box
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

describe('hosts on the settings page', () => {
  const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

  it('lists hosts from wicket.yaml, adds and changes hosts live, removes and resets', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'ha.example.test': { mode: 'observe', recipe: 'home-assistant' } }) });
    const owner = cookieOf(await h.login('owner-pw'));
    let page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<b>ha.example.test</b> <small>wicket.yaml');
    expect(page).not.toContain('Reset hosts, access and limits');

    // A new gated host with the api preset, visible to the pipeline at once (same isolate: cache invalidated).
    const add = await post(h, owner, { action: 'host.save', host: 'API.example.test', mode: 'gated', recipe: '', passthrough: 'api' });
    expect(add.status).toBe(303);
    expect(add.headers.get('location')).toContain('ok=host-saved');
    expect((await h.run(h.request('/v1/items', { host: 'api.example.test', headers: { authorization: 'Bearer x', accept: '*/*' } }))).status).toBe(200);
    expect(h.analytics.outcomes().at(-1)).toBe('app');

    // Switch the observe host off, then open.
    await post(h, owner, { action: 'host.save', host: 'ha.example.test', mode: 'off', recipe: '', passthrough: '' });
    expect((await h.run(h.request('/', { host: 'ha.example.test' }))).status).toBe(503);
    await post(h, owner, { action: 'host.save', host: 'ha.example.test', mode: 'open', recipe: '', passthrough: '' });
    expect((await h.run(h.request('/', { host: 'ha.example.test' }))).status).toBe(200);
    expect(h.analytics.outcomes().at(-1)).toBe('open');

    page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<b>api.example.test</b> <small>saved here');
    expect(page).toContain('<b>ha.example.test</b> <small>saved here');
    expect(page).toContain('Reset hosts, access and limits');

    // Remove the override: wicket.yaml's observe entry applies again.
    await post(h, owner, { action: 'host.remove', host: 'ha.example.test' });
    expect((await h.run(h.request('/api/x', { host: 'ha.example.test', headers: { accept: '*/*' } }))).status).toBe(200);
    expect(h.analytics.outcomes().at(-1)).toBe('observe');

    await post(h, owner, { action: 'runtime.reset' });
    expect(await h.kv.get('settings:runtime')).toBeNull();
    expect((await h.run(h.request('/v1/items', { host: 'api.example.test', headers: { authorization: 'Bearer x', accept: '*/*' } }))).status).toBe(401);
  });

  it('rejects hostnames outside the cookie domain, unknown recipes and modes', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    expect((await post(h, owner, { action: 'host.save', host: 'evil.other.test', mode: 'gated' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.save', host: 'x.example.test', mode: 'observe', recipe: 'nope' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.save', host: 'x.example.test', mode: 'sometimes' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.remove', host: 'x.example.test' })).status).toBe(400);
    expect(await h.kv.get('settings:runtime')).toBeNull();
  });
});

describe('access and limits on the settings page', () => {
  const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

  it('saves allow lists, trust and bypass; they apply at once and validate', async () => {
    const h = harness({ ALLOW_IPS: '198.51.100.1' });
    const owner = cookieOf(await h.login('owner-pw'));
    let page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('name="allowIps"');
    expect(page).toContain('>198.51.100.1</textarea>');

    const bad = await post(h, owner, { action: 'access.save', allowIps: '203.0.113.9\nnot-an-ip', allowDns: '', trustSeconds: '3600', bypass: '' });
    expect(bad.status).toBe(400);
    expect(await h.kv.get('settings:runtime')).toBeNull();

    const ok = await post(h, owner, { action: 'access.save', allowIps: '203.0.113.0/24\n2001:db8:1:2::1', allowDns: 'Home.Example.Test', trustSeconds: '3600', bypass: 'nas.example.test/hooks/' });
    expect(ok.headers.get('location')).toContain('ok=access-saved');
    expect((await h.run(h.request('/', { ip: '203.0.113.77', headers: { accept: '*/*' } }))).status).toBe(200); // allowed by the new CIDR
    expect((await h.run(h.request('/', { ip: '198.51.100.1', headers: { accept: '*/*' } }))).status).toBe(401); // the wicket.yaml entry is replaced, not merged
    expect((await h.run(h.request('/hooks/x', { ip: '203.0.113.200', headers: { accept: '*/*' } }))).status).toBe(200); // bypass
    await h.login('owner-pw', {}, { ip: '203.0.113.200' });
    expect(h.kv.store.get('trust:203.0.113.200')!.expires).toBe(h.time() + 3_600_000);
    page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('2001:db8:1:2::1</textarea>');
    expect(page).toContain('home.example.test</textarea>');
    expect(page).toContain('<option value="3600" selected>');
    expect((await post(h, owner, { action: 'access.save', allowIps: '', allowDns: '', trustSeconds: '0', bypass: 'other.test/x' })).status).toBe(400);
  });

  it('saves limits with durations and rejects nonsense', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    const page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('name="limit.failWindowSeconds" value="1d"');
    expect(page).toContain('name="limit.failLimit" value="3"');
    const fields: Record<string, string> = { action: 'limits.save', 'limit.failLimit': '5', 'limit.failWindowSeconds': '12h', 'limit.failGlobalLimit': '10', 'limit.failGlobalWindowSeconds': '10m', 'limit.lockdownSeconds': '1h', 'limit.scanLimit': '100', 'limit.scanWindowSeconds': '60s', 'limit.scanningLimit': '15', 'limit.signatureLimit': '0', 'limit.signatureWindowSeconds': '10m', 'limit.originFailLimit': '5', 'limit.originFailWindowSeconds': '600' };
    expect((await post(h, owner, fields)).headers.get('location')).toContain('ok=limits-saved');
    const { resolveRuntime } = await import('../src/runtime');
    const s = (await resolveRuntime(h.env)).settings;
    expect(s.failLimit).toBe(5);
    expect(s.failWindowSeconds).toBe(43_200);
    expect(s.scanningLimit).toBe(15);
    expect(s.signatureLimit).toBe(0);
    expect(s.originFailWindowSeconds).toBe(600);
    for (let i = 0; i < 4; i++) expect((await h.login('nope', {}, { ip: '203.0.113.9' })).status).toBe(401); // five now, not three
    expect((await post(h, owner, { ...fields, 'limit.scanLimit': 'lots' })).status).toBe(400);
    expect((await post(h, owner, { ...fields, 'limit.failLimit': '0' })).status).toBe(400);
    expect((await post(h, owner, { ...fields, 'limit.lockdownSeconds': '90d' })).status).toBe(400);
  });
});

describe('Cloudflare section', () => {
  const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

  /** A fake Cloudflare account: token ok, no lists yet, zone known, no custom ruleset yet. */
  function account() {
    const state = { lists: [] as { id: string; name: string; kind: string; num_items: number }[], rules: null as null | { id: string; rules: unknown[] }, posts: [] as string[] };
    const json = (result: unknown, status = 200) => new Response(JSON.stringify({ success: status < 400, result, errors: status < 400 ? [] : [{ code: status, message: 'nope' }] }), { status });
    const handlers = {
      'user/tokens/verify': () => json({ id: 'tok', status: 'active' }),
      'analytics_engine/sql': () => new Response(JSON.stringify({ data: [{ n: '42' }] })),
      'rules/lists/0123456789abcdef0123456789abcdef/items': () => json({ operation_id: 'op' }),
      'rules/lists': (req: Request) => {
        if (req.method === 'POST') {
          state.lists.push({ id: '0123456789abcdef0123456789abcdef', name: 'wicket_banned', kind: 'ip', num_items: 0 });
          return json({ id: '0123456789abcdef0123456789abcdef' });
        }
        return json(state.lists);
      },
      'zones?name=': () => json([{ id: 'fedcba9876543210fedcba9876543210', name: 'example.test' }]),
      'rulesets/phases/http_request_firewall_custom/entrypoint': (req: Request) => {
        if (req.method === 'PUT') {
          state.rules = { id: 'rs1', rules: [{ id: 'r1', action: 'block', expression: 'ip.src in $wicket_banned' }] };
          return json(state.rules);
        }
        return state.rules ? json(state.rules) : json(null, 404);
      },
    };
    return { state, handlers };
  }

  it('shows what is missing, creates the list and the WAF rule, and bans then reach the new list', async () => {
    const acc = account();
    const h = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', ZONE: 'example.test', COOKIE_DOMAIN: 'example.test' }, acc.handlers);
    const owner = cookieOf(await h.login('owner-pw'));
    let page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<b>API token</b></td><td>active');
    expect(page).toContain('ok, 42 rows today');
    expect(page).toContain('value="cf.list"');
    expect(page).not.toContain('value="cf.waf"'); // no list yet

    expect((await post(h, owner, { action: 'cf.list' })).headers.get('location')).toContain('ok=cf-list');
    const { resolveRuntime } = await import('../src/runtime');
    expect((await resolveRuntime(h.env)).settings.listId).toBe('0123456789abcdef0123456789abcdef');
    page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<code>wicket_banned</code> · 0 items <small>created here</small>');
    expect(page).toContain('<span class="warn">missing</span>'); // WAF rule
    expect(page).toContain('value="cf.waf"');

    expect((await post(h, owner, { action: 'cf.waf' })).headers.get('location')).toContain('ok=cf-waf');
    expect(acc.state.rules?.rules).toHaveLength(1);
    page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<b>WAF rule</b><br><small>blocks the list on example.test</small></td><td>present');

    // A ban now goes to the list created from the page, without CF_LIST_ID in the secrets.
    for (let i = 0; i < 3; i++) await h.login('nope', {}, { ip: '203.0.113.9' });
    const added = h.net.sent.find((s) => s.url.includes('rules/lists/0123456789abcdef0123456789abcdef/items') && s.init?.method === 'POST');
    expect(added?.body).toEqual([{ ip: '203.0.113.9', comment: expect.stringContaining('wrong passwords') }]);
  });

  it('explains a missing or rejected token instead of guessing', async () => {
    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    const page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('<span class="warn">missing</span>');
    expect(page).toContain('CF_API_TOKEN missing');
    expect((await post(h, owner, { action: 'cf.list' })).status).toBe(400);
    const bad = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc' }, { 'user/tokens/verify': () => new Response(JSON.stringify({ success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] }), { status: 401 }) });
    const owner2 = cookieOf(await bad.login('owner-pw'));
    const page2 = await (await bad.run(bad.request('/__wicket/settings', { headers: { cookie: owner2 } }))).text();
    expect(page2).toContain('<span class="warn">invalid</span> <small>1000: Invalid API Token</small>');
  });
});

describe('custom pass-through rules on the page', () => {
  const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

  it('parses, saves, round-trips and validates the one-line form', async () => {
    const { parsePassthroughSpec, formatPassthroughSpec } = await import('../src/config/hosts');
    const rule = parsePassthroughSpec('headers=Authorization, X-Session; cookies=sid; paths=/api/,/mcp; status=401,403');
    expect(rule).toEqual({ headers: ['authorization', 'x-session'], cookies: ['sid'], params: [], paths: ['/api/', '/mcp'], status: [401, 403] });
    expect(formatPassthroughSpec(rule as never)).toBe('headers=authorization,x-session; cookies=sid; paths=/api/,/mcp; status=401,403');
    expect(parsePassthroughSpec('paths=/api/')).toMatch(/at least one/);
    expect(parsePassthroughSpec('headers=cookie')).toMatch(/not cookie/);
    expect(parsePassthroughSpec('nonsense')).toMatch(/should look like/);
    expect(parsePassthroughSpec('status=9')).toMatch(/status codes/);

    const h = harness();
    const owner = cookieOf(await h.login('owner-pw'));
    expect((await post(h, owner, { action: 'host.save', host: 'app.example.test', mode: 'gated', recipe: '', passthrough: 'custom', spec: 'paths=/x' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.save', host: 'app.example.test', mode: 'gated', recipe: '', passthrough: 'custom', spec: 'cookies=sid; paths=/api/' })).status).toBe(303);
    expect((await h.run(h.request('/api/me', { host: 'app.example.test', headers: { cookie: 'sid=1', accept: '*/*' } }))).status).toBe(200);
    expect((await h.run(h.request('/api/me', { host: 'app.example.test', headers: { accept: '*/*' } }))).status).toBe(401);
    const page = await (await h.run(h.request('/__wicket/settings', { headers: { cookie: owner } }))).text();
    expect(page).toContain('value="cookies=sid; paths=/api/"');
    expect(page).toContain('<option value="custom" selected>');
  });
});
