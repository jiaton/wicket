import { describe, expect, it } from 'vitest';
import { COOKIE_NAME } from '../src/core/crypto';
import { matchToken } from '../src/config/tokens';
import { safeNext } from '../src/core/credentials';
import { ipAllowed } from '../src/core/ip';
import { createHandler } from '../src/pipeline/handler';
import { ctx, harness } from './helpers';

const cookieFrom = (res: Response) => {
  const raw = res.headers.get('set-cookie') ?? '';
  expect(raw).toContain('HttpOnly');
  expect(raw).toContain('Secure');
  expect(raw).toContain('Domain=example.test');
  return raw.split(';')[0]!;
};

describe('anonymous requests', () => {
  it('get the password page instead of the origin', async () => {
    const h = harness();
    const res = await h.run(h.request('/admin?x=1'));
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).toContain('nas.example.test');
    expect(body).toContain('value="/admin?x=1"');
    expect(h.net.origin).toHaveLength(0);
    expect(h.analytics.outcomes()).toEqual(['reject']);
  });

  it('get JSON 401 for non-browser calls', async () => {
    const h = harness();
    const res = await h.run(h.request('/api', { headers: { accept: 'application/json' } }));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'password required' });
  });
});

describe('password login', () => {
  it('sets a cookie, redirects to next, and later passes through without the cookie', async () => {
    const h = harness();
    const res = await h.login('owner-pw');
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('https://nas.example.test/dash');
    const cookie = cookieFrom(res);
    expect(cookie.startsWith(`${COOKIE_NAME}=owner.`)).toBe(true);

    const page = await h.run(h.request('/dash', { headers: { cookie: `a=1; ${cookie}; b=2` } }));
    expect(await page.text()).toBe('origin:/dash');
    expect(h.net.origin[0]!.headers.get('cookie')).toBe('a=1; b=2');
    expect(h.analytics.outcomes()).toEqual(['login', 'pass']);
  });

  it('fails closed when the secrets are missing (the literal "undefined" must never log in)', async () => {
    const h = harness({ OWNER_PASSWORD: undefined as unknown as string });
    expect((await h.login('undefined')).status).toBe(503);
    expect((await h.login('owner-pw')).status).toBe(503);
    expect(await h.kv.get('fail:203.0.113.5')).toBeNull();
    const noSecret = harness({ COOKIE_SECRET: undefined as unknown as string });
    expect((await noSecret.login('owner-pw')).status).toBe(503);
  });

  it('accepts the friend password as a separate role', async () => {
    const h = harness();
    expect(cookieFrom(await h.login('friend-pw')).startsWith(`${COOKIE_NAME}=friend.`)).toBe(true);
  });

  it('expired cookies fall back to the password page', async () => {
    const h = harness({ COOKIE_DAYS: '1' });
    const cookie = cookieFrom(await h.login('owner-pw'));
    h.advance(2 * 86_400_000);
    expect((await h.run(h.request('/', { headers: { cookie } }))).status).toBe(401);
  });

  it('refuses cross-site posts, honeypot fills and open redirects', async () => {
    const h = harness();
    const cross = await h.run(
      h.request('/__wicket/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'cross-site' },
        body: new URLSearchParams({ password: 'owner-pw' }),
      }),
    );
    expect(cross.status).toBe(403);
    const res = await h.login('owner-pw', { next: 'https://evil.test/' });
    expect(res.headers.get('location')).toBe('https://nas.example.test/');
    expect(safeNext('//evil')).toBe('/');
    expect(safeNext('/__wicket/login')).toBe('/');
    expect(safeNext('/ok?x=1')).toBe('/ok?x=1');
  });
});

describe('three strikes', () => {
  it('bans the address, notifies Telegram with an unban link, and the link lifts the ban', async () => {
    const h = harness();
    expect((await h.login('nope')).status).toBe(401);
    expect(await (await h.login('nope')).text()).toContain('1 attempt left');
    const third = await h.login('nope');
    expect(third.status).toBe(403);
    expect(await h.kv.get('ban:203.0.113.5')).toContain('"host":"nas.example.test"');

    const tg = h.net.telegram();
    expect(tg).toHaveLength(1);
    const msg = tg[0]!.body as { text: string; reply_markup: { inline_keyboard: { url: string }[][] } };
    expect(msg.text).toContain('203.0.113.5');
    const link = msg.reply_markup.inline_keyboard[0]![0]!.url;
    expect(link).toMatch(/^https:\/\/nas\.example\.test\/__wicket\/unban\?ip=203\.0\.113\.5&exp=\d+&sig=[0-9a-f]{64}$/);

    // Banned: even the right password is refused, and any page is 403.
    expect((await h.login('owner-pw')).status).toBe(403);
    expect((await h.run(h.request('/'))).status).toBe(403);

    // A forged link is rejected; the real one works and resets the counter.
    const forged = await h.run(h.request(new URL(link.replace(/sig=.{4}/, 'sig=0000')).pathname + new URL(link.replace(/sig=.{4}/, 'sig=0000')).search));
    expect(forged.status).toBe(400);
    const lifted = await h.run(h.request(new URL(link).pathname + new URL(link).search, { ip: '198.51.100.9' }));
    expect(lifted.status).toBe(200);
    expect(await h.kv.get('ban:203.0.113.5')).toBeNull();
    expect((await h.login('owner-pw')).status).toBe(303);
    expect(h.net.telegram()).toHaveLength(2);
  });

  it('a correct password clears earlier failures', async () => {
    const h = harness();
    await h.login('nope');
    await h.login('nope');
    expect((await h.login('owner-pw')).status).toBe(303);
    expect(await h.kv.get('fail:203.0.113.5')).toBeNull();
  });

  it('adds the IP to the Cloudflare list when configured', async () => {
    const h = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list' });
    for (let i = 0; i < 3; i++) await h.login('nope');
    const cf = h.net.sent.find((s) => s.url.includes('rules/lists/list/items') && s.init?.method === 'POST');
    expect(cf?.init?.method).toBe('POST');
    expect(cf?.body).toEqual([{ ip: '203.0.113.5', comment: expect.stringContaining('nas.example.test') }]);
    expect((h.net.telegram()[0]!.body as { text: string }).text).toContain('IP list');
  });
});

describe('allow list and bypass', () => {
  it('lets an allow-listed address log in for a cookie, without counting wrong passwords', async () => {
    const h = harness({ ALLOW_IPS: '203.0.113.5' });
    for (let i = 0; i < 4; i++) expect((await h.login('nope')).status).toBe(401);
    expect(await h.kv.get('fail:203.0.113.5')).toBeNull();
    expect(await h.kv.get('ban:203.0.113.5')).toBeNull();
    const res = await h.login('owner-pw');
    expect(res.status).toBe(303);
    expect(res.headers.get('set-cookie')).toContain('__wicket=owner.');
  });


  it('passes allowed IPs and bypass prefixes without a cookie', async () => {
    const h = harness({ ALLOW_IPS: '10.0.0.0/8, 203.0.113.77', BYPASS_PREFIXES: 'ha.example.test/api/webhook/' });
    expect(await (await h.run(h.request('/x', { ip: '10.9.8.7' }))).text()).toBe('origin:/x');
    expect(await (await h.run(h.request('/x', { ip: '203.0.113.77' }))).text()).toBe('origin:/x');
    expect(await (await h.run(h.request('/api/webhook/abc', { host: 'ha.example.test' }))).text()).toBe('origin:/api/webhook/abc');
    expect((await h.run(h.request('/api/other', { host: 'ha.example.test' }))).status).toBe(401);
    expect((await h.run(h.request('/api/webhook/abc'))).status).toBe(401);
    expect(h.analytics.outcomes()).toEqual(['allow', 'allow', 'bypass', 'reject', 'reject']);
  });

  it("lets Let's Encrypt HTTP-01 validation through anonymously on every host, unless banned", async () => {
    const h = harness();
    const res = await h.run(h.request('/.well-known/acme-challenge/tok3n', { ip: '66.133.109.36', headers: { accept: '*/*' } }));
    expect(await res.text()).toBe('origin:/.well-known/acme-challenge/tok3n');
    expect((await h.run(h.request('/.well-known/other', { ip: '66.133.109.36', headers: { accept: '*/*' } }))).status).toBe(401);
    await h.kv.put('ban:66.133.109.36', '{}');
    expect((await h.run(h.request('/.well-known/acme-challenge/tok3n', { ip: '66.133.109.36', headers: { accept: '*/*' } }))).status).toBe(403);
    expect(h.analytics.outcomes()).toEqual(['bypass', 'reject', 'banned']);
  });

  it('ipAllowed handles CIDRs and garbage', () => {
    expect(ipAllowed('192.168.1.9', ['192.168.1.0/24'])).toBe(true);
    expect(ipAllowed('192.168.2.9', ['192.168.1.0/24'])).toBe(false);
    expect(ipAllowed('2001:db8::1', ['2001:db8::1'])).toBe(true);
    expect(ipAllowed('2001:db8::1', ['192.168.1.0/24', 'junk/99'])).toBe(false);
  });
});

describe('API tokens', () => {
  const tokens = { API_TOKENS: 'ha:tok-ha@ha.example.test|ha2.example.test, any:tok-any' };

  it('accepts header, query and bearer carriers and strips them before the origin', async () => {
    const h = harness(tokens);
    const viaHeader = await h.run(h.request('/api/x', { host: 'ha.example.test', headers: { 'x-wicket-token': 'tok-ha', accept: 'application/json' } }));
    expect(await viaHeader.text()).toBe('origin:/api/x');
    expect(h.net.origin[0]!.headers.has('x-wicket-token')).toBe(false);

    const viaQuery = await h.run(h.request('/hook?wicket_token=tok-any&a=1', { headers: { accept: '*/*' } }));
    expect(await viaQuery.text()).toBe('origin:/hook');
    expect(new URL(h.net.origin[1]!.url).search).toBe('?a=1');

    const viaBearer = await h.run(h.request('/api', { headers: { authorization: 'Bearer tok-any', accept: '*/*' } }));
    expect(viaBearer.status).toBe(200);
    // The origin validates the same bearer itself (tac daemon), so it must survive.
    expect(h.net.origin[2]!.headers.get('authorization')).toBe('Bearer tok-any');
    expect(h.analytics.outcomes()).toEqual(['token', 'token', 'token']);
  });

  it('lets CORS preflights through without credentials, but not banned addresses', async () => {
    const h = harness();
    const preflight = await h.run(
      h.request('/api/x', { method: 'OPTIONS', headers: { origin: 'https://app.example.test', 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization', accept: '*/*' } }),
    );
    expect(preflight.status).toBe(200);
    expect(h.net.origin[0]!.method).toBe('OPTIONS');
    expect(h.net.origin[0]!.headers.get('access-control-request-headers')).toBe('authorization');
    expect(h.analytics.outcomes()).toEqual(['preflight']);

    await h.kv.put('ban:203.0.113.5', '{}');
    expect((await h.run(h.request('/api/x', { method: 'OPTIONS', headers: { accept: '*/*' } }))).status).toBe(403);
  });

  it('scopes tokens to hosts and punishes explicit wrong tokens but not foreign bearers', async () => {
    const h = harness(tokens);
    expect((await h.run(h.request('/api', { host: 'nas.example.test', headers: { 'x-wicket-token': 'tok-ha', accept: '*/*' } }))).status).toBe(401);
    expect((await h.run(h.request('/api', { headers: { 'x-wicket-token': 'wrong', accept: '*/*' } }))).status).toBe(401);
    expect(await h.kv.get('fail:203.0.113.5')).toBe('2');

    const foreign = await h.run(h.request('/api', { headers: { authorization: 'Bearer some-ha-token', accept: '*/*' } }));
    expect(foreign.status).toBe(401);
    expect(await h.kv.get('fail:203.0.113.5')).toBe('2');

    expect((await h.run(h.request('/api', { headers: { 'x-wicket-token': 'wrong', accept: '*/*' } }))).status).toBe(403);
    expect(await h.kv.get('ban:203.0.113.5')).toContain('"kind":"token"');
    expect((h.net.telegram()[0]!.body as { text: string }).text).toContain('API tokens');
  });

  it('matchToken', () => {
    const list = [
      { name: 'a', token: 'x', hosts: ['h1'] },
      { name: 'b', token: 'y', hosts: [] },
    ];
    expect(matchToken('x', 'h1', list)?.name).toBe('a');
    expect(matchToken('x', 'h2', list)).toBeNull();
    expect(matchToken('y', 'h2', list)?.name).toBe('b');
    expect(matchToken('z', 'h1', list)).toBeNull();
  });
});

describe('app token headers', () => {
  it('lets registered x-access-token / X-API-Key values through untouched and punishes wrong ones', async () => {
    const h = harness({ API_TOKENS: 'money:mb-token@money.example.test, tennis:tn-key@tennis.example.test' });
    const mcp = await h.run(h.request('/mcp', { host: 'money.example.test', method: 'POST', headers: { 'x-access-token': 'mb-token', accept: 'application/json' }, body: '{}' }));
    expect(await mcp.text()).toBe('origin:/mcp');
    expect(h.net.origin[0]!.headers.get('x-access-token')).toBe('mb-token');

    const tennis = await h.run(h.request('/api/slots', { host: 'tennis.example.test', headers: { 'X-API-Key': 'tn-key', accept: '*/*' } }));
    expect(tennis.status).toBe(200);
    expect(h.net.origin[1]!.headers.get('x-api-key')).toBe('tn-key');

    // The money MCP's URL-only form: ?token= passes and stays in the URL for the origin.
    const viaQuery = await h.run(h.request('/mcp?token=mb-token', { host: 'money.example.test', headers: { accept: '*/*' } }));
    expect(await viaQuery.text()).toBe('origin:/mcp');
    expect(new URL(h.net.origin[2]!.url).searchParams.get('token')).toBe('mb-token');

    for (let i = 0; i < 3; i++) await h.run(h.request('/mcp', { host: 'money.example.test', headers: { 'x-access-token': 'guess', accept: '*/*' } }));
    expect(await h.kv.get('ban:203.0.113.5')).not.toBeNull();
  });
});

describe('rotating-IP brute force', () => {
  it('locks password entry after the global limit and the Telegram link lifts it', async () => {
    const h = harness({ FAIL_GLOBAL_LIMIT: '4', FAIL_LIMIT: '3' });
    // Four different addresses, one wrong password each: no per-IP ban, but the global counter trips.
    for (const ip of ['1.1.1.1', '2.2.2.2', '3.3.3.3']) expect((await h.login('nope', {}, { ip })).status).toBe(401);
    expect(await h.kv.get('lockdown')).toBeNull();
    expect((await h.login('nope', {}, { ip: '4.4.4.4' })).status).toBe(401);
    expect(await h.kv.get('lockdown')).toContain('"fails":4');
    for (const ip of ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4']) expect(await h.kv.get(`ban:${ip}`)).toBeNull();

    // Locked: even the right password from a fresh address is refused, tokens too.
    const locked = await h.login('owner-pw', {}, { ip: '5.5.5.5' });
    expect(locked.status).toBe(403);
    expect(await locked.text()).toContain('paused');
    const tokenTry = await h.run(h.request('/x', { ip: '6.6.6.6', headers: { 'x-wicket-token': 'whatever', accept: '*/*' } }));
    expect(tokenTry.status).toBe(403);
    expect(await h.kv.get('fail:6.6.6.6')).toBeNull();

    // Existing sessions and allow-listed addresses are unaffected.
    const h2 = harness({ ALLOW_IPS: '9.9.9.9' });
    const cookie = cookieFrom(await h2.login('owner-pw'));
    await h2.kv.put('lockdown', '{}');
    expect((await h2.run(h2.request('/dash', { headers: { cookie } }))).status).toBe(200);
    expect((await h2.run(h2.request('/dash', { ip: '9.9.9.9' }))).status).toBe(200);

    const tg = h.net.telegram();
    expect(tg).toHaveLength(1);
    const msg = tg[0]!.body as { text: string; reply_markup: { inline_keyboard: { url: string }[][] } };
    expect(msg.text).toContain('lockdown');
    const link = new URL(msg.reply_markup.inline_keyboard[0]![0]!.url);
    expect(link.searchParams.get('ip')).toBe('*');
    expect((await h.run(h.request(link.pathname + link.search, { ip: '7.7.7.7' }))).status).toBe(200);
    expect(await h.kv.get('lockdown')).toBeNull();
    expect((await h.login('owner-pw', {}, { ip: '5.5.5.5' })).status).toBe(303);
  });

  it('lockdown expires on its own', async () => {
    const h = harness({ FAIL_GLOBAL_LIMIT: '2', LOCKDOWN_SECONDS: '60' });
    h.kv.now = () => h.time();
    await h.login('nope', {}, { ip: '1.1.1.1' });
    await h.login('nope', {}, { ip: '2.2.2.2' });
    expect((await h.login('owner-pw')).status).toBe(403);
    h.advance(61_000);
    expect((await h.login('owner-pw')).status).toBe(303);
  });
});

describe('scanner auto-ban', () => {
  it('bans an address after SCAN_LIMIT anonymous rejections inside the window', async () => {
    const h = harness({ SCAN_LIMIT: '20', SCAN_WINDOW_SECONDS: '60', CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list' });
    for (let i = 0; i < 19; i++) {
      expect((await h.run(h.request(`/probe-${i}.env`, { ip: '198.51.100.7', headers: { accept: '*/*' } }))).status).toBe(401);
    }
    expect(await h.kv.get('ban:198.51.100.7')).toBeNull();
    const twentieth = await h.run(h.request('/wp-config.old', { ip: '198.51.100.7', headers: { accept: '*/*' } }));
    expect(twentieth.status).toBe(403);
    expect(await h.kv.get('ban:198.51.100.7')).toContain('"kind":"scan"');
    expect((await h.run(h.request('/anything', { ip: '198.51.100.7' }))).status).toBe(403);

    const tg = h.net.telegram();
    expect(tg).toHaveLength(1);
    expect((tg[0]!.body as { text: string }).text).toContain('scanner');
    const cf = h.net.sent.find((s) => s.url.includes('rules/lists/list/items') && s.init?.method === 'POST');
    expect(cf?.body).toEqual([{ ip: '198.51.100.7', comment: expect.stringContaining('scanner') }]);

    // A different address is unaffected, and a slow visitor never trips it.
    expect((await h.run(h.request('/x', { ip: '198.51.100.8', headers: { accept: '*/*' } }))).status).toBe(401);
    const slow = harness({ SCAN_LIMIT: '3', SCAN_WINDOW_SECONDS: '60' });
    for (let i = 0; i < 6; i++) {
      expect((await slow.run(slow.request('/x', { ip: '198.51.100.9', headers: { accept: '*/*' } }))).status).toBe(401);
      slow.advance(61_000);
    }
  });
});

describe('observe mode', () => {
  const hosts = {
    HOSTS_JSON: JSON.stringify({
      'ha.example.test': { mode: 'observe', recipe: 'home-assistant' },
      'photos.example.test': { mode: 'observe', recipe: 'immich', watch: [{ path: '/custom', status: [403] }] },
    }),
    ORIGIN_FAIL_LIMIT: '3',
  };

  it('passes anonymous requests through untouched and never shows a password page', async () => {
    const h = harness(hosts);
    const res = await h.run(h.request('/lovelace', { host: 'ha.example.test' }));
    expect(await res.text()).toBe('origin:/lovelace');
    expect(res.headers.get('set-cookie')).toBeNull();
    // Gated hosts are unaffected.
    expect((await h.run(h.request('/', { host: 'nas.example.test' }))).status).toBe(401);
    expect(h.analytics.outcomes()).toEqual(['observe', 'reject']);
  });

  it("counts the origin's failed logins per watch rule and bans at the limit", async () => {
    const h = harness(hosts, { none: () => new Response('') });
    // Teach the fake origin to answer 401 for the HA API.
    const originFetch = h.net.doFetch;
    h.net.doFetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      if (new URL(req.url).pathname.startsWith('/api/')) return new Response('{"message":"Unauthorized"}', { status: 401 });
      return originFetch(input, init);
    };
    const g = createHandler({ fetch: (i, init) => h.net.doFetch(i, init), now: () => h.time() });
    const run = async (path: string, ip = '198.51.100.20', method = 'GET') => {
      const c = ctx();
      const res = await g(h.request(path, { host: 'ha.example.test', ip, method, headers: { accept: '*/*' } }), h.env, c);
      await c.settle();
      return res;
    };
    expect((await run('/api/states')).status).toBe(401); // 1
    expect((await run('/api/states')).status).toBe(401); // 2
    expect(await h.kv.get('ofail:198.51.100.20')).toBe('2');
    expect((await run('/api/states')).status).toBe(401); // 3 → ban written, this response still passes through
    expect(await h.kv.get('ban:198.51.100.20')).toContain('"kind":"origin"');
    expect((await run('/lovelace')).status).toBe(403); // from now on blocked
    const tg = h.net.telegram();
    expect(tg).toHaveLength(1);
    expect((tg[0]!.body as { text: string }).text).toContain('failed logins at the app itself');
    // A different address browsing normally is unaffected; non-watched 401s do not count.
    expect((await run('/lovelace', '198.51.100.21')).status).toBe(200);
  });

  it('custom watch rules extend the recipe and status must match', async () => {
    const h = harness(hosts);
    const originFetch = h.net.doFetch;
    h.net.doFetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      const p = new URL(req.url).pathname;
      if (p.startsWith('/custom')) return new Response('', { status: 403 });
      if (p.startsWith('/api/auth/login')) return new Response('', { status: 200 }); // a successful login
      return originFetch(input, init);
    };
    const g = createHandler({ fetch: (i, init) => h.net.doFetch(i, init), now: () => h.time() });
    const run = async (path: string, method = 'GET') => {
      const c = ctx();
      const res = await g(h.request(path, { host: 'photos.example.test', ip: '198.51.100.30', method, headers: { accept: '*/*' } }), h.env, c);
      await c.settle();
      return res;
    };
    await run('/api/auth/login', 'POST'); // 200: not a failure
    expect(await h.kv.get('ofail:198.51.100.30')).toBeNull();
    await run('/custom/thing');
    expect(await h.kv.get('ofail:198.51.100.30')).toBe('1');
  });

  it('bans a scanner on an observe host from the origin 404 burst', async () => {
    const h = harness({ ...hosts, SCAN_LIMIT: '10' });
    const originFetch = h.net.doFetch;
    h.net.doFetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      if (new URL(req.url).pathname.startsWith('/probe')) return new Response('nope', { status: 404 });
      return originFetch(input, init);
    };
    const g = createHandler({ fetch: (i, init) => h.net.doFetch(i, init), now: () => h.time() });
    for (let i = 0; i < 10; i++) {
      const c = ctx();
      await g(h.request(`/probe-${i}.env`, { host: 'ha.example.test', ip: '198.51.100.40', headers: { accept: '*/*' } }), h.env, c);
      await c.settle();
    }
    expect(await h.kv.get('ban:198.51.100.40')).toContain('"kind":"scan"');
  });

  it('malformed or unknown host config falls back to gated', async () => {
    const h = harness({ HOSTS_JSON: '{not json' });
    expect((await h.run(h.request('/', { host: 'ha.example.test' }))).status).toBe(401);
    const h2 = harness({ HOSTS_JSON: JSON.stringify({ 'ha.example.test': { mode: 'open' } }) });
    expect((await h2.run(h2.request('/', { host: 'ha.example.test' }))).status).toBe(401);
  });
});

describe('logout', () => {
  it('clears the cookie', async () => {
    const h = harness();
    const res = await h.run(h.request('/__wicket/logout'));
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });
});

describe('ban bookkeeping', () => {
  it('bans once: one KV write, one list call, one message, even while KV still reports a miss', async () => {
    const h = harness({ SCAN_LIMIT: '3', CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list' });
    const probe = (path: string) => h.run(h.request(path, { ip: '198.51.100.7', headers: { accept: '*/*' } }));
    for (let i = 0; i < 2; i++) expect((await probe(`/p${i}`)).status).toBe(401);
    expect((await probe('/p2')).status).toBe(403);
    expect(h.kv.writes.filter((k) => k === 'ban:198.51.100.7')).toHaveLength(1);

    // Simulate KV's cached miss: the record is gone from this isolate's view, the scanner keeps going.
    h.kv.store.delete('ban:198.51.100.7');
    for (let i = 0; i < 6; i++) expect((await probe(`/q${i}`)).status).toBe(403);
    expect(h.analytics.outcomes().slice(2)).toEqual(['ban-scan', 'banned', 'banned', 'banned', 'banned', 'banned', 'banned']);
    expect(h.kv.writes.filter((k) => k === 'ban:198.51.100.7')).toHaveLength(1);
    expect(h.net.telegram()).toHaveLength(1);
    expect(h.net.sent.filter((s) => s.url.includes('rules/lists') && s.init?.method === 'POST')).toHaveLength(1);

    // The memory expires; KV is the truth again.
    h.advance(11 * 60_000);
    expect((await probe('/r')).status).toBe(401);
  });

  it('API keys sprayed at scanner paths earn per-address strikes but never a lockdown', async () => {
    const h = harness({ FAIL_GLOBAL_LIMIT: '4', FAIL_LIMIT: '3' });
    for (const i of [1, 2, 3, 4, 5, 6]) {
      const res = await h.run(h.request('/.env', { ip: `10.0.0.${i}`, headers: { 'x-api-key': 'test', accept: '*/*' } }));
      expect(res.status).toBe(401);
    }
    expect(await h.kv.get('lockdown')).toBeNull();
    expect(await h.kv.get('gfail')).toBeNull();
    expect(await h.kv.get('fail:10.0.0.1')).toBe('1');
    // The same keys at an ordinary path are the rotating-IP case and do count.
    for (const i of [1, 2, 3, 4]) await h.run(h.request('/api/items', { ip: `10.0.1.${i}`, headers: { 'x-api-key': 'test', accept: '*/*' } }));
    expect(await h.kv.get('lockdown')).not.toBeNull();
  });
});

describe('pass-through of the app\'s own credential', () => {
  const HOSTS = JSON.stringify({ 'api.example.test': { mode: 'gated', passthrough: 'api' }, 'app.example.test': { mode: 'gated', passthrough: { cookies: ['sid'], paths: ['/api/'] } } });

  it('forwards requests that carry a credential the app validates, stores nothing, and still asks browsers for the password', async () => {
    const h = harness({ HOSTS_JSON: HOSTS });
    const bearer = await h.run(h.request('/v1/items', { host: 'api.example.test', headers: { authorization: 'Bearer app-issued', accept: 'application/json' } }));
    expect(bearer.status).toBe(200);
    expect(await bearer.text()).toBe('origin:/v1/items');
    expect(h.net.origin.at(-1)!.headers.get('authorization')).toBe('Bearer app-issued'); // untouched
    const key = await h.run(h.request('/mcp', { host: 'api.example.test', method: 'POST', headers: { 'x-api-key': 'whatever', accept: '*/*' }, body: '{}' }));
    expect(key.status).toBe(200);
    const param = await h.run(h.request('/ws?token=abc', { host: 'api.example.test', headers: { accept: '*/*' } }));
    expect(param.status).toBe(200);
    expect((await h.run(h.request('/', { host: 'api.example.test' }))).status).toBe(401); // no credential → password page
    expect(h.analytics.outcomes()).toEqual(['app', 'app', 'app', 'reject']);
    expect([...h.kv.store.keys()].filter((k) => !k.startsWith('job:'))).toEqual([]); // nothing recorded
  });

  it('counts the app\'s 401 as failed logins and bans at limits.origin; a 200 clears nothing it did not count', async () => {
    const h = harness({ HOSTS_JSON: HOSTS, ORIGIN_FAIL_LIMIT: '3' }, { 'api.example.test': () => new Response('bad token', { status: 401 }) });
    // The fake network treats unknown hosts as origins; route this host to a 401 answer instead.
    const net = h.net;
    const original = net.doFetch;
    const { createHandler } = await import('../src/pipeline/handler');
    const gate = createHandler({
      fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(String(input), init);
        if (new URL(req.url).hostname === 'api.example.test') return new Response('bad token', { status: 401 });
        return original(input, init);
      },
      now: () => h.time(),
    });
    const { ctx } = await import('./helpers');
    const call = async () => {
      const c = ctx();
      const res = await gate(h.request('/v1/items', { ip: '198.51.100.3', host: 'api.example.test', headers: { authorization: 'Bearer stale', accept: 'application/json' } }), h.env, c);
      await c.settle();
      return res;
    };
    expect((await call()).status).toBe(401);
    expect((await call()).status).toBe(401);
    expect(await h.kv.get('ofail:198.51.100.3')).toBe('2');
    expect((await call()).status).toBe(401); // the app's answer, and the ban is written
    expect(await h.kv.get('ban:198.51.100.3')).toContain('"kind":"origin"');
    expect(h.analytics.outcomes()).toEqual(['origin-fail', 'origin-fail', 'ban-origin']);
    expect((await call()).status).toBe(403);
    expect(net.telegram()).toHaveLength(1);
  });

  it('cookie carriers and path prefixes; registered wicket tokens still win; wrong explicit tokens elsewhere still strike', async () => {
    const h = harness({ HOSTS_JSON: HOSTS, API_TOKENS: 'bot:bot-token@api.example.test' });
    expect((await h.run(h.request('/api/me', { host: 'app.example.test', headers: { cookie: 'sid=abc; theme=dark' } }))).status).toBe(200);
    expect((await h.run(h.request('/settings', { host: 'app.example.test', headers: { cookie: 'sid=abc' } }))).status).toBe(401); // outside /api/
    expect((await h.run(h.request('/api/me', { host: 'app.example.test', headers: { cookie: 'theme=dark' } }))).status).toBe(401); // no credential cookie
    expect(h.analytics.outcomes()).toEqual(['app', 'reject', 'reject']);
    const registered = await h.run(h.request('/x', { host: 'api.example.test', headers: { 'x-wicket-token': 'bot-token', accept: '*/*' } }));
    expect(registered.status).toBe(200);
    expect(h.analytics.outcomes().at(-1)).toBe('token');
    // On a host without pass-through the same header is still a wicket strike.
    expect((await h.run(h.request('/x', { ip: '198.51.100.4', headers: { 'x-api-key': 'nope', accept: '*/*' } }))).status).toBe(401);
    expect(await h.kv.get('fail:198.51.100.4')).toBe('1');
  });
});
