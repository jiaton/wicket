import { describe, expect, it } from 'vitest';
import { compileExtra, matchSignature } from '../src/recipes/signatures';
import { harness } from './helpers';

const none = compileExtra(undefined, undefined);

describe('matchSignature', () => {
  it('knows common probe paths, CRS restricted files and scanner agents', () => {
    expect(matchSignature('/wp-login.php', 'Mozilla/5.0', none)).toBe('path /wp-login.php');
    expect(matchSignature('/WP-Admin/setup-config.php', '', none)).toBe('path /wp-admin');
    expect(matchSignature('/.env', '', none)).toBe('file .env');
    expect(matchSignature('/app/.git/config', '', none)).toBe('path /.git/');
    expect(matchSignature('/%2Eaws/credentials', '', none)).toMatch(/^file \.aws/);
    expect(matchSignature('/', 'Mozilla/5.0 (compatible; Nikto/2.1.6)', none)).toBe('agent nikto');
    expect(matchSignature('/', 'masscan/1.3', none)).toBe('agent masscan');
  });

  it('leaves ordinary requests alone', () => {
    for (const p of ['/', '/api/states', '/index.html', '/assets/app.js', '/environment', '/login', '/.well-known/acme-challenge/x']) {
      expect(matchSignature(p, 'Mozilla/5.0 (Macintosh) Safari/605', none)).toBeNull();
    }
  });

  it('applies the user\'s extra patterns and ignores broken ones', () => {
    const extra = compileExtra('^/old-admin/\n(unclosed', '^curl/');
    expect(extra.paths).toHaveLength(1);
    expect(matchSignature('/old-admin/x', '', extra)).toMatch(/^path ~ .*old-admin/);
    expect(matchSignature('/', 'curl/8.5', extra)).toMatch(/^agent ~ .*curl/);
  });
});

describe('signature strikes', () => {
  it('bans an anonymous address after three known scanner requests on a gated host', async () => {
    const h = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list' });
    const probe = (path: string) => h.run(h.request(path, { ip: '198.51.100.9', headers: { accept: 'application/json' } }));
    expect((await probe('/.env')).status).toBe(401);
    expect((await probe('/wp-login.php')).status).toBe(401);
    const third = await probe('/phpmyadmin/index.php');
    expect(third.status).toBe(403);
    expect(await h.kv.get('ban:198.51.100.9')).not.toBeNull();
    expect(h.analytics.outcomes()).toEqual(['reject', 'reject', 'ban']);
    const tg = h.net.telegram();
    expect(tg).toHaveLength(1);
    expect((tg[0]!.body as { text: string }).text).toContain('3 requests for known scanner paths/agents in 600s (last: path /phpmyadmin) on nas.example.test');
    expect((await probe('/')).status).toBe(403);
  });

  it('does not count ordinary anonymous requests, and forgets hits after the window', async () => {
    const h = harness();
    const probe = (path: string) => h.run(h.request(path, { ip: '198.51.100.9', headers: { accept: 'application/json' } }));
    for (let i = 0; i < 5; i++) expect((await probe('/dashboard')).status).toBe(401);
    expect((await probe('/.env')).status).toBe(401);
    expect((await probe('/.git/HEAD')).status).toBe(401);
    h.advance(11 * 60_000);
    expect((await probe('/xmlrpc.php')).status).toBe(401);
    expect(await h.kv.get('ban:198.51.100.9')).toBeNull();
  });

  it('counts on observe hosts only when the origin rejected the request', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'blog.example.test': { mode: 'observe' } }) }, {});
    // The fake origin answers 200 to everything: a WordPress blog really serving /wp-login.php.
    const probe = (path: string) => h.run(h.request(path, { ip: '198.51.100.9', host: 'blog.example.test' }));
    for (const p of ['/wp-login.php', '/xmlrpc.php', '/wp-admin/']) expect((await probe(p)).status).toBe(200);
    expect(await h.kv.get('ban:198.51.100.9')).toBeNull();
  });

  it('bans on observe hosts when the origin answers 4xx to scanner paths', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'ha.example.test': { mode: 'observe' } }) });
    // Make the origin 404 by routing through the fake network's handler for the host.
    const originalFetch = h.net.doFetch;
    const deps404 = async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      if (new URL(req.url).hostname === 'ha.example.test') return new Response('nope', { status: 404 });
      return originalFetch(input, init);
    };
    const { createHandler } = await import('../src/pipeline/handler');
    const gate = createHandler({ fetch: deps404, now: () => h.time() });
    const { ctx } = await import('./helpers');
    const probe = async (path: string) => {
      const c = ctx();
      const res = await gate(h.request(path, { ip: '198.51.100.9', host: 'ha.example.test' }), h.env, c);
      await c.settle();
      return res;
    };
    expect((await probe('/.env')).status).toBe(404);
    expect((await probe('/wp-login.php')).status).toBe(404);
    expect((await probe('/.git/config')).status).toBe(403);
    expect(await h.kv.get('ban:198.51.100.9')).not.toBeNull();
  });

  it('is off when the limit is 0', async () => {
    const h = harness({ SIGNATURE_LIMIT: '0' });
    const probe = (path: string) => h.run(h.request(path, { ip: '198.51.100.9', headers: { accept: 'application/json' } }));
    for (const p of ['/.env', '/wp-login.php', '/phpmyadmin', '/xmlrpc.php']) expect((await probe(p)).status).toBe(401);
    expect(await h.kv.get('ban:198.51.100.9')).toBeNull();
  });
});
