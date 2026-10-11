import { describe, expect, it } from 'vitest';
import { harness } from './helpers';

const IP = '198.51.100.44';
const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;

describe('trusted addresses', () => {
  it('an owner login marks the address trusted; a friend login does not', async () => {
    const h = harness();
    await h.login('friend-pw', {}, { ip: IP });
    expect(await h.kv.get(`trust:${IP}`)).toBeNull();
    await h.login('owner-pw', {}, { ip: IP });
    expect(await h.kv.get(`trust:${IP}`)).toBe('1');
    expect(h.kv.store.get(`trust:${IP}`)!.expires).toBe(h.time() + 86_400_000);
  });

  it('wrong passwords from a trusted address are not counted and never ban it', async () => {
    const h = harness();
    await h.login('owner-pw', {}, { ip: IP });
    for (let i = 0; i < 6; i++) expect((await h.login('nope', {}, { ip: IP })).status).toBe(401);
    expect(await h.kv.get(`fail:${IP}`)).toBeNull();
    expect(await h.kv.get(`ban:${IP}`)).toBeNull();
    expect(await h.kv.get('gfail')).toBeNull();
    expect(h.net.telegram()).toHaveLength(0);
  });

  it('scanner signatures and probe bursts do not ban a trusted address', async () => {
    const h = harness({ SCAN_LIMIT: '5' });
    await h.login('owner-pw', {}, { ip: IP });
    const probe = (path: string) => h.run(h.request(path, { ip: IP, headers: { accept: 'application/json' } }));
    for (const p of ['/.env', '/wp-login.php', '/phpmyadmin', '/xmlrpc.php', '/a', '/b', '/c', '/d', '/e', '/f']) expect((await probe(p)).status).toBe(401);
    expect(await h.kv.get(`ban:${IP}`)).toBeNull();
  });

  it('a trusted address may log in during a lockdown', async () => {
    const h = harness();
    await h.login('owner-pw', {}, { ip: IP });
    await h.kv.put('lockdown', JSON.stringify({ at: h.time(), host: 'nas.example.test', fails: 10 }), { expirationTtl: 3600 });
    expect((await h.login('owner-pw', {}, { ip: '203.0.113.5' })).status).toBe(403);
    expect((await h.login('owner-pw', {}, { ip: IP })).status).toBe(303);
  });

  it('an owner cookie in use refreshes trust, at most once per hour per isolate', async () => {
    const h = harness();
    const cookie = cookieOf(await h.login('owner-pw', {}, { ip: IP }));
    await h.kv.delete(`trust:${IP}`);
    await h.run(h.request('/a', { ip: IP, headers: { cookie } }));
    expect(await h.kv.get(`trust:${IP}`)).toBe('1');
    await h.kv.delete(`trust:${IP}`);
    await h.run(h.request('/b', { ip: IP, headers: { cookie } }));
    expect(await h.kv.get(`trust:${IP}`)).toBeNull(); // throttled
    h.advance(3_600_001);
    await h.run(h.request('/c', { ip: IP, headers: { cookie } }));
    expect(await h.kv.get(`trust:${IP}`)).toBe('1');
  });

  it('expires with trust_window and is off at 0', async () => {
    const h = harness({ TRUST_SECONDS: '0' });
    await h.login('owner-pw', {}, { ip: IP });
    expect(await h.kv.get(`trust:${IP}`)).toBeNull();
    const h2 = harness({ TRUST_SECONDS: '600' });
    await h2.login('owner-pw', {}, { ip: IP });
    h2.advance(601_000);
    expect(await h2.kv.get(`trust:${IP}`)).toBeNull();
    await h2.login('nope', {}, { ip: IP });
    expect(await h2.kv.get(`fail:${IP}`)).toBe('1');
  });
});
