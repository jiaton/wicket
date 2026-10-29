import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../src/core/password';
import { resolveRuntime } from '../src/runtime';
import { harness } from './helpers';

const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
/** A deploy with no secrets at all, only the setup token. */
const fresh = (extra = {}) => harness({ OWNER_PASSWORD: undefined, FRIEND_PASSWORD: undefined, COOKIE_SECRET: undefined, SETUP_TOKEN: 'deploy-token', ...extra } as never);
const post = (h: ReturnType<typeof harness>, path: string, fields: Record<string, string>, ip = '203.0.113.5') =>
  h.run(h.request(path, { ip, method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

describe('password hashing', () => {
  it('round-trips and rejects tampering', async () => {
    const h = await hashPassword('correct horse battery staple');
    expect(h).toMatch(/^pbkdf2\$20000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(await verifyPassword('correct horse battery staple', h)).toBe(true);
    expect(await verifyPassword('correct horse battery stapl', h)).toBe(false);
    expect(await verifyPassword('x', 'pbkdf2$1$ab$cd')).toBe(false);
    expect(await verifyPassword('x', 'garbage')).toBe(false);
  });
});

describe('first-run setup', () => {
  it('a fresh deploy is closed: gated hosts 401, login 503 with a hint, setup needs the token', async () => {
    const h = fresh();
    expect((await h.run(h.request('/', { headers: { accept: '*/*' } }))).status).toBe(401);
    const login = await h.login('anything');
    expect(login.status).toBe(503);
    expect(await login.text()).toContain('not been set up yet');
    expect((await h.run(h.request('/__wicket/setup'))).status).toBe(403);
    expect((await h.run(h.request('/__wicket/setup?token=wrong'))).status).toBe(403);
    const page = await h.run(h.request('/__wicket/setup?token=deploy-token'));
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('name="password2"');
  });

  it('sets the passwords, allow-lists the visitor, signs the owner in, and then disappears', async () => {
    const h = fresh();
    expect((await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'short', password2: 'short' })).status).toBe(400);
    expect((await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'a-long-enough-password', password2: 'different-long-password' })).status).toBe(400);
    const done = await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'a-long-enough-password', password2: 'a-long-enough-password', friend: 'friends-password', allow: '1' }, '198.51.100.9');
    expect(done.status).toBe(303);
    expect(done.headers.get('location')).toContain('/__wicket/settings?ok=setup');
    const owner = cookieOf(done);
    expect(owner).toContain('__wicket=owner.');

    const rt = await resolveRuntime(h.env);
    expect(rt.auth.kind).toBe('hash');
    expect(rt.auth.setupOpen).toBe(false);
    expect(rt.settings.allowIps).toContain('198.51.100.9');
    expect(await h.kv.get('trust:198.51.100.9')).toBe('1');

    // Owner session works on gated hosts; the settings page shows the Passwords section for KV passwords.
    expect((await h.run(h.request('/dash', { headers: { cookie: owner }, ip: '203.0.113.7' }))).status).toBe(200);
    const settings = await (await h.run(h.request('/__wicket/settings?ok=setup', { headers: { cookie: owner }, ip: '203.0.113.7' }))).text();
    expect(settings).toContain('value="auth.password"');
    expect(settings).toContain('Welcome. wicket is set up');

    // Passwords now work through the normal login, with the usual counting.
    expect((await h.login('a-long-enough-password', {}, { ip: '203.0.113.8' })).status).toBe(303);
    expect(cookieOf(await h.login('friends-password', {}, { ip: '203.0.113.8' }))).toContain('__wicket=friend.');
    expect((await h.login('nope', {}, { ip: '203.0.113.9' })).status).toBe(401); // not the owner's (now trusted) address
    expect(await h.kv.get('fail:203.0.113.9')).toBe('1');

    // Setup is gone, even with the token.
    expect((await h.run(h.request('/__wicket/setup?token=deploy-token'))).status).toBe(404);
    expect((await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'another-long-password', password2: 'another-long-password' })).status).toBe(404);
  });

  it('changing the owner password signs old browsers out; secrets-based deploys keep their page read-only', async () => {
    const h = fresh();
    const owner = cookieOf(await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'a-long-enough-password', password2: 'a-long-enough-password' }));
    const change = (fields: Record<string, string>) => h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie: owner, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams({ action: 'auth.password', ...fields }) }));
    expect((await change({ current: 'wrong', owner: 'brand-new-password-1' })).status).toBe(400);
    expect((await change({ current: 'a-long-enough-password', owner: 'brand-new-password-1', friend: 'friend-pass' })).status).toBe(303);
    expect((await h.run(h.request('/dash', { headers: { cookie: owner } }))).status).toBe(401); // old cookie dead
    expect((await h.login('brand-new-password-1')).status).toBe(303);
    expect((await h.login('a-long-enough-password')).status).toBe(401);
    expect(cookieOf(await h.login('friend-pass'))).toContain('friend');

    const secrets = harness();
    const o = cookieOf(await secrets.login('owner-pw'));
    const page = await (await secrets.run(secrets.request('/__wicket/settings', { headers: { cookie: o } }))).text();
    expect(page).toContain('Set as secrets at deploy time');
    expect(page).not.toContain('value="auth.password"');
    expect((await secrets.run(secrets.request('/__wicket/setup?token=x'))).status).toBe(404);
  });

  it('a Cloudflare token given on the page is used by the jobs and the Cloudflare section until a secret replaces it', async () => {
    const h = fresh();
    await post(h, '/__wicket/setup', { token: 'deploy-token', password: 'a-long-enough-password', password2: 'a-long-enough-password', cfToken: 'kv-token', cfAccount: '0123456789abcdef0123456789abcdef' });
    const rt = await resolveRuntime(h.env);
    expect(rt.env.CF_API_TOKEN).toBe('kv-token');
    expect(rt.env.CF_ACCOUNT_ID).toBe('0123456789abcdef0123456789abcdef');
    expect(h.env.CF_API_TOKEN).toBeUndefined(); // the raw env is untouched
    const withSecret = await resolveRuntime({ ...h.env, CF_API_TOKEN: 'secret-token' });
    expect(withSecret.env.CF_API_TOKEN).toBe('secret-token');
  });
});

describe('review follow-ups', () => {
  const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
    h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

  it('owner and friend hashes share a salt; one derivation checks both; the two passwords cannot be made equal', async () => {
    const { matchPasswords, hashPassword } = await import('../src/core/password');
    const owner = await hashPassword('owner-password-long');
    const friend = await hashPassword('friend-password-long', owner);
    expect(owner.split('$')[2]).toBe(friend.split('$')[2]);
    expect(await matchPasswords('friend-password-long', [owner, friend])).toBe(1);
    expect(await matchPasswords('nope', [owner, friend])).toBe(-1);

    const h = fresh();
    const cookie = cookieOf(await h.run(h.request('/__wicket/setup', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams({ token: 'deploy-token', password: 'a-long-enough-password', password2: 'a-long-enough-password', friend: 'friend-pass' }) })));
    expect((await post(h, cookie, { action: 'auth.password', current: 'a-long-enough-password', friend: 'a-long-enough-password' })).status).toBe(400); // friend = current owner
    expect((await post(h, cookie, { action: 'auth.password', current: 'a-long-enough-password', owner: 'friend-pass' })).status).toBe(400); // too short (and equal to the friend password)
    expect((await post(h, cookie, { action: 'auth.password', current: 'a-long-enough-password', owner: 'another-long-password-1' })).status).toBe(303);
    expect((await h.run(h.request('/__wicket/settings', { headers: { cookie } }))).status).toBe(401); // the change signed this browser out
    expect(cookieOf(await h.login('friend-pass'))).toContain('__wicket=friend.'); // friend hash still valid with its old salt
  });

  it('reset keeps the Cloudflare ids created from the page', async () => {
    const h = harness({ CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc' });
    const owner = cookieOf(await h.login('owner-pw'));
    await h.kv.put('settings:runtime', JSON.stringify({ limits: { failLimit: 5 }, cloudflare: { listId: '0123456789abcdef0123456789abcdef' } }));
    await post(h, owner, { action: 'runtime.reset' });
    const { resolveRuntime } = await import('../src/runtime');
    const rt = await resolveRuntime(h.env);
    expect(rt.settings.failLimit).toBe(3);
    expect(rt.settings.listId).toBe('0123456789abcdef0123456789abcdef');
  });

  it('cf.creds: a KV token can be replaced; a secret token cannot be overridden', async () => {
    const h = fresh();
    const cookie = cookieOf(await h.run(h.request('/__wicket/setup', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams({ token: 'deploy-token', password: 'a-long-enough-password', password2: 'a-long-enough-password', cfToken: 'kv-1', cfAccount: '0123456789abcdef0123456789abcdef' }) })));
    expect((await post(h, cookie, { action: 'cf.creds', cfToken: 'kv-2', cfAccount: '0123456789abcdef0123456789abcdef' })).status).toBe(303);
    const { resolveRuntime } = await import('../src/runtime');
    expect((await resolveRuntime(h.env)).env.CF_API_TOKEN).toBe('kv-2');
    const secrets = harness({ CF_API_TOKEN: 'secret', CF_ACCOUNT_ID: 'acc' });
    const o = cookieOf(await secrets.login('owner-pw'));
    expect((await post(secrets, o, { action: 'cf.creds', cfToken: 'x', cfAccount: '0123456789abcdef0123456789abcdef' })).status).toBe(400);
  });

  it('share links are rendered from the POST, never taken from the URL; footguns on the access page are refused', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'app.example.test': { mode: 'gated' } }) });
    const owner = cookieOf(await h.login('owner-pw'));
    const created = await post(h, owner, { action: 'share.create', host: 'app.example.test', duration: '1d', label: 'x' });
    expect(created.status).toBe(200);
    expect(await created.text()).toContain('/__wicket/share?s=');
    const spoof = await (await h.run(h.request('/__wicket/settings?ok=share&link=https://attacker.example/x', { headers: { cookie: owner } }))).text();
    expect(spoof).not.toContain('attacker.example');
    expect((await post(h, owner, { action: 'access.save', allowIps: '0.0.0.0/0', allowDns: '', trustSeconds: '0', bypass: '' })).status).toBe(400);
    expect((await post(h, owner, { action: 'access.save', allowIps: '', allowDns: '', trustSeconds: '0', bypass: 'nas.example.test' })).status).toBe(400);
    expect((await post(h, owner, { action: 'access.save', allowIps: '', allowDns: '', trustSeconds: '0', bypass: 'nas.example.test/' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.save', host: 'app.example.test', mode: 'gated', passthrough: 'custom', spec: 'headers=accept' })).status).toBe(400);
    expect((await post(h, owner, { action: 'host.save', host: 'app.example.test', mode: 'gated', passthrough: 'custom', spec: 'headers=authorization; status=200' })).status).toBe(400);
  });

  it('the country comes from request.cf when present, never from a client header', async () => {
    const { country } = await import('../src/core/ip');
    const withCf = Object.assign(new Request('https://x.test/'), { cf: { country: 'DE' } });
    expect(country(withCf)).toBe('DE');
    const cfWithoutCountry = Object.assign(new Request('https://x.test/', { headers: { 'cf-ipcountry': 'US' } }), { cf: {} });
    expect(country(cfWithoutCountry)).toBe('??');
    expect(country(new Request('https://x.test/', { headers: { 'cf-ipcountry': 'fr' } }))).toBe('FR');
  });
});
