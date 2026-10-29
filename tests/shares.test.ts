import { describe, expect, it } from 'vitest';
import { harness } from './helpers';

const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!;
const post = (h: ReturnType<typeof harness>, cookie: string, fields: Record<string, string>) =>
  h.run(h.request('/__wicket/settings', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams(fields) }));

describe('share links', () => {
  it('opens one host for a while without a password, and nothing else', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'app.example.test': { mode: 'gated' }, 'nas.example.test': { mode: 'gated' } }) });
    const owner = cookieOf(await h.login('owner-pw'));
    const created = await post(h, owner, { action: 'share.create', host: 'app.example.test', duration: '7d', label: 'Alice' });
    expect(created.status).toBe(303);
    const link = new URL(decodeURIComponent(new URL(created.headers.get('location')!).searchParams.get('link')!));
    expect(link.hostname).toBe('app.example.test');
    expect(link.pathname).toBe('/__wicket/share');

    // The page shows the link once and lists the share.
    const page = await (await h.run(h.request(created.headers.get('location')!.replace('https://nas.example.test', ''), { headers: { cookie: owner } }))).text();
    expect(page).toContain('New share link');
    expect(page).toContain('<b>Alice</b> <small>app.example.test · expires in 7 d');

    // A friend with the link: cookie for that host, straight to the app; wrong host or no cookie → password page.
    const visit = await h.run(h.request(link.pathname + link.search, { host: 'app.example.test', ip: '198.51.100.20' }));
    expect(visit.status).toBe(303);
    const shareCookie = cookieOf(visit);
    expect(shareCookie).toContain('__wicket_share=');
    expect(visit.headers.get('set-cookie')).not.toContain('Domain='); // host-only
    expect((await h.run(h.request('/photos', { host: 'app.example.test', ip: '198.51.100.20', headers: { cookie: shareCookie } }))).status).toBe(200);
    expect(h.analytics.outcomes().at(-1)).toBe('share');
    expect(h.net.origin.at(-1)!.headers.get('cookie')).toBeNull(); // stripped before the app
    expect((await h.run(h.request('/photos', { host: 'nas.example.test', ip: '198.51.100.20', headers: { cookie: shareCookie } }))).status).toBe(401);
    expect((await h.run(h.request(link.pathname + link.search, { host: 'nas.example.test', ip: '198.51.100.20' }))).status).toBe(410);
    expect((await h.run(h.request('/__wicket/settings', { host: 'app.example.test', ip: '198.51.100.20', headers: { cookie: shareCookie } }))).status).toBe(401);

    // Tampering and expiry.
    const [idPart, expPart] = shareCookie.split('=')[1]!.split('.');
    expect((await h.run(h.request('/x', { host: 'app.example.test', headers: { cookie: `__wicket_share=${idPart}.${expPart}.deadbeef` } }))).status).toBe(401);
    h.advance(8 * 86_400_000);
    expect((await h.run(h.request('/x', { host: 'app.example.test', headers: { cookie: shareCookie } }))).status).toBe(401);
  });

  it('revoking a share kills its link and its cookies at once', async () => {
    const h = harness({ HOSTS_JSON: JSON.stringify({ 'app.example.test': { mode: 'gated' } }) });
    const owner = cookieOf(await h.login('owner-pw'));
    const created = await post(h, owner, { action: 'share.create', host: 'app.example.test', duration: '1d', label: 'Bob' });
    const link = new URL(decodeURIComponent(new URL(created.headers.get('location')!).searchParams.get('link')!));
    const visit = await h.run(h.request(link.pathname + link.search, { host: 'app.example.test' }));
    const shareCookie = cookieOf(visit);
    expect((await h.run(h.request('/', { host: 'app.example.test', headers: { cookie: shareCookie } }))).status).toBe(200);
    const id = [...h.kv.store.keys()].find((k) => k.startsWith('share:'))!.slice('share:'.length);
    expect((await post(h, owner, { action: 'share.revoke', id })).headers.get('location')).toContain('ok=share-revoked');
    expect((await h.run(h.request('/', { host: 'app.example.test', headers: { cookie: shareCookie } }))).status).toBe(401);
    expect((await h.run(h.request(link.pathname + link.search, { host: 'app.example.test' }))).status).toBe(410);
    expect((await post(h, owner, { action: 'share.create', host: 'other.test', duration: '1d', label: 'x' })).status).toBe(400);
    expect((await post(h, owner, { action: 'share.create', host: 'app.example.test', duration: '3y', label: 'x' })).status).toBe(400);
  });
});
