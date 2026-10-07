import { describe, expect, it } from 'vitest';
import { harness } from './helpers';

const ANALYTICS_ENV = { CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list' };
const sqlCalls = (h: ReturnType<typeof harness>) => h.net.sent.filter((s) => s.url.includes('analytics_engine/sql')).length;
const listReads = (h: ReturnType<typeof harness>) => h.net.sent.filter((s) => s.url.includes('rules/lists') && (!s.init?.method || s.init.method === 'GET')).length;

describe('request-path fallback for the cron', () => {
  it('runs the five-minute job once per window and the hourly job once per hour', async () => {
    const h = harness(ANALYTICS_ENV);
    await h.run(h.request('/'));
    const afterFirst = sqlCalls(h);
    expect(afterFirst).toBeGreaterThan(0);
    expect(listReads(h)).toBe(1);
    expect(await h.kv.get('job:tick')).toBe('1');
    expect(await h.kv.get('job:reconcile')).toBe('1');

    await h.run(h.request('/'));
    h.advance(4 * 60_000);
    await h.run(h.request('/'));
    expect(sqlCalls(h)).toBe(afterFirst);

    h.advance(2 * 60_000); // 6 min since the first tick; lock (270 s) has expired too
    await h.run(h.request('/'));
    expect(sqlCalls(h)).toBe(afterFirst * 2);
    expect(listReads(h)).toBe(1);

    h.advance(60 * 60_000);
    await h.run(h.request('/'));
    expect(listReads(h)).toBe(2);
  });

  it('skips when another isolate holds the lock', async () => {
    const h = harness(ANALYTICS_ENV);
    await h.kv.put('job:tick', '1', { expirationTtl: 270 });
    await h.kv.put('job:reconcile', '1', { expirationTtl: 3570 });
    await h.run(h.request('/'));
    expect(sqlCalls(h)).toBe(0);
    expect(listReads(h)).toBe(0);
  });

  it('does nothing when neither analytics nor channels are configured', async () => {
    const h = harness();
    await h.run(h.request('/'));
    expect(h.net.sent.filter((s) => s.url.includes('api.cloudflare.com'))).toHaveLength(0);
    expect(await h.kv.get('job:tick')).toBeNull();
  });
});
