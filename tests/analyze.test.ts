import { describe, expect, it } from 'vitest';
import { inQuietHours, localHour, runAnalysis } from '../src/cron/analyze';
import { FakeAnalytics, FakeKV, fakeNetwork, makeEnv } from './helpers';

const rowsFor = (query: string) => {
  if (query.includes('GROUP BY ip, country')) return [{ ip: '1.1.1.1', country: 'US', n: 900, errors: 5 }, { ip: '2.2.2.2', country: 'DE', n: 40, errors: 35 }];
  if (query.includes("IN ('fail', 'ban') GROUP BY ip")) return [{ ip: '5.5.5.5', n: 2 }, { ip: '6.6.6.6', n: 1 }, { ip: '7.7.7.7', n: 1 }];
  if (query.includes("INTERVAL '7' DAY")) return [{ country: 'US' }];
  if (query.includes("IN ('pass', 'token', 'login') GROUP BY country")) return [{ country: 'US', n: 10 }, { country: 'DE', n: 3 }];
  if (query.includes('GROUP BY host, ip, country')) return [{ host: 'nas.x', ip: '3.3.3.3', country: 'US', n: 4 }];
  return [];
};

function setup(overrides = {}) {
  const kv = new FakeKV();
  const net = fakeNetwork({
    'analytics_engine/sql': async (req) => new Response(JSON.stringify({ data: rowsFor(await req.text()) })),
  });
  const env = makeEnv(kv, new FakeAnalytics(), { CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', ADMIN_HOSTS: 'nas.x', QUIET_HOURS: '0-23', ...overrides });
  return { kv, net, env };
}

describe('runAnalysis', () => {
  it('raises burst, error, new-country and quiet-hours alerts once per hour', async () => {
    const { kv, net, env } = setup();
    const first = await runAnalysis(env, net.doFetch, Date.now());
    const keys = first.map((a) => a.key).sort();
    expect(keys.filter((k) => !k.startsWith('guessing:'))).toEqual(['burst:1.1.1.1', 'country:DE', 'errors:2.2.2.2', 'quiet:nas.x:3.3.3.3']);
    expect(keys.some((k) => k.startsWith('guessing:'))).toBe(true);
    const tg = net.telegram();
    expect(tg).toHaveLength(1);
    const text = (tg[0]!.body as { text: string }).text;
    expect(text).toContain('900 requests');
    expect(text).toContain('guessing from 3 different addresses in 5 min (4 attempts)');

    expect(await runAnalysis(env, net.doFetch, Date.now())).toEqual([]);
    expect(net.telegram()).toHaveLength(1);
    kv.store.clear();
    expect(await runAnalysis(env, net.doFetch, Date.now())).toHaveLength(5);
  });

  it('does nothing without a Cloudflare token', async () => {
    const { net, env } = setup({ CF_API_TOKEN: undefined });
    expect(await runAnalysis(env, net.doFetch, Date.now())).toEqual([]);
    expect(net.sent).toHaveLength(0);
  });
});

describe('quiet hours', () => {
  it('handles ranges that wrap midnight', () => {
    expect(inQuietHours(3, [1, 6])).toBe(true);
    expect(inQuietHours(12, [1, 6])).toBe(false);
    expect(inQuietHours(23, [22, 5])).toBe(true);
    expect(inQuietHours(2, [22, 5])).toBe(true);
    expect(inQuietHours(12, [22, 5])).toBe(false);
    expect(inQuietHours(3, null)).toBe(false);
  });

  it('localHour respects the time zone', () => {
    const noonUtc = Date.UTC(2026, 0, 15, 12, 0, 0);
    expect(localHour(noonUtc, 'UTC')).toBe(12);
    expect(localHour(noonUtc, 'America/Los_Angeles')).toBe(4);
    expect(localHour(Date.UTC(2026, 0, 15, 0, 30, 0), 'UTC')).toBe(0);
  });
});
