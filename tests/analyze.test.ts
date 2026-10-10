import { describe, expect, it } from 'vitest';
import { foldAddresses, inQuietHours, localHour, runAnalysis } from '../src/cron/analyze';
import { FakeAnalytics, FakeKV, fakeNetwork, makeEnv } from './helpers';

const rowsFor = (query: string) => {
  if (query.includes('GROUP BY ip, country, outcome, host')) {
    return [
      { ip: '1.1.1.1', country: 'US', outcome: 'reject', host: 'nas.x', n: 900, errors: 900 }, // burst of probes
      { ip: '2.2.2.2', country: 'DE', outcome: 'reject', host: 'money.x', n: 30, errors: 30 }, // scanner below the ban line
      { ip: '2.2.2.2', country: 'DE', outcome: 'observe', host: 'ha.x', n: 10, errors: 6 },
      { ip: '5.5.5.5', country: 'RO', outcome: 'fail', host: 'nas.x', n: 2, errors: 2 }, // wicket password attempts
      { ip: '6.6.6.6', country: 'RO', outcome: 'fail', host: 'docker.x', n: 1, errors: 1 },
      { ip: '7.7.7.7', country: 'RO', outcome: 'fail', host: 'nas.x', n: 1, errors: 1 },
      { ip: '8.8.8.8', country: 'FR', outcome: 'origin-fail', host: 'ha.x', n: 3, errors: 3 }, // app login failures
      { ip: '9.9.9.9', country: 'CN', outcome: 'fail', host: 'nas.x', n: 2, errors: 2 }, // banned in this window → reported as a ban already
      { ip: '9.9.9.9', country: 'CN', outcome: 'ban', host: 'nas.x', n: 1, errors: 1 },
      { ip: '4.4.4.4', country: 'US', outcome: 'pass', host: 'nas.x', n: 50, errors: 0 }, // normal use
    ];
  }
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

describe('foldAddresses', () => {
  it('separates wicket credential failures, app login failures and probes per address', () => {
    const a = foldAddresses(rowsFor('GROUP BY ip, country, outcome, host') as never);
    expect(a.get('2.2.2.2')).toMatchObject({ probes: 36, fails: 0, appFails: 0, total: 40 });
    expect(a.get('5.5.5.5')).toMatchObject({ fails: 2, probes: 0 });
    expect(a.get('8.8.8.8')).toMatchObject({ appFails: 3 });
    expect(a.get('9.9.9.9')).toMatchObject({ fails: 3, bannedNow: true });
    expect(a.get('4.4.4.4')).toMatchObject({ total: 50, probes: 0, fails: 0 });
  });
});

describe('runAnalysis', () => {
  it('bans slow scanners first, then sends one message per kind: credentials (warn), app logins (warn), traffic (info); once per hour', async () => {
    const { kv, net, env } = setup();
    await kv.put('fail:5.5.5.5', '2');
    const first = await runAnalysis(env, net.doFetch, Date.now());
    const keys = first.map((a) => a.key).sort();
    // 1.1.1.1 (900 probes) and 2.2.2.2 (36 probes) crossed limits.scanning (30): banned, not alerted.
    expect(keys.filter((k) => !k.startsWith('guessing:'))).toEqual(['app:8.8.8.8', 'country:DE', 'cred:5.5.5.5', 'cred:6.6.6.6', 'cred:7.7.7.7', 'quiet:nas.x:3.3.3.3']);
    expect(await kv.get('ban:1.1.1.1')).not.toBeNull();
    expect(await kv.get('ban:2.2.2.2')).not.toBeNull();
    const bans = net.telegram().map((m) => (m.body as { text: string }).text).filter((t) => t.includes('banned'));
    expect(bans).toHaveLength(2);
    expect(bans.some((t) => t.includes('900 anonymous probes in 5 min across the network (scanner) on nas.x'))).toBe(true);
    expect(bans.some((t) => t.includes('36 anonymous probes in 5 min across the network (scanner) on money.x'))).toBe(true);
    expect(keys.some((k) => k.startsWith('guessing:'))).toBe(true);
    expect(keys.some((k) => k.includes('9.9.9.9'))).toBe(false);

    const messages = net.telegram().map((m) => (m.body as { text: string }).text).filter((t) => !t.includes('banned'));
    expect(messages).toHaveLength(3);
    const cred = messages.find((t) => t.includes('wicket password/token attempts'))!;
    expect(cred).toContain('5.5.5.5 (RO) sent 2 wrong wicket password/tokens on nas.x in 5 min (1 more → ban)');
    expect(cred).toContain('guessing from 4 different addresses in 5 min (7 attempts)');
    const app = messages.find((t) => t.includes('app login failures'))!;
    expect(app).toContain('8.8.8.8 (FR) failed 3 logins at ha.x in 5 min');
    const traffic = messages.find((t) => t.includes('<b>test: traffic</b>'))!;
    expect(traffic).not.toContain('anonymous probes');
    expect(traffic).toContain('first successful visits from DE');
    expect(traffic).toContain('used at night');
    expect(traffic).not.toContain('5.5.5.5');

    expect(await runAnalysis(env, net.doFetch, Date.now())).toEqual([]);
    expect(net.telegram()).toHaveLength(5);
    kv.store.clear();
    expect(await runAnalysis(env, net.doFetch, Date.now())).toHaveLength(7);
  });

  it('reports scanning below limits.scanning instead of banning, and skips addresses already banned', async () => {
    const { kv, net, env } = setup({ SCANNING_LIMIT: '1000' });
    await kv.put('ban:2.2.2.2', '{}');
    const alerts = await runAnalysis(env, net.doFetch, Date.now());
    expect(alerts.some((a) => a.key === 'scan:2.2.2.2')).toBe(false);
    expect(alerts.find((a) => a.key === 'scan:1.1.1.1')?.text).toContain('900 anonymous probes on nas.x (scanning, not banned yet)');
    expect(await kv.get('ban:1.1.1.1')).toBeNull();
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
