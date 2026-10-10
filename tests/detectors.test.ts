import { describe, expect, it } from 'vitest';
import { settings } from '../src/config/settings';
import { foldAddresses } from '../src/cron/addresses';
import { credentials } from '../src/cron/detectors/credentials';
import { DETECTORS, type DetectorContext } from '../src/cron/detectors';
import { scanning } from '../src/cron/detectors/scanning';
import { FakeAnalytics, FakeKV, makeEnv } from './helpers';

/** A detector sees only this: the folded window plus a few lookups. No network, no KV. */
function ctx(rows: Parameters<typeof foldAddresses>[0], extra: Partial<DetectorContext> = {}): DetectorContext {
  return {
    cfg: settings(makeEnv(new FakeKV(), new FakeAnalytics())),
    now: 1_800_000_000_000,
    addresses: foldAddresses(rows),
    query: async () => [],
    alreadyBanned: async () => false,
    failureCount: async () => 0,
    ...extra,
  };
}

describe('detectors run in isolation', () => {
  it('credentials: one line per address with wrong wicket credentials, skipping banned ones', async () => {
    const c = ctx(
      [
        { ip: '5.5.5.5', country: 'RO', outcome: 'fail', host: 'nas.x', n: 2, errors: 2 },
        { ip: '6.6.6.6', country: 'RO', outcome: 'fail', host: 'nas.x', n: 1, errors: 1 },
        { ip: '7.7.7.7', country: 'US', outcome: 'reject', host: 'nas.x', n: 50, errors: 50 },
      ],
      { alreadyBanned: async (ip) => ip === '6.6.6.6', failureCount: async () => 2 },
    );
    const alerts = await credentials.run(c);
    expect(alerts.map((a) => a.key)).toEqual(['cred:5.5.5.5']);
    expect(alerts[0]!.text).toBe('5.5.5.5 (RO) sent 2 wrong wicket password/tokens on nas.x in 5 min (1 more → ban)');
    expect(alerts[0]).toMatchObject({ kind: 'credentials', severity: 'warn' });
  });

  it('scanning: probes at or above the threshold, bursts otherwise, nothing for quiet addresses', async () => {
    const c = ctx([
      { ip: '1.1.1.1', country: 'DE', outcome: 'reject', host: 'nas.x', n: 30, errors: 30 },
      { ip: '2.2.2.2', country: 'DE', outcome: 'pass', host: 'nas.x', n: 300, errors: 0 },
      { ip: '3.3.3.3', country: 'DE', outcome: 'reject', host: 'nas.x', n: 5, errors: 5 },
    ]);
    const alerts = await scanning.run(c);
    expect(alerts.map((a) => a.key)).toEqual(['scan:1.1.1.1', 'scan:2.2.2.2']);
    expect(alerts[0]!.text).toContain('30 anonymous probes on nas.x (scanning, not banned yet)');
    expect(alerts[1]!.text).toContain('300 requests');
  });

  it('every detector has a unique id and survives an empty window', async () => {
    const ids = DETECTORS.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const d of DETECTORS) expect(await d.run(ctx([]))).toEqual([]);
  });
});
