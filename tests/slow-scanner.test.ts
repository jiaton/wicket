import { describe, expect, it } from 'vitest';
import { settings } from '../src/config/settings';
import { foldAddresses } from '../src/cron/addresses';
import { banSlowScanners } from '../src/cron/slow-scanner';
import { FakeAnalytics, FakeKV, fakeNetwork, makeEnv } from './helpers';

const NOW = 1_800_000_000_000;

describe('banSlowScanners', () => {
  it('bans at the threshold with the shared ban exit, skips allow-listed and already banned addresses', async () => {
    const kv = new FakeKV();
    const net = fakeNetwork();
    const env = makeEnv(kv, new FakeAnalytics(), { CF_API_TOKEN: 't', CF_ACCOUNT_ID: 'acc', CF_LIST_ID: 'list', ALLOW_IPS: '10.0.0.1', SCANNING_LIMIT: '30' });
    await kv.put('ban:3.3.3.3', '{}');
    const addresses = foldAddresses([
      { ip: '1.1.1.1', country: 'SG', outcome: 'reject', host: 'nas.x', n: 25, errors: 25 },
      { ip: '1.1.1.1', country: 'SG', outcome: 'observe', host: 'ha.x', n: 9, errors: 5 }, // 25 + 5 = 30 → banned
      { ip: '2.2.2.2', country: 'DE', outcome: 'reject', host: 'nas.x', n: 29, errors: 29 }, // below
      { ip: '10.0.0.1', country: 'US', outcome: 'reject', host: 'nas.x', n: 500, errors: 500 }, // allow-listed
      { ip: '3.3.3.3', country: 'US', outcome: 'reject', host: 'nas.x', n: 500, errors: 500 }, // already banned
      { ip: '4.4.4.4', country: 'US', outcome: 'pass', host: 'nas.x', n: 500, errors: 0 }, // authenticated traffic is not probing
    ]);
    const banned = await banSlowScanners(env, net.doFetch, NOW, settings(env), addresses);
    expect(banned).toEqual(['1.1.1.1']);
    expect(JSON.parse((await kv.get('ban:1.1.1.1'))!)).toMatchObject({ kind: 'scan', host: 'nas.x', country: 'SG', at: NOW });
    expect(addresses.get('1.1.1.1')!.bannedNow).toBe(true);
    const list = net.sent.find((s) => s.url.includes('rules/lists') && s.init?.method === 'POST')!;
    expect(list.body).toEqual([{ ip: '1.1.1.1', comment: 'wicket test: 30 anonymous probes in 5 min across the network (scanner) on nas.x' }]);
    const tg = net.telegram();
    expect(tg).toHaveLength(1);
    const body = tg[0]!.body as { text: string; reply_markup: { inline_keyboard: { url: string }[][] } };
    expect(body.text).toContain('banned 1.1.1.1 (SG)');
    expect(body.reply_markup.inline_keyboard[0]![0]!.url).toMatch(/^https:\/\/nas\.x\/__wicket\/unban\?ip=1\.1\.1\.1&exp=\d+&sig=/);
    expect(await kv.get('ban:2.2.2.2')).toBeNull();
    expect(await kv.get('ban:10.0.0.1')).toBeNull();
  });
});
