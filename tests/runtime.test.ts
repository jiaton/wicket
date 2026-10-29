import { describe, expect, it } from 'vitest';
import { applyHostOverrides, applyOverrides, runtimeOverridesOf } from '../src/config/runtime';
import { hostTableOf } from '../src/config/hosts';
import { settings } from '../src/config/settings';
import { CACHE_MS, createRuntimeCache, resolveRuntime } from '../src/runtime';
import { FakeAnalytics, FakeKV, makeEnv } from './helpers';

describe('runtime overrides', () => {
  it('parses field by field and drops junk without failing', () => {
    const o = runtimeOverridesOf(JSON.stringify({ hosts: { 'A.example.test': { mode: 'observe', recipe: 'immich' } }, access: { allowIps: ['203.0.113.9', 7], allowDns: ['Home.Example.Test', 'not a host'], trustSeconds: -5, bypass: ['a.example.test/hooks/'] }, limits: { failLimit: 5, scanLimit: 0, signatureLimit: 0, nonsense: 3 } }));
    expect(o.access).toEqual({ allowIps: ['203.0.113.9'], allowDns: ['home.example.test'], bypass: ['a.example.test/hooks/'] });
    expect(o.limits).toEqual({ failLimit: 5, signatureLimit: 0 }); // scanLimit 0 is not allowed, nonsense is unknown
    expect(runtimeOverridesOf('{broken')).toEqual({});
    expect(runtimeOverridesOf(null)).toEqual({});
  });

  it('layers over the deploy-time settings and host table', () => {
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), { ALLOW_IPS: '198.51.100.1', FAIL_LIMIT: '3', HOSTS_JSON: JSON.stringify({ 'ha.example.test': { mode: 'observe', recipe: 'home-assistant' } }) });
    const o = runtimeOverridesOf({ hosts: { 'ha.example.test': { mode: 'open' }, 'new.example.test': { mode: 'gated', passthrough: 'api' } }, access: { allowIps: [] }, limits: { failLimit: 5 } });
    const s = applyOverrides(settings(env), o);
    expect(s.allowIps).toEqual([]); // an empty list is a real value, not "unset"
    expect(s.failLimit).toBe(5);
    expect(s.scanLimit).toBe(100);
    const hosts = applyHostOverrides(hostTableOf(env.HOSTS_JSON), o);
    expect(hosts['ha.example.test']).toMatchObject({ mode: 'open' });
    expect(hosts['new.example.test']!.passthrough?.headers).toContain('authorization');
  });

  it('resolveRuntime reads KV once and the cache holds for CACHE_MS', async () => {
    const kv = new FakeKV();
    const env = makeEnv(kv, new FakeAnalytics());
    let now = 1_800_000_000_000;
    const cache = createRuntimeCache(() => now);
    expect((await cache.get(env)).overridden).toBe(false);
    await kv.put('settings:runtime', JSON.stringify({ limits: { failLimit: 7 } }));
    expect((await cache.get(env)).settings.failLimit).toBe(3); // cached
    now += CACHE_MS + 1;
    expect((await cache.get(env)).settings.failLimit).toBe(7);
    await kv.put('settings:runtime', JSON.stringify({ limits: { failLimit: 9 } }));
    cache.invalidate();
    expect((await cache.get(env)).settings.failLimit).toBe(9);
    expect((await resolveRuntime(env)).overridden).toBe(true);
  });
});
