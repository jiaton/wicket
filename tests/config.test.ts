import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { ConfigError, duration, loadConfig, parseConfig, toCrons, toRoutes, toVars } from '../deploy/config';
import { RECIPES } from '../src/recipes';
import { hostConfig } from '../src/config/hosts';
import { settings } from '../src/config/settings';
import { FakeAnalytics, FakeKV, makeEnv } from './helpers';

const RECIPE_NAMES = new Set(Object.keys(RECIPES));

const minimal = `
zone: example.test
hosts:
  nas.example.test: gated
  ha.example.test: { mode: observe, recipe: home-assistant }
  blog.example.test:
    mode: observe
    watch:
      - { path: /api/unlock, methods: [post], status: [401] }
`;

const bad = (yaml: string) => () => parseConfig(parse(yaml), RECIPE_NAMES);

describe('wicket.yaml', () => {
  it('fills every default from a minimal file', () => {
    const cfg = parseConfig(parse(minimal), RECIPE_NAMES);
    expect(cfg.worker).toBe('wicket');
    expect(cfg.siteName).toBe('example.test');
    expect(cfg.cookieDomain).toBe('example.test');
    expect(cfg.limits.password).toEqual({ count: 3, window: 86_400 });
    expect(cfg.limits.rotating).toEqual({ count: 10, window: 600, lockdown: 3600 });
    expect(cfg.limits.scanning).toEqual({ count: 30 });
    expect(cfg.limits.signatures).toEqual({ count: 3, window: 600 });
    expect(cfg.signatures).toEqual({ paths: [], agents: [] });
    expect(toVars(cfg).SCANNING_LIMIT).toBe('30');
    expect(cfg.cloudflare.cron).toBe('*/5 * * * *');
    expect(toCrons(cfg)).toEqual(['*/5 * * * *', '17 * * * *']);
    expect(toRoutes(cfg)).toEqual([
      { pattern: 'nas.example.test/*', zone: 'example.test' },
      { pattern: 'ha.example.test/*', zone: 'example.test' },
      { pattern: 'blog.example.test/*', zone: 'example.test' },
    ]);
  });

  it('compiles to vars the Worker parses back identically', () => {
    const cfg = parseConfig(parse(minimal), RECIPE_NAMES);
    const vars = toVars(cfg);
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), vars);
    expect(hostConfig(env, 'nas.example.test')).toEqual({ mode: 'gated', recipe: undefined, watch: [] });
    expect(hostConfig(env, 'ha.example.test')).toEqual({ mode: 'observe', recipe: 'home-assistant', watch: [] });
    expect(hostConfig(env, 'blog.example.test').watch).toEqual([{ path: '/api/unlock', methods: ['POST'], status: [401] }]);
    const s = settings(env);
    expect(s.failLimit).toBe(3);
    expect(s.lockdownSeconds).toBe(3600);
    expect(s.scanningLimit).toBe(30);
    expect(s.cookieDomain).toBe('example.test');
    expect(s.analyticsDataset).toBe('wicket_traffic');
    expect(s.reconcileCron).toBe('17 * * * *');
    // Gated hosts are the default and do not need to appear in HOSTS_JSON.
    expect(JSON.parse(vars.HOSTS_JSON!)).not.toHaveProperty('nas.example.test');
  });

  it('parses durations', () => {
    expect(duration('10m', 'x', 1)).toBe(600);
    expect(duration('24h', 'x', 1)).toBe(86_400);
    expect(duration('7d', 'x', 1)).toBe(604_800);
    expect(duration(90, 'x', 1)).toBe(90);
    expect(duration(undefined, 'x', 42)).toBe(42);
    expect(() => duration('soon', 'x', 1)).toThrow(ConfigError);
  });

  it('rejects hosts outside the zone, unknown recipes and watch rules on gated hosts', () => {
    expect(bad('zone: example.test\nhosts:\n  nas.other.test: gated')).toThrow(/not inside zone/);
    expect(bad('zone: example.test\nhosts:\n  x.example.test: { mode: observe, recipe: nope }')).toThrow(/unknown recipe/);
    expect(bad('zone: example.test\nhosts:\n  x.example.test: { mode: gated, recipe: immich }')).toThrow(/only apply to mode: observe/);
    expect(bad('zone: example.test\nhosts:\n  x.example.test: sometimes')).toThrow(/mode must be/);
    expect(bad('zone: example.test\nhosts: {}')).toThrow(/at least one hostname/);
    expect(bad('hosts:\n  x.example.test: gated')).toThrow(/zone is required/);
  });

  it('rejects bypass and admin hosts that are not routed', () => {
    expect(bad(`${minimal}\nbypass: [other.example.test/hook]`)).toThrow(/bypass/);
    expect(bad(`${minimal}\nalerts: { admin_hosts: [other.example.test] }`)).toThrow(/admin_hosts/);
    expect(bad(`${minimal}\nalerts: { quiet_hours: "late" }`)).toThrow(/quiet_hours/);
    expect(bad(`${minimal}\nsignatures: { paths: ['(oops'] }`)).toThrow(/not a valid regular expression/);
    expect(parseConfig(parse(`${minimal}\nlimits: { signatures: { count: 0 } }`), RECIPE_NAMES).limits.signatures.count).toBe(0);
  });

  it('ships an example that validates against the built-in recipes', () => {
    const cfg = loadConfig(resolve(process.cwd(), 'wicket.example.yaml'), RECIPE_NAMES);
    expect(cfg.zone).toBe('example.com');
    expect(Object.keys(cfg.hosts).length).toBeGreaterThan(2);
  });
});
