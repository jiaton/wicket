import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { ConfigError, configSource, configText, duration, loadConfig, parseConfig, toCrons, toRoutes, toVars } from '../deploy/config';
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
    expect(cfg.allowDns).toEqual([]);
    expect(cfg.trustWindow).toBe(86_400);
    expect(toVars(cfg).TRUST_SECONDS).toBe('86400');
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
    expect(bad(`${minimal}\nallow_dns: ['not a host']`)).toThrow(/allow_dns/);
    expect(parseConfig(parse(`${minimal}\nallow_dns: [Home.Example.DuckDNS.org]\ntrust_window: 0`), RECIPE_NAMES)).toMatchObject({ allowDns: ['home.example.duckdns.org'], trustWindow: 0 });
    expect(parseConfig(parse(`${minimal}\nlimits: { signatures: { count: 0 } }`), RECIPE_NAMES).limits.signatures.count).toBe(0);
  });

  it('ships an example that validates against the built-in recipes', () => {
    const cfg = loadConfig(resolve(process.cwd(), 'wicket.example.yaml'), RECIPE_NAMES);
    expect(cfg.zone).toBe('example.com');
    expect(Object.keys(cfg.hosts).length).toBeGreaterThan(2);
  });

  it('takes the whole config from $WICKET_YAML, as text or base64', () => {
    expect(configText({})).toBeNull();
    expect(configText({ WICKET_YAML: '  ' })).toBeNull();
    expect(configText({ WICKET_YAML: minimal })).toEqual({ text: minimal.trim(), label: '$WICKET_YAML' });
    const b64 = Buffer.from(minimal).toString('base64');
    expect(configText({ WICKET_YAML: b64 })).toEqual({ text: minimal.trim(), label: '$WICKET_YAML (base64)' });
    expect(() => configText({ WICKET_YAML: 'hosts: []' })).toThrow(/neither/);
    process.env.WICKET_YAML = b64;
    try {
      expect(loadConfig(undefined, RECIPE_NAMES).zone).toBe('example.test');
      expect(configSource()).toBe('$WICKET_YAML (base64)');
    } finally {
      delete process.env.WICKET_YAML;
    }
  });
});

describe('passthrough', () => {
  it('accepts the api preset or a mapping on gated hosts and compiles it into HOSTS_JSON', () => {
    const cfg = parseConfig(parse(`${minimal}\n  api.example.test: { passthrough: api }\n  app.example.test:\n    passthrough: { headers: [Authorization, X-Session], cookies: [sid], paths: [/api/] }`), RECIPE_NAMES);
    expect(cfg.hosts['api.example.test']!.passthrough).toEqual({ headers: ['authorization', 'x-api-key', 'x-access-token'], cookies: [], params: ['token'], paths: [] });
    expect(cfg.hosts['app.example.test']!.passthrough).toEqual({ headers: ['authorization', 'x-session'], cookies: ['sid'], params: [], paths: ['/api/'] });
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), toVars(cfg));
    expect(hostConfig(env, 'app.example.test')).toMatchObject({ mode: 'gated', passthrough: { cookies: ['sid'], paths: ['/api/'] } });
    expect(hostConfig(env, 'nas.example.test').passthrough).toBeUndefined();
  });

  it('rejects unknown presets, empty rules, bad paths, forbidden headers and observe hosts', () => {
    expect(bad(`${minimal}\n  a.example.test: { passthrough: nope }`)).toThrow(/unknown preset/);
    expect(bad(`${minimal}\n  a.example.test: { passthrough: { paths: [/api/] } }`)).toThrow(/at least one/);
    expect(bad(`${minimal}\n  a.example.test: { passthrough: { headers: [x], paths: [api] } }`)).toThrow(/must start with/);
    expect(bad(`${minimal}\n  a.example.test: { passthrough: { headers: [Cookie] } }`)).toThrow(/cannot be a credential carrier/);
    expect(bad(`${minimal}\n  a.example.test: { mode: observe, passthrough: api }`)).toThrow(/only applies to mode: gated/);
  });
});

describe('routes and modes', () => {
  it('wildcard routes need no host list; unlisted hosts get default_mode', () => {
    const cfg = parseConfig(parse('zone: example.test\nroutes: wildcard\ndefault_mode: open\nhosts:\n  nas.example.test: gated\n  old.example.test: off'), RECIPE_NAMES);
    expect(toRoutes(cfg)).toEqual([{ pattern: '*.example.test/*', zone: 'example.test' }]);
    const vars = toVars(cfg);
    expect(vars.DEFAULT_MODE).toBe('open');
    const env = makeEnv(new FakeKV(), new FakeAnalytics(), vars);
    expect(hostConfig(env, 'nas.example.test').mode).toBe('gated');
    expect(hostConfig(env, 'old.example.test').mode).toBe('off');
    expect(hostConfig(env, 'anything.example.test').mode).toBe('open');
    expect(parseConfig(parse('zone: example.test\nroutes: wildcard'), RECIPE_NAMES).hosts).toEqual({});
    expect(bad('zone: example.test\nroutes: everywhere\nhosts: { a.example.test: gated }')).toThrow(/routes must be/);
    expect(bad('zone: example.test\ndefault_mode: shut\nhosts: { a.example.test: gated }')).toThrow(/default_mode/);
    expect(bad('zone: example.test\nhosts: { a.example.test: { mode: open, passthrough: api } }')).toThrow(/passthrough only applies/);
  });
});
