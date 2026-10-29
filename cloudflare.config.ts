/**
 * cf CLI config. Nothing deployment-specific lives here: hosts, zone, limits and the KV id
 * come from `wicket.yaml` (see wicket.example.yaml), compiled by deploy/config.ts when the
 * cf CLI evaluates this file. Secrets ride along with `cf deploy --secrets-file`.
 */
import { randomBytes } from 'node:crypto';

import { bindings, defineConfig, triggers } from 'cf/config';

import { loadConfig, toCrons, toRoutes, toVars } from './deploy/config.ts';
import { RECIPES } from './src/recipes/index.ts';

const cfg = loadConfig(undefined, new Set(Object.keys(RECIPES)));

// First-run setup: a fresh token every deploy, printed here, required to open /__wicket/setup.
// It stops mattering the moment an owner password exists (secrets or setup page).
const setupToken = cfg.setup ? Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, '0')).join('') : '';
if (setupToken) {
  const host = Object.keys(cfg.hosts)[0] ?? `<any proxied host under ${cfg.zone}>`;
  console.error(`[wicket] setup link, for a deploy without an OWNER_PASSWORD secret (ignored once a password exists): https://${host}/__wicket/setup?token=${setupToken}`);
}

export default defineConfig({
  worker: {
    name: cfg.worker,
    compatibilityDate: '2026-09-01',
    entrypoint: 'src/index.ts',
    workersDev: false,
    observability: { enabled: true },
    triggers: [
      ...toRoutes(cfg).map((route) => triggers.fetch(route)),
      ...toCrons(cfg).map((schedule) => triggers.scheduled({ schedule })),
    ],
    env: {
      ...Object.fromEntries(Object.entries({ ...toVars(cfg), ...(setupToken ? { SETUP_TOKEN: setupToken } : {}) }).map(([name, value]) => [name, bindings.text(value)])),
      TRAFFIC: bindings.analyticsEngineDataset({ name: cfg.cloudflare.analyticsDataset }),
      STORE: bindings.kv(cfg.cloudflare.kvNamespaceId ? { id: cfg.cloudflare.kvNamespaceId } : {}),
    },
  },
});
