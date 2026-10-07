/**
 * cf CLI config. Nothing deployment-specific lives here: hosts, zone, limits and the KV id
 * come from `wicket.yaml` (see wicket.example.yaml), compiled by deploy/config.ts when the
 * cf CLI evaluates this file. Secrets ride along with `cf deploy --secrets-file`.
 */
import { bindings, defineConfig, triggers } from 'cf/config';

import { loadConfig, toCrons, toRoutes, toVars } from './deploy/config.ts';
import { RECIPES } from './src/recipes/index.ts';

const cfg = loadConfig(undefined, new Set(Object.keys(RECIPES)));

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
      ...Object.fromEntries(Object.entries(toVars(cfg)).map(([name, value]) => [name, bindings.text(value)])),
      TRAFFIC: bindings.analyticsEngineDataset({ name: cfg.cloudflare.analyticsDataset }),
      STORE: bindings.kv(cfg.cloudflare.kvNamespaceId ? { id: cfg.cloudflare.kvNamespaceId } : {}),
    },
  },
});
