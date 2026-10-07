/**
 * Writes `wrangler.jsonc` from `wicket.yaml` for people who deploy with wrangler instead of
 * the cf CLI:  npm run config:wrangler && npx wrangler deploy && npx wrangler secret bulk secrets.json
 *
 * The file is generated and git-ignored; edit wicket.yaml, not the output.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { RECIPES } from '../src/recipes/index.ts';
import { configPath, loadConfig, toCrons, toRoutes, toVars } from './config.ts';

const path = configPath();
const cfg = loadConfig(path, new Set(Object.keys(RECIPES)));

if (!cfg.cloudflare.kvNamespaceId) {
  console.error('wicket.yaml: cloudflare.kv_namespace_id is required for wrangler (create one with `npx wrangler kv namespace create STORE`).');
  process.exit(1);
}

const wrangler = {
  $schema: 'node_modules/wrangler/config-schema.json',
  name: cfg.worker,
  main: 'src/index.ts',
  compatibility_date: '2026-09-01',
  workers_dev: false,
  observability: { enabled: true },
  routes: toRoutes(cfg).map((r) => ({ pattern: r.pattern, zone_name: r.zone })),
  triggers: { crons: toCrons(cfg) },
  vars: toVars(cfg),
  kv_namespaces: [{ binding: 'STORE', id: cfg.cloudflare.kvNamespaceId }],
  analytics_engine_datasets: [{ binding: 'TRAFFIC', dataset: cfg.cloudflare.analyticsDataset }],
};

const out = resolve(process.cwd(), 'wrangler.jsonc');
writeFileSync(out, `// Generated from ${path} by deploy/wrangler.ts — do not edit.\n${JSON.stringify(wrangler, null, 2)}\n`);
console.log(`wrote ${out}: ${Object.keys(cfg.hosts).length} routes, crons ${toCrons(cfg).join(' | ')}`);
