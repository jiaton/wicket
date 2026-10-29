/**
 * Writes `wrangler.jsonc` from the config for people who deploy with wrangler instead of
 * the cf CLI, locally (`npm run config:wrangler && npx wrangler deploy`) or as the build
 * command of a Workers Builds project (config in the `WICKET_YAML` build variable).
 *
 * The file is generated and git-ignored; edit wicket.yaml, not the output.
 *
 * KV: wrangler needs a namespace id. When `cloudflare.kv_namespace_id` is empty this script
 * finds or creates one named `<worker>-STORE` with the wrangler credentials at hand (a
 * Workers Builds job has them), so repeated builds reuse the same namespace instead of
 * failing on a duplicate title. Without credentials the id is left out and wrangler's own
 * provisioning creates one on the first deploy.
 */
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { RECIPES } from '../src/recipes/index.ts';
import { configSource, loadConfig, toCrons, toRoutes, toVars } from './config.ts';

const source = configSource();
const cfg = loadConfig(undefined, new Set(Object.keys(RECIPES)));

function wrangler(args: string[]): string {
  // CI=1 keeps wrangler from opening a browser to log in when it has no credentials.
  return execFileSync('npx', ['wrangler', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: '1' } });
}

const findNamespace = (title: string): string | undefined =>
  (JSON.parse(wrangler(['kv', 'namespace', 'list'])) as { id: string; title: string }[]).find((n) => n.title === title)?.id;

/** The id of the namespace titled `title`, created when missing; null when wrangler has no credentials. */
function ensureNamespace(title: string): string | null {
  let id: string | undefined;
  try {
    id = findNamespace(title);
  } catch {
    console.warn(`[wicket] wrangler cannot list KV namespaces here; leaving the id out so \`wrangler deploy\` provisions one`);
    return null;
  }
  if (id) {
    console.log(`[wicket] KV namespace ${title}: ${id}`);
    return id;
  }
  wrangler(['kv', 'namespace', 'create', title]);
  id = findNamespace(title);
  if (!id) throw new Error(`[wicket] created KV namespace ${title} but cannot find it in the list`);
  console.log(`[wicket] created KV namespace ${title}: ${id}`);
  return id;
}

const kvId: string | null = cfg.cloudflare.kvNamespaceId ? cfg.cloudflare.kvNamespaceId : ensureNamespace(`${cfg.worker}-STORE`);

// First-run setup token, as cloudflare.config.ts does for the cf CLI: fresh each build, printed,
// meaningless once an owner password exists.
const setupToken = cfg.setup ? Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, '0')).join('') : '';
if (setupToken) {
  const host = Object.keys(cfg.hosts)[0] ?? `<any proxied host under ${cfg.zone}>`;
  console.error(`[wicket] setup link, for a deploy without an OWNER_PASSWORD secret (ignored once a password exists): https://${host}/__wicket/setup?token=${setupToken}`);
}

const wranglerConfig = {
  $schema: 'node_modules/wrangler/config-schema.json',
  name: cfg.worker,
  main: 'src/index.ts',
  compatibility_date: '2026-09-01',
  workers_dev: false,
  observability: { enabled: true },
  routes: toRoutes(cfg).map((r) => ({ pattern: r.pattern, zone_name: r.zone })),
  triggers: { crons: toCrons(cfg) },
  vars: { ...toVars(cfg), ...(setupToken ? { SETUP_TOKEN: setupToken } : {}) },
  kv_namespaces: [{ binding: 'STORE', ...(kvId ? { id: kvId } : {}) }],
  analytics_engine_datasets: [{ binding: 'TRAFFIC', dataset: cfg.cloudflare.analyticsDataset }],
};

const out = resolve(process.cwd(), 'wrangler.jsonc');
writeFileSync(out, `// Generated from ${source} by deploy/wrangler.ts — do not edit.\n${JSON.stringify(wranglerConfig, null, 2)}\n`);
console.log(`wrote ${out}: ${Object.keys(cfg.hosts).length} routes, crons ${toCrons(cfg).join(' | ')}`);
