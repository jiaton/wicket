import { CRS_RESTRICTED_FILES, CRS_SCANNER_AGENTS } from './signatures.generated';

/**
 * Scanner signatures: requests no legitimate visitor makes. A few hits from one address
 * inside a short window are a ban (`limits.signatures`), well before the probe-count
 * thresholds. Three sources:
 *   - OWASP CRS restricted files (signatures.generated.ts): dotfiles, credentials, configs
 *   - OWASP CRS scanner User-Agents (same file)
 *   - the paths below: the login pages, admin panels and exploit endpoints every bot tries,
 *     whatever software is actually behind the host
 * Users add their own with `signatures:` in wicket.yaml (regular expressions).
 */
export const PROBE_PATHS: readonly string[] = [
  '/wp-login.php',
  '/wp-admin',
  '/wp-content/',
  '/wp-includes/',
  '/xmlrpc.php',
  '/wlwmanifest.xml',
  '/phpmyadmin',
  '/pma/',
  '/myadmin/',
  '/adminer',
  '/vendor/phpunit',
  '/phpunit/',
  '/eval-stdin.php',
  '/cgi-bin/',
  '/boaform/',
  '/hnap1',
  '/goform/',
  '/shell',
  '/actuator/',
  '/solr/',
  '/console/',
  '/manager/html',
  '/jmx-console',
  '/owa/',
  '/autodiscover/',
  '/ecp/',
  '/telescope/',
  '/_ignition/',
  '/_profiler/',
  '/debug/default/view',
  '/server-status',
  '/.git/',
  '/.svn/',
  '/.hg/',
  '/.ds_store',
  '/.vscode/',
  '/.idea/',
  '/backup.sql',
  '/dump.sql',
  '/db.sql',
  '/database.sql',
  '/config.php.bak',
  '/wp-config.php',
  '/phpinfo.php',
  '/info.php',
  '/remote/login',
  '/+csco+/',
  '/geoserver/',
  '/api/v1/pods',
  '/.well-known/openid-configuration/jwks',
];

export interface SignatureSets {
  paths: RegExp[];
  agents: RegExp[];
}

/** Compiles the user's extra patterns (newline-separated regex sources); bad ones are skipped. */
export function compileExtra(paths: string | undefined, agents: string | undefined): SignatureSets {
  const compile = (s: string | undefined) =>
    (s ?? '')
      .split('\n')
      .map((x) => x.trim())
      .filter(Boolean)
      .flatMap((x) => {
        try {
          return [new RegExp(x, 'i')];
        } catch {
          return [];
        }
      });
  return { paths: compile(paths), agents: compile(agents) };
}

/**
 * Returns a short description of the matching signature, or null. Path checks are
 * case-insensitive substring checks against a lower-cased, decoded path.
 */
export function matchSignature(pathname: string, userAgent: string, extra: SignatureSets): string | null {
  let path = pathname.toLowerCase();
  try {
    path = decodeURIComponent(path);
  } catch {
    /* keep the raw path */
  }
  // Dot-directories (`/.git/`, `/.svn/`, …) are "file" signatures like the CRS restricted
  // files: never legitimate on any app, whatever it answers. `/.well-known/` is not one.
  for (const p of PROBE_PATHS) if (path.includes(p)) return `${p.startsWith('/.') && !p.startsWith('/.well-known/') ? 'file' : 'path'} ${p}`;
  for (const f of CRS_RESTRICTED_FILES) if (path.includes(`/${f}`)) return `file ${f}`;
  for (const re of extra.paths) if (re.test(pathname)) return `path ~ ${re.source}`;
  const ua = userAgent.toLowerCase();
  if (ua) {
    for (const a of CRS_SCANNER_AGENTS) if (ua.includes(a)) return `agent ${a}`;
    for (const re of extra.agents) if (re.test(userAgent)) return `agent ~ ${re.source}`;
  }
  return null;
}
