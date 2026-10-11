import { LIST_COMMENT_MARKER, listAdd } from '../cloudflare/lists';
import type { Env } from '../config/env';
import type { Settings } from '../config/settings';
import { signUnban } from '../core/crypto';
import { emit } from '../notify';
import { LOCKDOWN_IP, startLockdown, writeBan, type BanKind } from '../store/bans';
import type { Ctx, Deps } from '../pipeline/context';

const UNBAN_LINK_SECONDS = 7 * 86_400;

/** Signed, expiring one-click link that lifts a ban (`ip`) or the lockdown (`*`), served from `host`. */
export async function unbanLinkFor(env: Env, now: number, host: string, ip: string): Promise<string> {
  const exp = Math.floor(now / 1000) + UNBAN_LINK_SECONDS;
  const sig = await signUnban(env.COOKIE_SECRET, ip, exp);
  return `https://${host}/__wicket/unban?ip=${encodeURIComponent(ip)}&exp=${exp}&sig=${sig}`;
}

export const unbanLink = (c: Ctx, ip: string) => unbanLinkFor(c.env, c.deps.now(), c.url.hostname, ip);

export interface BanInput {
  ip: string;
  /** The host the ban is attributed to (and the one the Unban link is served from). */
  host: string;
  country: string;
  kind: BanKind;
  /** How many failures/probes led here. */
  fails: number;
  /** Human reason; derived from `kind` and `fails` when absent. */
  reason?: string;
}

/**
 * The single exit for every ban trigger, with or without a request: KV record, Cloudflare
 * IP list (edge block on all proxied hosts), notification with the Unban link. Scanner bans
 * are routine (`info`); bans from wrong credentials or failed app logins are `warn`.
 */
export async function recordBan(env: Env, deps: Deps, cfg: Settings, b: BanInput): Promise<void> {
  const now = deps.now();
  await writeBan(env, b.ip, { at: now, host: b.host, country: b.country, kind: b.kind });
  const reason =
    b.reason ??
    (b.kind === 'scan'
      ? `${b.fails} anonymous probes in ${cfg.scanWindowSeconds}s (scanner)`
      : b.kind === 'origin'
        ? `${b.fails} failed logins at the app itself`
        : `${b.fails} wrong ${b.kind === 'token' ? 'API tokens' : 'passwords'}`);
  const edge = await listAdd(env, deps.fetch, b.ip, `${LIST_COMMENT_MARKER}${cfg.siteName}: ${reason} on ${b.host}`).catch(() => false);
  await emit(
    env,
    deps.fetch,
    {
      kind: b.kind === 'scan' ? 'scanner' : b.kind === 'origin' ? 'app_logins' : 'credentials',
      severity: b.kind === 'scan' ? 'info' : 'warn',
      title: `${cfg.siteName}: banned ${b.ip} (${b.country})`,
      text: `${reason} on ${b.host}.${edge ? ' Also added to the Cloudflare IP list.' : ''}`,
      link: { text: 'Unban', url: await unbanLinkFor(env, now, b.host, b.ip) },
      ip: b.ip,
      cc: b.country,
      host: b.host,
    },
    now,
  );
}

/** Request-path ban: the KV record lands before the response, the rest rides on waitUntil. */
export async function banAddress(c: Ctx, ip: string, kind: BanKind, fails: number, reason?: string): Promise<void> {
  await writeBan(c.env, ip, { at: c.deps.now(), host: c.url.hostname, country: c.cc, kind });
  c.exec.waitUntil(recordBan(c.env, c.deps, c.cfg, { ip, host: c.url.hostname, country: c.cc, kind, fails, ...(reason ? { reason } : {}) }));
}

/** Pause password/token entry site-wide and tell the owner. */
export async function lockDown(c: Ctx, fails: number, minutes: number): Promise<void> {
  await startLockdown(c.env, { at: c.deps.now(), host: c.url.hostname, fails }, c.cfg.lockdownSeconds);
  c.exec.waitUntil(
    emit(c.env, c.deps.fetch, {
      kind: 'lockdown',
      severity: 'critical',
      title: `${c.cfg.siteName}: lockdown`,
      text: `${fails} wrong passwords/tokens from changing addresses within ${minutes} min (last on ${c.url.hostname}). Password entry is paused for ${Math.round(c.cfg.lockdownSeconds / 60)} min; sessions and API tokens still work.`,
      link: { text: 'Lift lockdown', url: await unbanLink(c, LOCKDOWN_IP) },
    }, c.deps.now()),
  );
}
