import { LIST_COMMENT_MARKER, listAdd } from '../cloudflare/lists';
import type { Env } from '../config/env';
import type { Settings } from '../config/settings';
import { signUnban } from '../core/crypto';
import { emit } from '../notify';
import { addPendingEdge, LOCKDOWN_IP, startLockdown, writeBan, type BanKind } from '../store/bans';
import { isTrusted } from '../store/trust';
import type { Ctx, Deps } from '../pipeline/context';

const UNBAN_LINK_SECONDS = 7 * 86_400;
/** How long an isolate remembers its own bans (covers KV's eventual consistency with margin). */
export const RECENT_BAN_MS = 10 * 60_000;

/**
 * Signed, expiring one-click link that lifts a ban (`ip`) or the lockdown (`*`), served from
 * `host`. `at` is the record's timestamp: the link is only good for that ban, not for a later
 * one of the same address. Without a cookie secret there is no link (nothing to sign with).
 */
export async function unbanLinkFor(env: Env, now: number, host: string, ip: string, at: number): Promise<string | null> {
  if (!env.COOKIE_SECRET) return null;
  const exp = Math.floor(now / 1000) + UNBAN_LINK_SECONDS;
  const sig = await signUnban(env.COOKIE_SECRET, ip, exp, at);
  return `https://${host}/__wicket/unban?ip=${encodeURIComponent(ip)}&exp=${exp}&at=${at}&sig=${sig}`;
}

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

const persist = (env: Env, b: BanInput, now: number) => writeBan(env, b.ip, { at: now, host: b.host, country: b.country, kind: b.kind });

/** The edge list and the notification; the KV record is already written. */
async function announce(env: Env, deps: Deps, cfg: Settings, b: BanInput, now: number): Promise<void> {
  const reason =
    b.reason ??
    (b.kind === 'scan'
      ? `${b.fails} anonymous probes in ${cfg.scanWindowSeconds}s (scanner)`
      : b.kind === 'origin'
        ? `${b.fails} failed logins at the app itself`
        : `${b.fails} wrong ${b.kind === 'token' ? 'API tokens' : 'passwords'}`);
  const edge = await listAdd(env, deps.fetch, b.ip, `${LIST_COMMENT_MARKER}${cfg.siteName}: ${reason} on ${b.host}`).catch(() => false);
  // A failed list call (rate limit, outage) is retried by the five-minute job, not left for the hourly reconcile.
  if (!edge && env.CF_LIST_ID) await addPendingEdge(env, b.ip).catch(() => undefined);
  await emit(
    env,
    deps.fetch,
    {
      kind: b.kind === 'scan' ? 'scanner' : b.kind === 'origin' ? 'app_logins' : 'credentials',
      severity: b.kind === 'scan' ? 'info' : 'warn',
      title: `${cfg.siteName}: banned ${b.ip} (${b.country})`,
      text: `${reason} on ${b.host}.${edge ? ' Also added to the Cloudflare IP list.' : ''}`,
      ...(await linkTo(env, now, b.host, b.ip, now, 'Unban')),
      ip: b.ip,
      cc: b.country,
      host: b.host,
    },
    now,
  );
}

async function linkTo(env: Env, now: number, host: string, ip: string, at: number, text: string): Promise<{ link?: { text: string; url: string } }> {
  const url = await unbanLinkFor(env, now, host, ip, at);
  return url ? { link: { text, url } } : {};
}

/**
 * The single exit for every ban trigger, with or without a request: KV record, Cloudflare
 * IP list (edge block on all proxied hosts), notification with the Unban link. Scanner bans
 * are routine (`info`); bans from wrong credentials or failed app logins are `warn`.
 */
export async function recordBan(env: Env, deps: Deps, cfg: Settings, b: BanInput): Promise<boolean> {
  if (await isTrusted(env, b.ip)) {
    console.warn('not banning trusted address', b.ip, b.kind);
    return false;
  }
  const now = deps.now();
  await persist(env, b, now);
  await announce(env, deps, cfg, b, now);
  return true;
}

/**
 * Request-path ban: the KV record lands before the response, the rest rides on waitUntil,
 * and the isolate remembers the address so a scanner that keeps hammering is answered from
 * memory instead of being banned again while KV still reports a miss.
 * Returns false (and does nothing) for a trusted address.
 */
export async function banAddress(c: Ctx, ip: string, kind: BanKind, fails: number, reason?: string): Promise<boolean> {
  if (await isTrusted(c.env, ip)) return false;
  const b: BanInput = { ip, host: c.url.hostname, country: c.cc, kind, fails, ...(reason ? { reason } : {}) };
  const now = c.deps.now();
  // The isolate remembers the ban even if KV refuses the record below (quota, outage): the
  // address stays blocked here for RECENT_BAN_MS, and the owner is told about the failure.
  c.recentBans.add(ip, RECENT_BAN_MS);
  try {
    await persist(c.env, b, now);
  } catch (err) {
    c.kv.failed('ban record', err);
  }
  c.exec.waitUntil(announce(c.env, c.deps, c.cfg, b, now));
  return true;
}

/** Pause password/token entry site-wide and tell the owner. */
export async function lockDown(c: Ctx, fails: number, minutes: number): Promise<void> {
  const at = c.deps.now();
  await startLockdown(c.env, { at, host: c.url.hostname, fails }, c.cfg.lockdownSeconds);
  c.exec.waitUntil(
    emit(c.env, c.deps.fetch, {
      kind: 'lockdown',
      severity: 'critical',
      title: `${c.cfg.siteName}: lockdown`,
      text: `${fails} wrong passwords/tokens from changing addresses within ${minutes} min (last on ${c.url.hostname}). Password entry is paused for ${Math.round(c.cfg.lockdownSeconds / 60)} min; sessions and API tokens still work.`,
      ...(await linkTo(c.env, at, c.url.hostname, LOCKDOWN_IP, at, 'Lift lockdown')),
    }, at),
  );
}
