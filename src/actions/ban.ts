import { LIST_COMMENT_MARKER, listAdd } from '../cloudflare/lists';
import { signUnban } from '../core/crypto';
import { emit } from '../notify';
import { LOCKDOWN_IP, startLockdown, writeBan, type BanKind } from '../store/bans';
import type { Ctx } from '../pipeline/context';

const UNBAN_LINK_SECONDS = 7 * 86_400;

/** Signed, expiring one-click link that lifts a ban (`ip`) or the lockdown (`*`). */
export async function unbanLink(c: Ctx, ip: string): Promise<string> {
  const exp = Math.floor(c.deps.now() / 1000) + UNBAN_LINK_SECONDS;
  const sig = await signUnban(c.env.COOKIE_SECRET, ip, exp);
  return `${c.url.origin}/__wicket/unban?ip=${encodeURIComponent(ip)}&exp=${exp}&sig=${sig}`;
}

/**
 * The single exit for every ban trigger: KV record, Cloudflare IP list (edge block on all
 * proxied hosts), notification with the Unban link. Scanner bans are routine (`info`);
 * bans from wrong credentials or failed app logins are `warn`.
 */
export async function banAddress(c: Ctx, ip: string, kind: BanKind, fails: number): Promise<void> {
  await writeBan(c.env, ip, { at: c.deps.now(), host: c.url.hostname, country: c.cc, kind });
  c.exec.waitUntil(announceBan(c, ip, kind, fails));
}

async function announceBan(c: Ctx, ip: string, kind: BanKind, fails: number): Promise<void> {
  const reason =
    kind === 'scan'
      ? `${fails} anonymous probes in ${c.cfg.scanWindowSeconds}s (scanner)`
      : kind === 'origin'
        ? `${fails} failed logins at the app itself`
        : `${fails} wrong ${kind === 'token' ? 'API tokens' : 'passwords'}`;
  const edge = await listAdd(c.env, c.deps.fetch, ip, `${LIST_COMMENT_MARKER}${c.cfg.siteName}: ${reason} on ${c.url.hostname}`).catch(() => false);
  await emit(c.env, c.deps.fetch, {
    kind: kind === 'scan' ? 'scanner' : kind === 'origin' ? 'app_logins' : 'credentials',
    severity: kind === 'scan' ? 'info' : 'warn',
    title: `${c.cfg.siteName}: banned ${ip} (${c.cc})`,
    text: `${reason} on ${c.url.hostname}.${edge ? ' Also added to the Cloudflare IP list.' : ''}`,
    link: { text: 'Unban', url: await unbanLink(c, ip) },
    ip,
    cc: c.cc,
    host: c.url.hostname,
  }, c.deps.now());
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
