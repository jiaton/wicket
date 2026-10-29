import { banAddress } from '../actions/ban';
import { carriesAppCredential } from '../config/hosts';
import { apiTokens, matchToken } from '../config/tokens';
import type { Env } from '../config/env';
import { RecentSet, SlidingCounter } from '../core/counters';
import { createFallbackTick } from '../cron';
import { cookieValue, presentedToken, stripCredentials, wantsHtml } from '../core/credentials';
import { verifySession } from '../core/crypto';
import { clientIp, country } from '../core/ip';
import { isBanned, isLockedDown } from '../store/bans';
import { messagePage } from '../ui/pages';
import type { Ctx, Deps, Outcome, Result, Step } from './context';
import { endpoints, loginForm } from './endpoints';
import { registerFailure } from './failures';
import { observe, passthrough as appPassthrough } from './observe';
import { signatureStrike } from './signatures';
import { createAllowCheck } from './allow';
import { createTrustRefresher } from '../store/trust';
import { createRuntimeCache, hostOf } from '../runtime';
import { html, json } from './respond';

const ACME_PREFIX = '/.well-known/acme-challenge/';

const passthrough = async (c: Ctx, outcome: Outcome): Promise<Result> => [await c.deps.fetch(stripCredentials(c.req)), outcome];

/**
 * The request pipeline, in order. Each step answers or declines; the first answer wins.
 * Adding a check = adding a step here (and a test); nothing else needs to know about it.
 */
export const STEPS: Step[] = [
  // 1. Our own endpoints (login form, logout, unban) — before every other check so a banned
  //    owner can still use the signed unban link.
  endpoints,

  // 2. Allow-listed addresses (e.g. the household's public IP) never see a password page.
  async (c) => ((await c.allowed()) ? passthrough(c, 'allow') : null),

  // 3. Banned addresses get nothing, on every host and every path. The isolate's own memory
  //    of recent bans comes first: KV may still answer "not banned" for a minute.
  async (c) => (c.recentBans.has(c.ip) || (await isBanned(c.env, c.ip)) ? [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'banned'] : null),

  // 4. ACME HTTP-01: certificate validators fetch this anonymously; the origin answers 404
  //    unless a challenge is pending, so this leaks nothing and keeps renewals working.
  async (c) => (c.url.pathname.startsWith(ACME_PREFIX) ? passthrough(c, 'bypass') : null),

  // 5. Hosts that are not gated: observe (forward, watch, count), open (forward untouched),
  //    off (maintenance page). Bans above still apply to all of them.
  async (c) => {
    switch (c.host.mode) {
      case 'observe':
        return observe(c);
      case 'open':
        return passthrough(c, 'open');
      case 'off':
        return [html(messagePage('Temporarily closed', 'This host is switched off by its owner.'), 503, { 'retry-after': '600' }), 'off'];
      default:
        return null;
    }
  },

  // 6. Configured open prefixes (webhooks, native clients).
  async (c) => (c.cfg.bypass.some((b) => b.host === c.url.hostname && c.url.pathname.startsWith(b.prefix)) ? passthrough(c, 'bypass') : null),

  // 7. CORS preflights carry no credentials by design; the origin's CORS policy answers them.
  async (c) => (c.req.method === 'OPTIONS' ? passthrough(c, 'preflight') : null),

  // 8. Registered API tokens pass (and stay in the request for the origin).
  async (c) => {
    const presented = presentedToken(c.req, c.url);
    return presented && matchToken(presented.value, c.url.hostname, apiTokens(c.env)) ? passthrough(c, 'token') : null;
  },

  // 9. The app's own credential (hosts.<name>.passthrough): the request goes to the app, which
  //    decides; its 401 counts as a failed login for the address. wicket stores no app tokens.
  async (c) => (c.host.passthrough && carriesAppCredential(c.host.passthrough, c.req, c.url) ? appPassthrough(c) : null),

  // 10. A wrong explicit token is a strike; a foreign bearer is ignored, not punished.
  async (c) => {
    const presented = presentedToken(c.req, c.url);
    if (!presented?.explicit) return null;
    if (await isLockedDown(c.env)) return [json({ error: 'locked' }, 403), 'locked'];
    return registerFailure(c, 'token');
  },

  // 11. The session cookie.
  async (c) => {
    const session = await verifySession(
      cookieValue(c.req),
      c.env.COOKIE_SECRET,
      { owner: c.env.OWNER_PASSWORD, friend: c.env.FRIEND_PASSWORD },
      Math.floor(c.deps.now() / 1000),
      c.cfg.cookieSeconds,
    );
    if (!session) return null;
    if (session.role === 'owner') c.trust();
    return passthrough(c, 'pass');
  },

  // 12. Nothing presented. A few requests for known scanner paths/agents, or hundreds of
  //     anonymous probes in a minute = scanner → ban; otherwise the password page (or a
  //     JSON 401 for non-browsers).
  async (c) => {
    const strike = await signatureStrike(c);
    if (strike) return strike;
    if (c.scanner.hit(c.ip, c.cfg.scanLimit, c.cfg.scanWindowSeconds * 1000)) {
      c.scanner.reset(c.ip);
      if (await banAddress(c, c.ip, 'scan', c.cfg.scanLimit)) return [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'ban-scan'];
    }
    if (!wantsHtml(c.req) || c.req.method !== 'GET') return [json({ error: 'password required' }, 401), 'reject'];
    return [loginForm(c, 401), 'reject'];
  },
];

/** Builds the fetch handler: one Ctx per request, the steps in order, one analytics row per request. */
export function createHandler(deps: Deps) {
  const scanner = new SlidingCounter(deps.now);
  const signatures = new SlidingCounter(deps.now);
  const recentBans = new RecentSet(deps.now);
  const allowCheck = createAllowCheck(deps);
  const refreshTrust = createTrustRefresher(deps.now);
  const fallbackTick = createFallbackTick(deps);
  const runtime = createRuntimeCache(deps.now);

  return async function fetchHandler(req: Request, env: Env, exec: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const started = deps.now();
    const ip = clientIp(req);
    const rt = await runtime.get(env);
    const cfg = rt.settings;
    const c: Ctx = {
      req,
      url,
      ip,
      cc: country(req),
      env,
      cfg,
      host: hostOf(env, rt, url.hostname),
      deps,
      exec,
      scanner,
      signatures,
      recentBans,
      allowed: () => allowCheck(env, cfg, ip),
      trust: () => refreshTrust(env, ip, cfg.trustSeconds, exec),
      invalidateRuntime: runtime.invalidate,
    };

    let result: Result = [json({ error: 'unhandled' }, 500), 'reject'];
    for (const step of STEPS) {
      const r = await step(c);
      if (r) {
        result = r;
        break;
      }
    }

    const [res, outcome] = result;
    try {
      env.TRAFFIC.writeDataPoint({
        indexes: [url.hostname],
        blobs: [url.hostname, url.pathname.slice(0, 256), c.ip, c.cc, outcome, req.method],
        doubles: [res.status, deps.now() - started],
      });
    } catch (err) {
      console.warn('analytics write failed', String(err));
    }
    // Periodic jobs ride on traffic when Cloudflare's cron does not deliver (see cron/index.ts).
    fallbackTick(env, exec);
    return res;
  };
}
