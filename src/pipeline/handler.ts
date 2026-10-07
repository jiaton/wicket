import { banAddress } from '../actions/ban';
import { hostConfig } from '../config/hosts';
import { settings } from '../config/settings';
import { apiTokens, matchToken } from '../config/tokens';
import type { Env } from '../config/env';
import { SlidingCounter } from '../core/counters';
import { createFallbackTick } from '../cron';
import { cookieValue, presentedToken, stripCredentials, wantsHtml } from '../core/credentials';
import { verifySession } from '../core/crypto';
import { clientIp, country, ipAllowed } from '../core/ip';
import { isBanned, isLockedDown } from '../store/bans';
import { messagePage } from '../ui/pages';
import type { Ctx, Deps, Outcome, Result, Step } from './context';
import { endpoints, loginForm } from './endpoints';
import { registerFailure } from './failures';
import { observe } from './observe';
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
  async (c) => (ipAllowed(c.ip, c.cfg.allowIps) ? passthrough(c, 'allow') : null),

  // 3. Banned addresses get nothing, on every host and every path.
  async (c) => ((await isBanned(c.env, c.ip)) ? [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'banned'] : null),

  // 4. ACME HTTP-01: certificate validators fetch this anonymously; the origin answers 404
  //    unless a challenge is pending, so this leaks nothing and keeps renewals working.
  async (c) => (c.url.pathname.startsWith(ACME_PREFIX) ? passthrough(c, 'bypass') : null),

  // 5. Observe mode: the app keeps its own login; we only watch and ban.
  async (c) => (c.host.mode === 'observe' ? observe(c) : null),

  // 6. Configured open prefixes (webhooks, native clients).
  async (c) => (c.cfg.bypass.some((b) => b.host === c.url.hostname && c.url.pathname.startsWith(b.prefix)) ? passthrough(c, 'bypass') : null),

  // 7. CORS preflights carry no credentials by design; the origin's CORS policy answers them.
  async (c) => (c.req.method === 'OPTIONS' ? passthrough(c, 'preflight') : null),

  // 8. API tokens. A registered token passes (and stays in the request for the origin);
  //    a wrong explicit token is a strike; a foreign bearer is ignored, not punished.
  async (c) => {
    const presented = presentedToken(c.req, c.url);
    if (!presented) return null;
    if (matchToken(presented.value, c.url.hostname, apiTokens(c.env))) return passthrough(c, 'token');
    if (!presented.explicit) return null;
    if (await isLockedDown(c.env)) return [json({ error: 'locked' }, 403), 'locked'];
    return registerFailure(c, 'token');
  },

  // 9. The session cookie.
  async (c) => {
    const session = await verifySession(
      cookieValue(c.req),
      c.env.COOKIE_SECRET,
      { owner: c.env.OWNER_PASSWORD, friend: c.env.FRIEND_PASSWORD },
      Math.floor(c.deps.now() / 1000),
      c.cfg.cookieSeconds,
    );
    return session ? passthrough(c, 'pass') : null;
  },

  // 10. Nothing presented. Hundreds of anonymous probes in a minute = scanner → ban;
  //     otherwise the password page (or a JSON 401 for non-browsers).
  async (c) => {
    if (c.scanner.hit(c.ip, c.cfg.scanLimit, c.cfg.scanWindowSeconds * 1000)) {
      c.scanner.reset(c.ip);
      await banAddress(c, c.ip, 'scan', c.cfg.scanLimit);
      return [html(messagePage('Blocked', 'This address has been blocked.'), 403), 'ban'];
    }
    if (!wantsHtml(c.req) || c.req.method !== 'GET') return [json({ error: 'password required' }, 401), 'reject'];
    return [loginForm(c, 401), 'reject'];
  },
];

/** Builds the fetch handler: one Ctx per request, the steps in order, one analytics row per request. */
export function createHandler(deps: Deps) {
  const scanner = new SlidingCounter(deps.now);
  const fallbackTick = createFallbackTick(deps);

  return async function fetchHandler(req: Request, env: Env, exec: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const started = deps.now();
    const c: Ctx = { req, url, ip: clientIp(req), cc: country(req), env, cfg: settings(env), host: hostConfig(env, url.hostname), deps, exec, scanner };

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
