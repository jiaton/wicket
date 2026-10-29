import type { Settings } from '../config/settings';
import { COOKIE_NAME } from './crypto';

/** Paths the Worker owns on every gated host. */
export const ENDPOINT_PREFIX = '/__wicket/';
/** Token carriers specific to wicket; stripped before the origin sees the request. */
export const TOKEN_HEADER = 'x-wicket-token';
export const TOKEN_PARAM = 'wicket_token';
/** Headers the origins' own API clients already send; the same values go in API_TOKENS and pass through untouched. */
export const APP_TOKEN_HEADERS = ['x-access-token', 'x-api-key'];
/** Query parameter many apps use for their own token (URL-only MCP clients, WebSockets); left in place. */
export const APP_TOKEN_PARAM = 'token';

/** Host-only cookie set by a share link; `id.exp.sig`, valid for that host only. */
export const SHARE_COOKIE = '__wicket_share';

export function shareCookieValue(req: Request): string | undefined {
  for (const part of (req.headers.get('cookie') ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === SHARE_COOKIE) return v.join('=');
  }
  return undefined;
}

export const setShareCookie = (value: string, maxAge: number): string => `${SHARE_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;

export function cookieValue(req: Request): string | undefined {
  for (const part of (req.headers.get('cookie') ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE_NAME) return v.join('=');
  }
  return undefined;
}

/**
 * The origin never sees the wicket cookie or the wicket-only token carriers.
 * `Authorization`, `x-access-token`, `X-API-Key` and `?token=` are left alone even when
 * they matched: the origin validates the same value itself.
 */
export function stripCredentials(req: Request): Request {
  const h = new Headers(req.headers);
  const rest = (req.headers.get('cookie') ?? '')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith(`${COOKIE_NAME}=`) && !s.startsWith(`${SHARE_COOKIE}=`));
  if (rest.length) h.set('cookie', rest.join('; '));
  else h.delete('cookie');
  h.delete(TOKEN_HEADER);
  const url = new URL(req.url);
  if (!url.searchParams.has(TOKEN_PARAM)) return new Request(req, { headers: h });
  url.searchParams.delete(TOKEN_PARAM);
  return new Request(url.toString(), new Request(req, { headers: h }));
}

export interface PresentedToken {
  value: string;
  /** True for carriers that can only mean "a token for wicket or the app": a mismatch is a strike. */
  explicit: boolean;
  /** `wicket`: X-Wicket-Token / ?wicket_token= (a guess at wicket itself, counts toward the lockdown); `app`: an app-style header or ?token=; `bearer`: Authorization, never punished. */
  carrier: 'wicket' | 'app' | 'bearer';
}

/**
 * The API token a request presents, if any. A foreign `Authorization: Bearer` is never
 * punished when it does not match: it may be the origin's own auth.
 */
export function presentedToken(req: Request, url: URL): PresentedToken | null {
  const header = req.headers.get(TOKEN_HEADER);
  if (header) return { value: header, explicit: true, carrier: 'wicket' };
  const param = url.searchParams.get(TOKEN_PARAM);
  if (param) return { value: param, explicit: true, carrier: 'wicket' };
  for (const name of APP_TOKEN_HEADERS) {
    const v = req.headers.get(name);
    if (v) return { value: v, explicit: true, carrier: 'app' };
  }
  const appParam = url.searchParams.get(APP_TOKEN_PARAM);
  if (appParam) return { value: appParam, explicit: true, carrier: 'app' };
  const auth = req.headers.get('authorization') ?? '';
  if (auth.toLowerCase().startsWith('bearer ')) return { value: auth.slice(7).trim(), explicit: false, carrier: 'bearer' };
  return null;
}

export function setCookie(value: string, cfg: Settings, maxAge: number): string {
  const domain = cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : '';
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax${domain}`;
}

/** Only same-origin paths are valid redirect targets after login (the settings page is the one wicket path allowed). */
export function safeNext(next: string | null): string {
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\') || /[\u0000-\u001f\u007f]/.test(next)) return '/';
  if (next.startsWith(ENDPOINT_PREFIX)) return next === `${ENDPOINT_PREFIX}settings` ? next : '/';
  return next;
}

/** CSRF guard for the login form: same-origin or a direct navigation. */
export function sameOrigin(req: Request): boolean {
  const site = req.headers.get('sec-fetch-site');
  if (site) return site === 'same-origin' || site === 'none';
  const origin = req.headers.get('origin');
  return !origin || origin === new URL(req.url).origin;
}

export const wantsHtml = (req: Request): boolean => (req.headers.get('accept') ?? '').includes('text/html');
