import type { Env } from '../src/config/env';
import { createHandler } from '../src/pipeline/handler';

export class FakeKV {
  store = new Map<string, { value: string; expires?: number; metadata?: unknown }>();
  now = () => Date.now();
  async get(key: string): Promise<string | null> {
    const hit = this.store.get(key);
    if (!hit) return null;
    if (hit.expires !== undefined && hit.expires <= this.now()) {
      this.store.delete(key);
      return null;
    }
    return hit.value;
  }
  async put(key: string, value: string, opts?: { expirationTtl?: number; metadata?: unknown }): Promise<void> {
    this.store.set(key, { value, expires: opts?.expirationTtl ? this.now() + opts.expirationTtl * 1000 : undefined, metadata: opts?.metadata });
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  /** Prefix listing in two pages, so cursor handling is exercised. */
  async list(opts: { prefix?: string; cursor?: string } = {}): Promise<{ keys: { name: string; metadata?: unknown }[]; list_complete: boolean; cursor?: string }> {
    const names = [...this.store.keys()].filter((k) => k.startsWith(opts.prefix ?? '')).sort();
    const start = opts.cursor ? Number(opts.cursor) : 0;
    const page = names.slice(start, start + 2);
    const done = start + 2 >= names.length;
    return { keys: page.map((name) => ({ name, metadata: this.store.get(name)?.metadata })), list_complete: done, ...(done ? {} : { cursor: String(start + 2) }) };
  }
}

export class FakeAnalytics {
  points: AnalyticsEngineDataPoint[] = [];
  writeDataPoint(p: AnalyticsEngineDataPoint) {
    this.points.push(p);
  }
  outcomes() {
    return this.points.map((p) => String(p.blobs?.[4]));
  }
}

export interface Sent {
  url: string;
  init?: RequestInit;
  body?: unknown;
}

/** Fake network: records Telegram / Cloudflare calls and answers origin fetches with a marker. */
export function fakeNetwork(handlers: Record<string, (req: Request) => Response | Promise<Response>> = {}) {
  const sent: Sent[] = [];
  const origin: Request[] = [];
  const doFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const url = new URL(req.url);
    const NOTIFY_HOSTS = ['api.telegram.org', 'api.cloudflare.com', 'ntfy.example.test', 'discord.com', 'hooks.slack.com', 'hooks.example.test', 'apprise.example.test'];
    if (NOTIFY_HOSTS.includes(url.hostname)) {
      const text = await req.clone().text();
      let body: unknown = text || undefined;
      try {
        if (text) body = JSON.parse(text);
      } catch {
        /* SQL queries are plain text */
      }
      sent.push({ url: req.url, init, body });
      const handler = Object.entries(handlers).find(([k]) => req.url.includes(k))?.[1];
      return handler ? handler(req) : new Response(JSON.stringify({ ok: true, result: [] }), { status: 200 });
    }
    origin.push(req);
    return new Response(`origin:${url.pathname}`, { status: 200, headers: { 'x-origin': '1' } });
  };
  return { doFetch, sent, origin, telegram: () => sent.filter((s) => s.url.includes('telegram')) };
}

export function makeEnv(kv: FakeKV, analytics: FakeAnalytics, overrides: Partial<Env> = {}): Env {
  return {
    STORE: kv as unknown as KVNamespace,
    TRAFFIC: analytics as unknown as AnalyticsEngineDataset,
    COOKIE_SECRET: 'secret-for-tests',
    OWNER_PASSWORD: 'owner-pw',
    FRIEND_PASSWORD: 'friend-pw',
    TELEGRAM_BOT_TOKEN: 'bot',
    TELEGRAM_CHAT_ID: '1',
    COOKIE_DOMAIN: 'example.test',
    FAIL_LIMIT: '3',
    SITE_NAME: 'test',
    // Every kind immediate, so the older suites see one message per event; tests/settings.test.ts covers digests.
    NOTIFY_POLICY_JSON: JSON.stringify({ kinds: { scanner: 'immediate', credentials: 'immediate', app_logins: 'immediate', lockdown: 'immediate', traffic: 'immediate', reconcile: 'immediate', unban: 'immediate' }, digestSeconds: 3600 }),
    ...overrides,
  };
}

export const ctx = () => {
  const pending: Promise<unknown>[] = [];
  return {
    waitUntil: (p: Promise<unknown>) => void pending.push(p),
    passThroughOnException: () => {},
    settle: () => Promise.all(pending),
  } as ExecutionContext & { settle: () => Promise<unknown[]> };
};

export function harness(overrides: Partial<Env> = {}, handlers?: Parameters<typeof fakeNetwork>[0]) {
  const kv = new FakeKV();
  const analytics = new FakeAnalytics();
  const net = fakeNetwork(handlers);
  let now = 1_800_000_000_000;
  kv.now = () => now; // TTLs follow the fake clock
  const env = makeEnv(kv, analytics, overrides);
  const gate = createHandler({ fetch: net.doFetch, now: () => now });
  const request = (path: string, init: RequestInit & { ip?: string; host?: string } = {}) => {
    const { ip = '203.0.113.5', host = 'nas.example.test', ...rest } = init;
    const headers = new Headers(rest.headers);
    headers.set('cf-connecting-ip', ip);
    if (!headers.has('accept')) headers.set('accept', 'text/html');
    if (!headers.has('cf-ipcountry')) headers.set('cf-ipcountry', 'US');
    return new Request(`https://${host}${path}`, { ...rest, headers });
  };
  const run = async (req: Request) => {
    const c = ctx();
    const res = await gate(req, env, c);
    await c.settle();
    return res;
  };
  const login = (password: string, extra: Record<string, string> = {}, init: { ip?: string; host?: string } = {}) => {
    const body = new URLSearchParams({ password, next: '/dash', ...extra });
    return run(
      request('/__wicket/login', {
        ...init,
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
        body,
      }),
    );
  };
  return { kv, analytics, net, env, request, run, login, advance: (ms: number) => (now += ms), time: () => now };
}
