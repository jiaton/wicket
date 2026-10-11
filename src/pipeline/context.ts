import type { Env } from '../config/env';
import type { HostConfig } from '../config/hosts';
import type { Settings } from '../config/settings';
import type { RecentSet, SlidingCounter } from '../core/counters';
import type { Fetch } from '../notify';

/** Injected I/O so tests run in plain Node with a fake network and a fake clock. */
export interface Deps {
  fetch: Fetch;
  /** Milliseconds since epoch. */
  now: () => number;
}

/** What happened to a request; written to Analytics Engine and used by the cron queries. */
export type Outcome =
  | 'pass' // valid cookie → origin
  | 'token' // valid API token → origin
  | 'allow' // allow-listed address → origin
  | 'bypass' // ACME challenge or BYPASS_PREFIXES → origin
  | 'preflight' // CORS OPTIONS → origin
  | 'observe' // observe-mode passthrough
  | 'origin-fail' // observe-mode passthrough whose origin answer matched a watch rule
  | 'login' // password accepted
  | 'fail' // wrong password/token (not yet banned)
  | 'ban' // this request triggered a password/token ban
  | 'ban-scan' // this request triggered a scanner ban (signature or burst)
  | 'ban-origin' // this request triggered a ban for failed logins at the app itself
  | 'banned' // already banned
  | 'locked' // lockdown in effect
  | 'unban' // unban / lift-lockdown link used
  | 'logout'
  | 'admin' // owner settings page
  | 'reject'; // no credentials → 401

/** Everything a pipeline step may need; built once per request by the handler. */
export interface Ctx {
  req: Request;
  url: URL;
  ip: string;
  /** Country code of the visitor. */
  cc: string;
  env: Env;
  cfg: Settings;
  host: HostConfig;
  deps: Deps;
  exec: ExecutionContext;
  /** Per-isolate scanner counter shared across requests. */
  scanner: SlidingCounter;
  /** Per-isolate counter of known scanner signature hits. */
  signatures: SlidingCounter;
  /**
   * Addresses this isolate banned in the last few minutes. KV caches a miss for up to a
   * minute, so without this a scanner that keeps hammering would be banned again and again
   * (each time a KV write, a list call and a notification).
   */
  recentBans: RecentSet;
  /** Static allow list plus resolved `allow_dns` names (cached per isolate). */
  allowed: () => Promise<boolean>;
  /** Remembers that this address holds an owner session (throttled KV write). */
  trust: () => void;
}

export type Result = [Response, Outcome];

/** A step either answers the request (returns a Result) or declines (returns null). */
export type Step = (c: Ctx) => Promise<Result | null>;
