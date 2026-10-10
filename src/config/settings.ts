import { int, list, type Env } from './env';

/** Parsed numeric/list vars. Everything has a default so a fresh deploy works. */
export interface Settings {
  allowIps: string[];
  bypass: { host: string; prefix: string }[];
  /** Wrong passwords/tokens from one address before a permanent ban. */
  failLimit: number;
  failWindowSeconds: number;
  /** Failures from any address within the window that pause password entry (lockdown). */
  failGlobalLimit: number;
  failGlobalWindowSeconds: number;
  lockdownSeconds: number;
  /** Anonymous rejections (gated) or 4xx probes (observe) from one address = scanner. */
  scanLimit: number;
  scanWindowSeconds: number;
  /** Slow scanner ban from the five-minute analysis (network-wide count). */
  scanningLimit: number;
  /** Observe mode: matched origin login failures from one address before a ban. */
  originFailLimit: number;
  originFailWindowSeconds: number;
  cookieSeconds: number;
  cookieDomain: string;
  adminHosts: string[];
  quietHours: [number, number] | null;
  timezone: string;
  alertIpRequests: number;
  alertIpErrors: number;
  alertGuessIps: number;
  siteName: string;
  analyticsDataset: string;
  reconcileCron: string;
}

export function settings(env: Env): Settings {
  const quiet = (env.QUIET_HOURS ?? '').match(/^(\d{1,2})-(\d{1,2})$/);
  return {
    allowIps: list(env.ALLOW_IPS),
    bypass: list(env.BYPASS_PREFIXES).map((entry) => {
      const slash = entry.indexOf('/');
      return slash < 0 ? { host: entry, prefix: '/' } : { host: entry.slice(0, slash), prefix: entry.slice(slash) };
    }),
    failLimit: int(env.FAIL_LIMIT, 3),
    failWindowSeconds: int(env.FAIL_WINDOW_SECONDS, 86_400),
    failGlobalLimit: int(env.FAIL_GLOBAL_LIMIT, 10),
    failGlobalWindowSeconds: int(env.FAIL_GLOBAL_WINDOW_SECONDS, 600),
    lockdownSeconds: int(env.LOCKDOWN_SECONDS, 3600),
    scanLimit: int(env.SCAN_LIMIT, 100),
    scanWindowSeconds: int(env.SCAN_WINDOW_SECONDS, 60),
    scanningLimit: int(env.SCANNING_LIMIT, 30),
    originFailLimit: int(env.ORIGIN_FAIL_LIMIT, 5),
    originFailWindowSeconds: int(env.ORIGIN_FAIL_WINDOW_SECONDS, 600),
    cookieSeconds: int(env.COOKIE_DAYS, 365) * 86_400,
    cookieDomain: env.COOKIE_DOMAIN ?? '',
    adminHosts: list(env.ADMIN_HOSTS),
    quietHours: quiet ? [Number(quiet[1]), Number(quiet[2])] : null,
    timezone: env.TIMEZONE ?? 'UTC',
    alertIpRequests: int(env.ALERT_IP_REQUESTS, 300),
    alertIpErrors: int(env.ALERT_IP_ERRORS, 30),
    alertGuessIps: int(env.ALERT_GUESS_IPS, 3),
    siteName: env.SITE_NAME ?? 'wicket',
    analyticsDataset: (env.ANALYTICS_DATASET ?? '').match(/^[A-Za-z_][A-Za-z0-9_]*$/) ? env.ANALYTICS_DATASET! : 'wicket_traffic',
    reconcileCron: env.RECONCILE_CRON ?? '17 * * * *',
  };
}
