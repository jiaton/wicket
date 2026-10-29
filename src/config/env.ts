/**
 * Everything the Worker receives from the platform: bindings (cloudflare.config.ts),
 * plain vars (same file) and secrets (uploaded at deploy). Parsing lives next door in
 * settings.ts / hosts.ts / tokens.ts / channels.ts; this file only names the fields.
 */
export interface Env {
  /** KV namespace: bans, failure counters, lockdown, alert dedup, notification queues. */
  STORE: KVNamespace;
  /** Workers Analytics Engine dataset: one row per request. */
  TRAFFIC: AnalyticsEngineDataset;

  // ---- vars (non-secret, committed) ----
  ALLOW_IPS?: string;
  /** Hostnames (dynamic DNS) whose current addresses count as allow-listed. */
  ALLOW_DNS?: string;
  /** Seconds an address stays trusted after an owner login; 0 disables. */
  TRUST_SECONDS?: string;
  BYPASS_PREFIXES?: string;
  FAIL_LIMIT?: string;
  FAIL_WINDOW_SECONDS?: string;
  FAIL_GLOBAL_LIMIT?: string;
  FAIL_GLOBAL_WINDOW_SECONDS?: string;
  LOCKDOWN_SECONDS?: string;
  SCAN_LIMIT?: string;
  /** Slow scanner ban: anonymous probes per address in the five-minute analysis window (network-wide). */
  SCANNING_LIMIT?: string;
  /** Scanner signature hits (known paths / User-Agents) per address before a ban; 0 disables. */
  SIGNATURE_LIMIT?: string;
  SIGNATURE_WINDOW_SECONDS?: string;
  /** Extra signature patterns from wicket.yaml, newline-separated regular expressions. */
  SIGNATURE_PATHS?: string;
  SIGNATURE_AGENTS?: string;
  SCAN_WINDOW_SECONDS?: string;
  ORIGIN_FAIL_LIMIT?: string;
  ORIGIN_FAIL_WINDOW_SECONDS?: string;
  /** Per-host modes and watch rules, JSON (see config/hosts.ts). */
  HOSTS_JSON?: string;
  /** Mode for routed hosts missing from HOSTS_JSON (wildcard routes): gated | observe | open | off. */
  DEFAULT_MODE?: string;
  /** The Cloudflare zone the hosts live in (for the Cloudflare section of the settings page). */
  ZONE?: string;
  /** First-run setup page on/off (`setup:` in wicket.yaml); only matters while no owner password exists anywhere. */
  SETUP_ENABLED?: string;
  /** One-time token printed at deploy time; required to open /__wicket/setup. */
  SETUP_TOKEN?: string;
  COOKIE_DAYS?: string;
  COOKIE_DOMAIN?: string;
  ADMIN_HOSTS?: string;
  QUIET_HOURS?: string;
  TIMEZONE?: string;
  ALERT_IP_REQUESTS?: string;
  ALERT_IP_ERRORS?: string;
  ALERT_GUESS_IPS?: string;
  SITE_NAME?: string;
  /** Analytics Engine dataset name the cron queries (must match the TRAFFIC binding). */
  ANALYTICS_DATASET?: string;
  /** The cron expression of the hourly KV ↔ IP-list reconcile; every other tick is the alert pass. */
  RECONCILE_CRON?: string;
  /** Notification policy from wicket.yaml (see config/notifications.ts); the settings page can override it. */
  NOTIFY_POLICY_JSON?: string;

  // ---- secrets ----
  COOKIE_SECRET: string;
  OWNER_PASSWORD: string;
  FRIEND_PASSWORD?: string;
  /** `name:token[@host1|host2]`, comma-separated (see config/tokens.ts). */
  API_TOKENS?: string;
  /** Notification channels, JSON array (see config/channels.ts); TELEGRAM_* is the fallback. */
  NOTIFY_JSON?: string;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
  CF_LIST_ID?: string;
}

/** Comma-separated list var → trimmed, non-empty entries. */
export const list = (s: string | undefined): string[] =>
  (s ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

/** Positive-integer var with a fallback. */
export const int = (s: string | undefined, fallback: number): number => {
  const n = Number.parseInt(s ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};
