/**
 * Notification policy: what happens to each kind of event. Parsing only; the merge of
 * defaults ← wicket.yaml ← the owner's saved settings lives in notify/policy.ts.
 */
export type EventKind = 'scanner' | 'credentials' | 'app_logins' | 'lockdown' | 'traffic' | 'reconcile' | 'unban' | 'test';

/** `immediate`: one message per event. `digest`: collected and sent as one message per window. `off`: dropped. */
export type Delivery = 'immediate' | 'digest' | 'off';

/** Kinds the owner can configure; `test` is always immediate. */
export const POLICY_KINDS = ['scanner', 'credentials', 'app_logins', 'lockdown', 'traffic', 'reconcile', 'unban'] as const;
export type PolicyKind = (typeof POLICY_KINDS)[number];

export interface NotifyPolicy {
  kinds: Record<PolicyKind, Delivery>;
  /** Digest window in seconds; digests go out with the five-minute job once the window has passed. */
  digestSeconds: number;
}

export const KIND_LABELS: Record<PolicyKind, { label: string; hint: string }> = {
  scanner: { label: 'Scanner bans', hint: 'Addresses banned for probe bursts. The internet is full of these; a digest is plenty.' },
  credentials: { label: 'Wrong password / token bans', hint: 'Someone typed or sent wrong credentials three times.' },
  app_logins: { label: 'App login bans (observe mode)', hint: 'Failed logins at an app with its own login page.' },
  lockdown: { label: 'Lockdown', hint: 'Password entry paused because of guessing from changing addresses.' },
  traffic: { label: 'Traffic alerts', hint: 'Bursts, error floods, new countries, admin hosts at night (five-minute analysis).' },
  reconcile: { label: 'IP list reconcile', hint: 'The hourly KV ↔ Cloudflare list check changed something.' },
  unban: { label: 'Unbans', hint: 'An unban or lift-lockdown link was used.' },
};

export const DEFAULT_POLICY: NotifyPolicy = {
  kinds: { scanner: 'digest', credentials: 'immediate', app_logins: 'immediate', lockdown: 'immediate', traffic: 'digest', reconcile: 'digest', unban: 'immediate' },
  digestSeconds: 3600,
};

/** Digest windows offered in the settings page (seconds → label). */
export const DIGEST_CHOICES: [number, string][] = [
  [900, '15 minutes'],
  [1800, '30 minutes'],
  [3600, '1 hour'],
  [10_800, '3 hours'],
  [21_600, '6 hours'],
  [86_400, '24 hours'],
];

export const isDelivery = (v: unknown): v is Delivery => v === 'immediate' || v === 'digest' || v === 'off';
export const isPolicyKind = (v: unknown): v is PolicyKind => (POLICY_KINDS as readonly string[]).includes(String(v));

/** Applies a partial policy (JSON object or parsed) on top of `base`; unknown or malformed parts are ignored. */
export function mergePolicy(base: NotifyPolicy, raw: unknown): NotifyPolicy {
  let doc = raw;
  if (typeof raw === 'string') {
    try {
      doc = JSON.parse(raw);
    } catch {
      return base;
    }
  }
  if (!doc || typeof doc !== 'object') return base;
  const r = doc as { kinds?: unknown; digestSeconds?: unknown };
  const kinds = { ...base.kinds };
  if (r.kinds && typeof r.kinds === 'object') {
    for (const [k, v] of Object.entries(r.kinds as Record<string, unknown>)) if (isPolicyKind(k) && isDelivery(v)) kinds[k] = v;
  }
  const digestSeconds = typeof r.digestSeconds === 'number' && r.digestSeconds >= 300 && r.digestSeconds <= 86_400 ? Math.round(r.digestSeconds) : base.digestSeconds;
  return { kinds, digestSeconds };
}
