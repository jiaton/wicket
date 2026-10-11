/**
 * Per-isolate sliding window counter keyed by address.
 *
 * Used for scanner detection: a vulnerability scanner fires hundreds of requests in
 * seconds and would burn the free KV write quota if every probe were persisted. Isolates
 * are per colo and ephemeral, so the count is approximate — one scanner hits one colo,
 * which is all we need. Returns true when the key crossed `limit` inside `windowMs`.
 */
export class SlidingCounter {
  private readonly entries = new Map<string, { n: number; since: number }>();
  private readonly now: () => number;
  private readonly maxKeys: number;

  constructor(now: () => number, maxKeys = 5000) {
    this.now = now;
    this.maxKeys = maxKeys;
  }

  hit(key: string, limit: number, windowMs: number): boolean {
    const now = this.now();
    if (this.entries.size > this.maxKeys) {
      for (const [k, v] of this.entries) if (now - v.since > windowMs) this.entries.delete(k);
    }
    const cur = this.entries.get(key);
    if (!cur || now - cur.since > windowMs) {
      this.entries.set(key, { n: 1, since: now });
      return false;
    }
    cur.n += 1;
    return cur.n >= limit;
  }

  reset(key: string): void {
    this.entries.delete(key);
  }
}

/** Per-isolate set of keys that expire: "seen in the last N ms". Bounded like SlidingCounter. */
export class RecentSet {
  private readonly until = new Map<string, number>();
  private readonly now: () => number;
  private readonly maxKeys: number;

  constructor(now: () => number, maxKeys = 5000) {
    this.now = now;
    this.maxKeys = maxKeys;
  }

  add(key: string, ttlMs: number): void {
    const now = this.now();
    if (this.until.size > this.maxKeys) {
      for (const [k, t] of this.until) if (t <= now) this.until.delete(k);
    }
    this.until.set(key, now + ttlMs);
  }

  has(key: string): boolean {
    const t = this.until.get(key);
    if (t === undefined) return false;
    if (t <= this.now()) {
      this.until.delete(key);
      return false;
    }
    return true;
  }
}
