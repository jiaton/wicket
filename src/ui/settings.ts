import { DIGEST_CHOICES, KIND_LABELS, POLICY_KINDS, type Delivery, type NotifyPolicy } from '../config/notifications';
import type { BanKind } from '../store/bans';
import { brand, page } from './pages';

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

export const BAN_KIND_LABELS: Record<BanKind | 'unknown', string> = {
  scan: 'scanner',
  password: 'wrong password',
  token: 'wrong token',
  origin: 'app login',
  unknown: 'unknown',
};

export interface BanRow {
  ip: string;
  kind: BanKind | 'unknown';
  host: string;
  country: string;
  /** ms since epoch */
  at: number;
}

export interface SettingsView {
  host: string;
  action: string;
  logout: string;
  policy: NotifyPolicy;
  source: 'defaults' | 'config' | 'saved';
  /** Channels in use with their thresholds and digest queues; secrets never reach the page. */
  channels: { type: string; min: string; waiting: number; dueInSeconds: number | null }[];
  lockdown: { host: string; fails: number; at: number; until: number } | null;
  /** Count per kind over every ban in KV. */
  banCounts: Partial<Record<BanKind | 'unknown', number>>;
  /** The most recent bans, newest first. */
  recent: BanRow[];
  page: number;
  pages: number;
  perPage: number;
  now: number;
  notice?: string;
}

const DELIVERIES: [Delivery, string][] = [
  ['immediate', 'Immediately'],
  ['digest', 'In the digest'],
  ['off', 'Off'],
];

const select = (name: string, options: [string, string][], current: string) =>
  `<select name="${esc(name)}">${options.map(([v, l]) => `<option value="${esc(v)}"${v === current ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`;

const ago = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172_800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
};

const inMinutes = (s: number) => (s < 60 ? 'with the next five-minute job' : `in about ${Math.round(s / 60)} min`);

/** Owner-only page: status, notification policy, recent bans. */
export function settingsPage(v: SettingsView): string {
  const sourceText =
    v.source === 'saved'
      ? 'These values were saved on this page and override wicket.yaml.'
      : v.source === 'config'
        ? 'These values come from wicket.yaml; saving here overrides them until you reset.'
        : 'These are the built-in defaults; saving here overrides them until you reset.';

  const channels = v.channels.length
    ? v.channels
        .map((c) => `${esc(c.type)} (min ${esc(c.min)})${c.waiting ? `: ${c.waiting} waiting, digest ${esc(inMinutes(c.dueInSeconds ?? 0))}` : ': nothing waiting'}`)
        .join('<br>')
    : 'none configured — set NOTIFY_JSON or the TELEGRAM_* secrets';

  const lockdown = v.lockdown
    ? `<b>Active</b>, started ${esc(ago(v.now - v.lockdown.at))}, ends ${esc(inMinutes(Math.max(0, (v.lockdown.until - v.now) / 1000)))}; ${v.lockdown.fails} failures, last on ${esc(v.lockdown.host)}. ` +
      `<form method="post" action="${esc(v.action)}" class="inline"><button type="submit" name="action" value="lift" class="secondary small">Lift lockdown</button></form>`
    : 'none';

  const counts = Object.entries(v.banCounts)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .map(([k, n]) => `${n} ${esc(BAN_KIND_LABELS[k as BanKind | 'unknown'] ?? k)}`)
    .join(' · ');

  const policyRows = POLICY_KINDS.map(
    (k) =>
      `<tr><td><b>${esc(KIND_LABELS[k].label)}</b><br><small>${esc(KIND_LABELS[k].hint)}</small></td><td>${select(`kind.${k}`, DELIVERIES, v.policy.kinds[k])}</td></tr>`,
  ).join('');

  const banRows = v.recent.length
    ? v.recent
        .map(
          (b) =>
            `<tr><td><code>${esc(b.ip)}</code> <small>${esc(b.country)}</small><br><small>${esc(BAN_KIND_LABELS[b.kind])} · ${esc(b.host)} · ${esc(ago(v.now - b.at))}</small></td>` +
            `<td><form method="post" action="${esc(v.action)}" class="inline"><input type="hidden" name="ip" value="${esc(b.ip)}"><button type="submit" name="action" value="unban" class="secondary small">Unban</button></form></td></tr>`,
        )
        .join('')
    : '<tr><td><small>No bans.</small></td><td></td></tr>';
  const total = Object.values(v.banCounts).reduce((a, b) => a + (b ?? 0), 0);

  return page(
    'wicket · settings',
    `<div class="head">${brand('wicket · settings')}<a href="${esc(v.logout)}">Sign out</a></div>
<p>Signed in as owner on ${esc(v.host)}. Settings apply to every host.</p>

<h2>Status</h2>
<table>
<tr><td><b>Channels</b><br><small>${channels}</small></td><td></td></tr>
<tr><td><b>Lockdown</b><br><small>${lockdown}</small></td><td></td></tr>
<tr><td><b>Bans in store</b><br><small>${total ? esc(String(total)) + ' total: ' + counts : 'none'}</small></td><td></td></tr>
</table>

<h2>Notifications</h2>
<p><small>${esc(sourceText)}</small></p>
<form method="post" action="${esc(v.action)}">
<table>${policyRows}
<tr><td><b>Digest every</b><br><small>Collected events go out as one message per window, with the five-minute job. A quiet window sends nothing.</small></td><td>${select(
      'digest',
      DIGEST_CHOICES.map(([s, l]) => [String(s), l]),
      String(v.policy.digestSeconds),
    )}</td></tr>
</table>
<div class="row">
<button type="submit" name="action" value="save">Save</button>
<button type="submit" name="action" value="reset" class="secondary">Reset to config</button>
<button type="submit" name="action" value="test" class="secondary">Send test message</button>
</div>
${v.notice ? `<p class="ok" role="status">${esc(v.notice)}</p>` : ''}
</form>

<h2>Bans</h2>
<p><small>${total} total, newest first, ${v.perPage} per page. Unban removes the address from KV and from the Cloudflare IP list.</small></p>
<table>${banRows}</table>
${
  v.pages > 1
    ? `<p class="pager"><small>${v.page > 1 ? `<a href="?page=${v.page - 1}">← newer</a>` : '<span>← newer</span>'} · page ${v.page} of ${v.pages} · ${
        v.page < v.pages ? `<a href="?page=${v.page + 1}">older →</a>` : '<span>older →</span>'
      }</small></p>`
    : ''
}
<form method="post" action="${esc(v.action)}" class="row"><input name="ip" placeholder="Unban an address not listed here" aria-label="IP address" required><button type="submit" name="action" value="unban" class="secondary small">Unban</button></form>`,
    'wide',
  );
}
