import { DIGEST_CHOICES, KIND_LABELS, POLICY_KINDS, type Delivery, type NotifyPolicy } from '../config/notifications';
import { page } from './pages';

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

export interface SettingsView {
  host: string;
  action: string;
  policy: NotifyPolicy;
  source: 'defaults' | 'config' | 'saved';
  /** Channel types in use, e.g. ["telegram", "ntfy"]; secrets never reach the page. */
  channels: string[];
  /** Bans in KV by kind. */
  bans: Record<string, number>;
  notice?: string;
}

const DELIVERIES: [Delivery, string][] = [
  ['immediate', 'Immediately'],
  ['digest', 'In the digest'],
  ['off', 'Off'],
];

const select = (name: string, options: [string, string][], current: string) =>
  `<select name="${esc(name)}">${options.map(([v, l]) => `<option value="${esc(v)}"${v === current ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`;

/** Owner-only page: notification policy, with the deploy-time config as the fallback. */
export function settingsPage(v: SettingsView): string {
  const rows = POLICY_KINDS.map(
    (k) =>
      `<tr><td><b>${esc(KIND_LABELS[k].label)}</b><br><small>${esc(KIND_LABELS[k].hint)}</small></td><td>${select(`kind.${k}`, DELIVERIES, v.policy.kinds[k])}</td></tr>`,
  ).join('');
  const bans = Object.entries(v.bans)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${esc(k)} ${n}`)
    .join(' · ');
  const sourceText =
    v.source === 'saved'
      ? 'Values below were saved on this page and override wicket.yaml.'
      : v.source === 'config'
        ? 'Values below come from wicket.yaml; saving here overrides them until you reset.'
        : 'Values below are the built-in defaults; saving here overrides them until you reset.';
  return page(
    'Settings',
    `<h1>${esc(v.host)} · settings</h1>
<p>Who gets told what. Channels in use: ${v.channels.length ? esc(v.channels.join(', ')) : 'none configured'}. Bans in store: ${bans || 'none'}.</p>
${v.notice ? `<p class="ok" role="status">${esc(v.notice)}</p>` : ''}
<form method="post" action="${esc(v.action)}">
<table>${rows}
<tr><td><b>Digest every</b><br><small>Collected events go out as one message per window, with the five-minute job.</small></td><td>${select(
      'digest',
      DIGEST_CHOICES.map(([s, l]) => [String(s), l]),
      String(v.policy.digestSeconds),
    )}</td></tr>
</table>
<p><small>${esc(sourceText)}</small></p>
<div class="row">
<button type="submit" name="action" value="save">Save</button>
<button type="submit" name="action" value="reset" class="secondary">Reset to config</button>
<button type="submit" name="action" value="test" class="secondary">Send test message</button>
</div>
</form>
<p><small><a href="/__wicket/logout">Sign out</a></small></p>`,
    'wide',
  );
}
