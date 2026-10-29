import { HOST_MODES, type HostMode } from '../config/hosts';
import { formatDuration, LIMIT_FIELDS, type LimitKey } from '../config/runtime';
import { DIGEST_CHOICES, KIND_LABELS, POLICY_KINDS, type Delivery, type NotifyPolicy } from '../config/notifications';
import type { BanKind } from '../store/bans';
import { brand, page } from './pages';

const MODE_HINTS: Record<HostMode, string> = {
  gated: 'password page',
  observe: 'app keeps its login, watched',
  open: 'forwarded untouched',
  off: 'maintenance page',
};

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

export interface HostRow {
  host: string;
  mode: HostMode;
  recipe: string;
  /** '' = none, a preset name, or 'custom' (a mapping from wicket.yaml). */
  passthrough: string;
  watchRules: number;
  /** Where the effective entry comes from. */
  source: 'config' | 'saved';
}

export interface CloudflareView {
  token: 'missing' | 'active' | 'expired' | 'disabled' | 'invalid';
  tokenNote?: string;
  accountId: string;
  analytics: { ok: true; rows: number } | { ok: false; error: string };
  list: { id: string; name?: string; items?: number; source: 'secret' | 'saved' | 'none' };
  zone: string;
  waf: 'present' | 'missing' | 'unknown' | 'no-zone';
}

export interface SettingsView {
  host: string;
  action: string;
  logout: string;
  /** Every configured host, deploy-time and runtime, sorted. */
  hosts: HostRow[];
  recipes: string[];
  passthroughPresets: string[];
  defaultMode: HostMode;
  /** True when any runtime override (hosts, access, limits) is saved. */
  runtimeOverridden: boolean;
  access: { allowIps: string[]; allowDns: string[]; trustSeconds: number; bypass: string[]; saved: boolean };
  cloudflare: CloudflareView;
  limits: { values: Record<LimitKey, number>; saved: boolean };
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
            `<tr><td><code>${esc(b.ip)}</code> <small>${esc(b.country)}</small><br><small>${esc(BAN_KIND_LABELS[b.kind] ?? String(b.kind))} · ${esc(b.host)} · ${esc(ago(v.now - b.at))}</small></td>` +
            `<td><form method="post" action="${esc(v.action)}" class="inline"><input type="hidden" name="ip" value="${esc(b.ip)}"><button type="submit" name="action" value="unban" class="secondary small">Unban</button></form></td></tr>`,
        )
        .join('')
    : '<tr><td><small>No bans.</small></td><td></td></tr>';
  const total = Object.values(v.banCounts).reduce((a, b) => a + (b ?? 0), 0);

  const modeOptions: [string, string][] = HOST_MODES.map((m) => [m, `${m} — ${MODE_HINTS[m]}`]);
  const recipeOptions: [string, string][] = [['', 'no recipe'], ...v.recipes.map((r): [string, string] => [r, r])];
  const passthroughOptions = (current: string): [string, string][] => [
    ['', 'none'],
    ...v.passthroughPresets.map((p): [string, string] => [p, `${p} (app's own tokens reach the app)`]),
    ...(current === 'custom' ? [['custom', 'custom (from wicket.yaml)'] as [string, string]] : []),
  ];
  const hostRows = v.hosts.length
    ? v.hosts
        .map(
          (h) =>
            `<tr><td><form method="post" action="${esc(v.action)}" class="hostrow"><input type="hidden" name="host" value="${esc(h.host)}">` +
            `<b>${esc(h.host)}</b> <small>${h.source === 'saved' ? 'saved here' : 'wicket.yaml'}${h.watchRules ? ` · ${h.watchRules} watch rule${h.watchRules === 1 ? '' : 's'}` : ''}</small><br>` +
            `${select('mode', modeOptions, h.mode)} ${select('recipe', recipeOptions, h.recipe)} ${select('passthrough', passthroughOptions(h.passthrough), h.passthrough)}` +
            `<span class="actions"><button type="submit" name="action" value="host.save" class="small">Save</button>` +
            `${h.source === 'saved' ? `<button type="submit" name="action" value="host.remove" class="secondary small">Remove</button>` : ''}</span></form></td></tr>`,
        )
        .join('')
    : '<tr><td><small>No hosts configured; every routed host gets the default mode.</small></td></tr>';

  const cf = v.cloudflare;
  const TRUST_CHOICES: [string, string][] = [['0', 'off'], ['3600', '1 hour'], ['21600', '6 hours'], ['86400', '24 hours'], ['604800', '7 days']];
  const trustCurrent = TRUST_CHOICES.some(([s]) => Number(s) === v.access.trustSeconds) ? String(v.access.trustSeconds) : 'custom';
  const trustOptions: [string, string][] = trustCurrent === 'custom' ? [...TRUST_CHOICES, ['custom', `${formatDuration(v.access.trustSeconds)} (from wicket.yaml)`]] : TRUST_CHOICES;
  const area = (name: string, lines: string[], placeholder: string) =>
    `<textarea name="${esc(name)}" rows="${Math.min(6, Math.max(2, lines.length + 1))}" placeholder="${esc(placeholder)}" spellcheck="false">${esc(lines.join('\n'))}</textarea>`;
  const limitRows = LIMIT_FIELDS.map(
    (f) =>
      `<tr><td>${esc(f.label)}</td><td><input name="limit.${f.key}" value="${esc(f.kind === 'duration' ? formatDuration(v.limits.values[f.key]) : String(v.limits.values[f.key]))}" size="7" inputmode="${f.kind === 'count' ? 'numeric' : 'text'}" aria-label="${esc(f.label)}"></td></tr>`,
  ).join('');

  return page(
    'wicket · settings',
    `<div class="head">${brand('wicket · settings')}<a href="${esc(v.logout)}">Sign out</a></div>
<p>Signed in as owner on ${esc(v.host)}. Settings apply to every host.</p>
<nav class="sections"><a href="#hosts">Hosts</a><a href="#access">Access</a><a href="#limits">Limits</a><a href="#cloudflare">Cloudflare</a><a href="#notifications">Notifications</a><a href="#bans">Bans</a></nav>

<h2 id="hosts">Hosts</h2>
<p><small>Mode, recipe and pass-through per host. Changes are live within 30 s; a host must also be routed to the Worker (its own route in wicket.yaml, or <code>routes: wildcard</code>). Unlisted routed hosts are <b>${esc(v.defaultMode)}</b>.${v.runtimeOverridden ? ' Entries marked <i>saved here</i> override wicket.yaml until removed or reset.' : ''}</small></p>
<table class="hosts">${hostRows}</table>
<form method="post" action="${esc(v.action)}" class="hostrow add"><input name="host" placeholder="new.host.example.com" aria-label="hostname" required pattern="[A-Za-z0-9.-]+">${select('mode', modeOptions, 'gated')} ${select('recipe', recipeOptions, '')} ${select('passthrough', passthroughOptions(''), '')}<button type="submit" name="action" value="host.save" class="small">Add host</button></form>
${v.runtimeOverridden ? `<form method="post" action="${esc(v.action)}" class="inline"><button type="submit" name="action" value="runtime.reset" class="secondary small">Reset hosts, access and limits to wicket.yaml</button></form>` : ''}

<h2 id="access">Access</h2>
<p><small>${v.access.saved ? 'Saved here; overrides wicket.yaml until reset.' : 'From wicket.yaml; saving here overrides it until reset.'} One entry per line.</small></p>
<form method="post" action="${esc(v.action)}">
<table>
<tr><td><b>Allowed addresses</b><br><small>Never see a password page, never counted. IPv4, IPv4 CIDR, IPv6 (its /64), IPv6 CIDR.</small></td><td>${area('allowIps', v.access.allowIps, '203.0.113.7')}</td></tr>
<tr><td><b>Allowed DNS names</b><br><small>Dynamic-DNS names resolved every five minutes; their addresses count as allowed.</small></td><td>${area('allowDns', v.access.allowDns, 'home.example.duckdns.org')}</td></tr>
<tr><td><b>Trust after owner login</b><br><small>An address that logged in as owner is immune to counting and bans this long.</small></td><td>${select('trustSeconds', trustOptions, trustCurrent)}</td></tr>
<tr><td><b>Bypass prefixes</b><br><small><code>host/prefix</code> that passes without any credential (webhooks).</small></td><td>${area('bypass', v.access.bypass, 'nas.example.com/hooks/')}</td></tr>
</table>
<div class="row"><button type="submit" name="action" value="access.save">Save access</button></div>
</form>

<h2 id="limits">Limits</h2>
<p><small>${v.limits.saved ? 'Saved here; overrides wicket.yaml until reset.' : 'From wicket.yaml; saving here overrides it until reset.'} Counts are whole numbers; windows take <code>30s</code>, <code>10m</code>, <code>24h</code>, <code>7d</code>.</small></p>
<form method="post" action="${esc(v.action)}">
<table class="limits">${limitRows}</table>
<div class="row"><button type="submit" name="action" value="limits.save">Save limits</button></div>
</form>

<h2 id="cloudflare">Cloudflare</h2>
<p><small>What wicket can reach in your account with <code>CF_API_TOKEN</code>. Edge bans need an IP list and a WAF rule on the zone; both can be created here when the token may (Account: <i>Filter Lists Edit</i>; Zone: <i>Zone Read</i>, <i>WAF Edit</i>). Analytics Engine needs <i>Account Analytics Read</i> and the account switch (<i>Workers &amp; Pages → Analytics Engine</i>).</small></p>
<table>
<tr><td><b>API token</b></td><td>${cf.token === 'active' ? 'active' : `<span class="warn">${esc(cf.token)}</span>${cf.tokenNote ? ` <small>${esc(cf.tokenNote)}</small>` : ''}`}</td></tr>
<tr><td><b>Account</b></td><td>${cf.accountId ? `<code>${esc(cf.accountId.slice(0, 8))}…</code>` : '<span class="warn">CF_ACCOUNT_ID missing</span>'}</td></tr>
<tr><td><b>Analytics Engine</b><br><small>traffic analysis, alerts, slow-scanner bans</small></td><td>${cf.analytics.ok ? `ok, ${cf.analytics.rows} rows today` : `<span class="warn">not answering</span> <small>${esc(cf.analytics.error)}</small>`}</td></tr>
<tr><td><b>IP list</b><br><small>bans at the edge, every proxied host</small></td><td>${
      cf.list.source === 'none'
        ? `<span class="warn">none</span> <form method="post" action="${esc(v.action)}" class="inline"><button type="submit" name="action" value="cf.list" class="secondary small">Create list wicket_banned</button></form>`
        : `<code>${esc(cf.list.name ?? cf.list.id.slice(0, 8) + '…')}</code>${cf.list.items !== undefined ? ` · ${cf.list.items} items` : ''} <small>${cf.list.source === 'saved' ? 'created here' : 'CF_LIST_ID'}</small>`
    }</td></tr>
<tr><td><b>WAF rule</b><br><small>blocks the list on ${esc(cf.zone || 'your zone')}</small></td><td>${
      cf.waf === 'present'
        ? 'present'
        : cf.waf === 'no-zone'
          ? '<small>zone unknown (redeploy with the current wicket.yaml)</small>'
          : `<span class="warn">${cf.waf === 'missing' ? 'missing' : 'unknown'}</span>${cf.list.source !== 'none' ? ` <form method="post" action="${esc(v.action)}" class="inline"><button type="submit" name="action" value="cf.waf" class="secondary small">Create rule</button></form>` : ''}${cf.waf === 'unknown' ? ' <small>the token cannot read zone rulesets</small>' : ''}`
    }</td></tr>
</table>

<h2>Status</h2>
<table>
<tr><td><b>Channels</b><br><small>${channels}</small></td><td></td></tr>
<tr><td><b>Lockdown</b><br><small>${lockdown}</small></td><td></td></tr>
<tr><td><b>Bans in store</b><br><small>${total ? esc(String(total)) + ' total: ' + counts : 'none'}</small></td><td></td></tr>
</table>

<h2 id="notifications">Notifications</h2>
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

<h2 id="bans">Bans</h2>
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
