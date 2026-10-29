/** The password page and small message pages. Inline CSS, dark mode, no scripts, no external assets. */
const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

/** The mark: a small gate (a wicket), stroke-only so it takes the page's colours. */
const MARK = (size: number) =>
  `<svg class="mark" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` +
  `<path d="M5 4v16M19 4v16M5 9h14M5 15h14M5 15l14-6"/></svg>`;

/** Same mark as a favicon (data URI, accent blue), so no external asset is ever loaded. */
const FAVICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#2d5be3" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 4v16M19 4v16M5 9h14M5 15h14M5 15l14-6"/></svg>`,
  );

/** Brand row above every page's heading. */
export const brand = (label = 'wicket') => `<div class="brand">${MARK(18)}<span>${esc(label)}</span></div>`;

const shell = (title: string, body: string, variant: 'narrow' | 'wide' = 'narrow') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><link rel="icon" href="${FAVICON}">
<style>
:root{--bg:#f6f5f2;--fg:#1c1b19;--muted:#6b6963;--card:#fff;--line:#d9d6cf;--accent:#2d5be3;--err:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#15161a;--fg:#ecebe6;--muted:#9a988f;--card:#1f2127;--line:#33363e;--accent:#7c9cff;--err:#ff8a80}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:16px}
main{width:100%;max-width:${variant === 'wide' ? '640px' : '360px'};background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}
table{width:100%;border-collapse:collapse;margin:8px 0}td{padding:10px 6px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}td:last-child{text-align:right;white-space:nowrap}
small{color:var(--muted)}select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}
.row{display:flex;gap:8px;flex-wrap:wrap}.row button{width:auto;flex:1}.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}
.ok{color:var(--accent);font-size:14px}a{color:var(--accent)}
.brand{display:flex;align-items:center;gap:7px;color:var(--accent);font-weight:600;font-size:13px;letter-spacing:.02em;margin-bottom:10px}.brand .mark{flex:none}
.head .brand{font-size:18px;color:var(--fg);margin:0}.head .brand .mark{color:var(--accent);width:22px;height:22px}
h2{font-size:15px;margin:22px 0 4px}.head{display:flex;justify-content:space-between;align-items:baseline;gap:12px}.head a{font-size:13px}
.inline{display:inline}.small{margin:0;padding:6px 10px;width:auto;font-size:13px}code{font-size:13px}
.pager span{color:var(--muted)}form.row{margin-top:12px;align-items:center}form.row input{flex:1;width:auto}form.row button{flex:none}
.warn{color:var(--err)}.sections{display:flex;gap:12px;flex-wrap:wrap;font-size:13px;margin:-6px 0 14px}textarea{width:100%;font:13px/1.4 ui-monospace,monospace;padding:8px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;resize:vertical}
.limits td{font-size:13px}.limits input{width:7em;padding:6px 8px;font-size:13px}
.hosts td{text-align:left;white-space:normal}.hostrow select{margin:6px 4px 0 0;font-size:13px;max-width:100%}.hostrow .actions{display:inline-flex;gap:6px;margin-left:4px}.hostrow .actions button{margin-top:6px}
.hostrow.add{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:10px}.hostrow.add input{flex:1 1 200px;width:auto;padding:6px 8px;font-size:13px}.hostrow.add select{margin:0}.hostrow.add button{margin:0}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 16px;color:var(--muted);font-size:14px}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
button{margin-top:14px;width:100%;font:inherit;font-weight:600;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
.err{color:var(--err);font-size:14px;margin:10px 0 0}
</style></head><body><main>${body}</main></body></html>`;

export function loginPage(opts: { host: string; action: string; next: string; error?: string; remaining?: number }): string {
  const hint =
    opts.remaining !== undefined && opts.remaining > 0
      ? ` ${opts.remaining} attempt${opts.remaining === 1 ? '' : 's'} left before this address is blocked.`
      : '';
  return shell(
    opts.host,
    `${brand()}<h1>${esc(opts.host)}</h1><p>Private. Enter the password to continue.</p>
<form method="post" action="${esc(opts.action)}" autocomplete="off">
<input type="hidden" name="next" value="${esc(opts.next)}">
<label for="pw">Password</label><input id="pw" name="password" type="password" required autofocus autocomplete="current-password">
<button type="submit">Enter</button>
${opts.error ? `<p class="err" role="alert">${esc(opts.error)}${esc(hint)}</p>` : ''}
</form>`,
  );
}

export function messagePage(title: string, text: string): string {
  return shell(title, `${brand()}<h1>${esc(title)}</h1><p>${esc(text)}</p>`);
}

/** The shell for pages built elsewhere (settings). */
export const page = shell;
