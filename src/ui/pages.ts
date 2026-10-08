/** The password page and small message pages. Inline CSS, dark mode, no scripts, no external assets. */
const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);

const shell = (title: string, body: string, variant: 'narrow' | 'wide' = 'narrow') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title>
<style>
:root{--bg:#f6f5f2;--fg:#1c1b19;--muted:#6b6963;--card:#fff;--line:#d9d6cf;--accent:#2d5be3;--err:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#15161a;--fg:#ecebe6;--muted:#9a988f;--card:#1f2127;--line:#33363e;--accent:#7c9cff;--err:#ff8a80}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:16px}
main{width:100%;max-width:${variant === 'wide' ? '640px' : '360px'};background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}
table{width:100%;border-collapse:collapse;margin:8px 0}td{padding:10px 6px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}td:last-child{text-align:right;white-space:nowrap}
small{color:var(--muted)}select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}
.row{display:flex;gap:8px;flex-wrap:wrap}.row button{width:auto;flex:1}.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}
.ok{color:var(--accent);font-size:14px}a{color:var(--accent)}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 16px;color:var(--muted);font-size:14px}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
button{margin-top:14px;width:100%;font:inherit;font-weight:600;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
.err{color:var(--err);font-size:14px;margin:10px 0 0}.hp{position:absolute;left:-9999px;top:-9999px}
</style></head><body><main>${body}</main></body></html>`;

export function loginPage(opts: { host: string; action: string; next: string; error?: string; remaining?: number }): string {
  const hint =
    opts.remaining !== undefined && opts.remaining > 0
      ? ` ${opts.remaining} attempt${opts.remaining === 1 ? '' : 's'} left before this address is blocked.`
      : '';
  return shell(
    opts.host,
    `<h1>${esc(opts.host)}</h1><p>Private. Enter the password to continue.</p>
<form method="post" action="${esc(opts.action)}" autocomplete="off">
<input type="hidden" name="next" value="${esc(opts.next)}">
<div class="hp" aria-hidden="true"><label>Leave this field empty<input name="website" type="text" tabindex="-1" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore></label></div>
<label for="pw">Password</label><input id="pw" name="password" type="password" required autofocus autocomplete="current-password">
<button type="submit">Enter</button>
${opts.error ? `<p class="err" role="alert">${esc(opts.error)}${esc(hint)}</p>` : ''}
</form>`,
  );
}

export function messagePage(title: string, text: string): string {
  return shell(title, `<h1>${esc(title)}</h1><p>${esc(text)}</p>`);
}

/** The shell for pages built elsewhere (settings). */
export const page = shell;
