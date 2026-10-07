# Contributing

Thanks for looking. wicket is small on purpose; the best contributions keep it that way.

## Ground rules

- **Read `AGENTS.md` first.** It describes the layers, the dependency direction and exactly which files change for each kind of addition. A pull request that follows it is easy to review; one that adds a new place for KV keys or network calls is not.
- **Fail closed.** Missing secrets disable login; a malformed host entry means `gated`; an unknown token never passes. Keep it so.
- **No identity features.** Accounts, email codes, OAuth and per-browser verification are out of scope by design. Two shared passwords and host-scoped tokens is the whole model.
- **Never forward wicket's own credentials** to the origin, and never log a secret.
- English for code, comments, docs and UI strings.

## Recipes

Recipes are the most useful thing to contribute. To add one:

1. Install the app, fail a login on purpose, and record the request path, method and the **response status**. A failure that is a `200` with an error body cannot be detected by wicket; say so in the recipe comment and point at the app's own lockout instead.
2. Check what an anonymous page load or the app's background polling does on the same path. If it produces the same status, narrow the rule (method, longer prefix) or drop it; a recipe that bans legitimate users is worse than none.
3. Add the entry to `src/recipes/index.ts` with a one-line comment stating the evidence, and a row to the recipe table in `README.md`.

## Pull requests

- `npm test` and `npm run check` (needs the `cf` CLI; `tsc --noEmit` alone is fine if you do not have it) must pass.
- One change per PR. Add or adjust a test in `tests/` for anything in `src/`.
- Describe what an attacker could do before and after if the change touches the pipeline order, counters or credentials.

## Reporting a security issue

Open a private security advisory on GitHub rather than a public issue.
