# Security

wicket stands between the internet and services people run at home, so a bug here can expose someone's house. Please report vulnerabilities privately.

**Report**: open a private advisory at <https://github.com/jiaton/wicket/security/advisories/new> (GitHub's private vulnerability reporting). Do not open a public issue for anything that could be exploited. Include the version or commit, the configuration that matters (modes, recipes, limits; never your real hosts or secrets) and the steps to reproduce.

**What counts**: a way past the password or token check, a way to make a trusted or allow-listed decision for an address that should not get one, a ban or lockdown that an unauthenticated stranger can inflict on others at will beyond the documented limits, credentials reaching the origin or a log, or a notification that leaks something it should not. Scanner lists being incomplete is not a vulnerability; send those as ordinary pull requests.

**Response**: expect an acknowledgement within a week. Fixes ship as a normal release with a note in the changelog; reporters are credited unless they prefer not to be.

**Scope notes**: wicket trusts Cloudflare's `CF-Connecting-IP` and only sees traffic that reaches the Worker. An origin reachable without the Tunnel, a leaked shared password, or a bug in the proxied application itself are outside what wicket can defend against; see the threat model in [`docs/design.md`](docs/design.md).
