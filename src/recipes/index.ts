import type { WatchRule } from '../config/hosts';

/**
 * Built-in watch rules for common self-hosted apps (the fail2ban `filter.d` idea).
 * A rule matches when the request path starts with `path`, the method is listed
 * (or `methods` is absent) and the origin answered one of `status`.
 *
 * Only failures visible in the status code can be caught, and a rule must not match
 * what anonymous page loads or background polling produce on the same path, or it bans
 * legitimate users. Every entry below was checked against the app's handler source
 * (2026-10); the comment names the evidence. Apps whose failure is a 200 or a redirect
 * (Home Assistant's UI login, Nextcloud, Gitea/Forgejo, Miniflux, BookStack, Sonarr/Radarr,
 * code-server, WordPress, …) are listed as not detectable in docs/configuration.md and rely on their own lockout.
 *
 * Contributing a recipe: see CONTRIBUTING.md.
 */
export const RECIPES: Record<string, WatchRule[]> = {
  // ---- media ----
  /** server/src/services/auth.service.ts: UnauthorizedException on a wrong password (web + mobile). */
  immich: [{ path: '/api/auth/login', methods: ['POST'], status: [401] }],
  /** AuthenticationException → 401; a locked account answers 403 (not counted: that is a user, not a guess). */
  jellyfin: [{ path: '/Users/AuthenticateByName', methods: ['POST'], status: [401] }],
  /** Same endpoint, also reachable under /emby. */
  emby: [
    { path: '/Users/AuthenticateByName', methods: ['POST'], status: [401] },
    { path: '/emby/Users/AuthenticateByName', methods: ['POST'], status: [401] },
  ],
  /** server/auth.go: 401 "Invalid username or password". */
  navidrome: [{ path: '/auth/login', methods: ['POST'], status: [401] }],
  /** passport-local failure → 401. */
  audiobookshelf: [{ path: '/login', methods: ['POST'], status: [401] }],
  /** internal/api/session_create.go: 401; PhotoPrism's own limiter answers 429. */
  photoprism: [{ path: '/api/v1/session', methods: ['POST'], status: [401] }],
  /** api/Account/login → Unauthorized("Your credentials are not correct"); Kavita also locks the account. */
  kavita: [{ path: '/api/Account/login', methods: ['POST'], status: [401] }],
  /** server/routes/auth.ts: 403 "Access denied." (Jellyseerr and Overseerr share the code). */
  jellyseerr: [{ path: '/api/v1/auth/local', methods: ['POST'], status: [403] }],
  overseerr: [{ path: '/api/v1/auth/local', methods: ['POST'], status: [403] }],
  /** cps/web.py: `render_login(...), 401` on purpose, for fail2ban. */
  'calibre-web': [{ path: '/login', methods: ['POST'], status: [401] }],
  /**
   * qBittorrent ≤ 5.1 answers 200 "Fails." (not detectable; it bans IPs itself). The next major
   * release throws APIErrorType::Unauthorized → 401, which this rule catches. Other /api/v2 paths
   * answer 403 when unauthenticated and are deliberately not matched.
   */
  qbittorrent: [{ path: '/api/v2/auth/login', methods: ['POST'], status: [401] }],

  // ---- infrastructure ----
  /** pkg/services/authn/clients/password.go: errutil.Unauthorized. Grafana's own protection also answers 401. */
  grafana: [{ path: '/login', methods: ['POST'], status: [401] }],
  /** api/http/handler/auth/authenticate.go: StatusUnprocessableEntity "Invalid credentials". */
  portainer: [{ path: '/api/auth', methods: ['POST'], status: [422] }],
  /**
   * lib/api/api_auth.go: the GUI login answers 403. Do NOT widen this to /rest/: every
   * unauthenticated REST call (a stale tab, a client without its key) is a 403 there.
   */
  syncthing: [{ path: '/rest/noauth/auth/password', methods: ['POST'], status: [403] }],
  /** backend/lib/error.js: AuthError is 400. GET /api/tokens is the refresh, hence POST only. */
  'nginx-proxy-manager': [{ path: '/api/tokens', methods: ['POST'], status: [400] }],
  /** src/api/auth.c: 401 on a wrong password. The UI polls GET /api/auth and gets 401 when logged out, hence POST only. */
  pihole: [{ path: '/api/auth', methods: ['POST'], status: [401] }],
  /** internal/home/authhttp.go: 403; AdGuard's own per-IP blocker answers 429 after that. */
  'adguard-home': [{ path: '/control/login', methods: ['POST'], status: [403] }],
  /** 2.x only (better-auth over HTTP): /api/auth/sign-in/username|email → 401. 1.x logs in over socket.io (not detectable). */
  'uptime-kuma': [{ path: '/api/auth/sign-in/', methods: ['POST'], status: [401] }],
  /** http/auth.go: os.ErrPermission → 403 on the login route. */
  filebrowser: [{ path: '/api/login', methods: ['POST'], status: [403] }],
  /** frigate/api/auth.py: 401 {"message":"Login failed"}. */
  frigate: [{ path: '/api/login', methods: ['POST'], status: [401] }],
  /** oauth2orize invalid_grant → 403; Node-RED also locks the user for 10 min. */
  'node-red': [{ path: '/auth/token', methods: ['POST'], status: [403] }],
  /** AuthError → 401. */
  n8n: [{ path: '/rest/login', methods: ['POST'], status: [401] }],
  /** internal/handlers/handler_firstfactor_password.go: 401. Authelia regulates itself; this is belt and braces. */
  authelia: [{ path: '/api/firstfactor', methods: ['POST'], status: [401] }],

  // ---- apps ----
  /**
   * src/api/identity.rs: wrong master password → 400 on the token endpoint. A correct password
   * on a 2FA account also answers 400 once ("Two factor required"), so keep the threshold ≥ 5.
   */
  vaultwarden: [{ path: '/identity/connect/token', methods: ['POST'], status: [400] }],
  /** DRF ObtainAuthToken: 400 with serializer errors. The web form (/accounts/login/) re-renders with 200. */
  'paperless-ngx': [{ path: '/api/token/', methods: ['POST'], status: [400] }],
  /** GReader API: 401 wrong password, 400 unknown user. The web login redirects (not detectable). */
  freshrss: [{ path: '/api/greader.php/accounts/ClientLogin', methods: ['POST'], status: [401, 400] }],
  /** pkg/user/error.go: ErrWrongUsernameOrPassword → 403. */
  vikunja: [{ path: '/api/v1/login', methods: ['POST'], status: [403] }],
  /** routes/auth/auth.py: 401; a locked account answers 423. */
  mealie: [{ path: '/api/auth/token', methods: ['POST'], status: [401] }],
  /** bookmarks/views/auth.py: 401 on the HTML login, explicitly for fail2ban. */
  linkding: [{ path: '/login', methods: ['POST'], status: [401] }],
  /** seahub/api2/views.py: 400 with serializer errors. The web form re-renders with 200. */
  seafile: [{ path: '/api2/auth-token/', methods: ['POST'], status: [400] }],
  /** backend/open_webui/routers/auths.py: HTTPException(400, INVALID_CRED). */
  'open-webui': [{ path: '/api/v1/auths/signin', methods: ['POST'], status: [400] }],
  /** core/server/api/endpoints/session.js: 401 "Access Denied." for unknown email and wrong password alike. */
  ghost: [{ path: '/ghost/api/admin/session', methods: ['POST'], status: [401] }],

  // ---- special cases ----
  /**
   * The UI login (/auth/login_flow) fails with 200 + errors and is not detectable; turn on HA's
   * own `ip_ban_enabled` for that. Every unauthenticated /api/ request is a 401, which legitimate
   * HA clients never send (the companion app and integrations always carry a token), so this
   * catches token guessing and scanners. If something of yours polls /api/ anonymously, use `watch`.
   */
  'home-assistant': [{ path: '/api/', status: [401] }],
  /** Any API that answers 401 to bad bearer tokens under /api/. Same caveat as home-assistant. */
  'generic-api': [{ path: '/api/', status: [401] }],
};

export function recipeRules(name: string | undefined): WatchRule[] {
  return name ? (RECIPES[name] ?? []) : [];
}
