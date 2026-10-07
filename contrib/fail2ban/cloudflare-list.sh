#!/bin/sh
# fail2ban → Cloudflare IP list bridge. Usage: cloudflare-list.sh ban|unban <ip> [jail]
# Install to /etc/fail2ban/cloudflare-list.sh (see README.md); reads /etc/fail2ban/cloudflare-list.env.
# Never prints the token; failures go to syslog (logger) and never fail the ban itself.
set -u

ENV_FILE="${CF_LIST_ENV:-/etc/fail2ban/cloudflare-list.env}"
ACTION="${1:-}"; IP="${2:-}"; JAIL="${3:-fail2ban}"
[ -n "$ACTION" ] && [ -n "$IP" ] || { echo "usage: $0 ban|unban <ip> [jail]" >&2; exit 1; }
[ -r "$ENV_FILE" ] || { logger -t fail2ban-cloudflare "no $ENV_FILE; skipping $ACTION $IP"; exit 0; }
# shellcheck disable=SC1090
. "$ENV_FILE"
[ -n "${CF_API_TOKEN:-}" ] && [ -n "${CF_ACCOUNT_ID:-}" ] && [ -n "${CF_LIST_ID:-}" ] || { logger -t fail2ban-cloudflare "cloudflare-list.env incomplete; skipping"; exit 0; }

API="https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/rules/lists/$CF_LIST_ID/items"
AUTH="Authorization: Bearer $CF_API_TOKEN"

case "$ACTION" in
  ban)
    # Reject anything that is not a bare IPv4/IPv6 literal (defensive: this lands in JSON).
    case "$IP" in *[!0-9a-fA-F:.]*|"") logger -t fail2ban-cloudflare "refusing odd ip '$IP'"; exit 0;; esac
    body=$(printf '[{"ip":"%s","comment":"fail2ban %s %s"}]' "$IP" "$JAIL" "$(date -u +%Y-%m-%dT%H:%MZ)")
    code=$(curl -sS -o /tmp/cf-list-ban.$$ -w '%{http_code}' --max-time 15 -X POST -H "$AUTH" -H 'Content-Type: application/json' --data "$body" "$API" 2>/dev/null || echo 000)
    if [ "$code" = "200" ]; then logger -t fail2ban-cloudflare "added $IP ($JAIL) to Cloudflare list";
    else logger -t fail2ban-cloudflare "FAILED to add $IP ($JAIL): http $code $(head -c 200 /tmp/cf-list-ban.$$ 2>/dev/null)"; fi
    rm -f /tmp/cf-list-ban.$$
    ;;
  unban)
    # Find the item ids whose ip matches (python3 is present wherever fail2ban runs), then delete them.
    items=$(curl -sS --max-time 15 -H "$AUTH" "$API?search=$IP" 2>/dev/null | IP="$IP" python3 -c '
import json, os, sys
try:
    data = json.load(sys.stdin).get("result") or []
except Exception:
    data = []
ids = [{"id": it["id"]} for it in data if it.get("ip") == os.environ["IP"]]
print(json.dumps(ids) if ids else "")')
    [ -n "$items" ] || { logger -t fail2ban-cloudflare "unban $IP: not in Cloudflare list"; exit 0; }
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 -X DELETE -H "$AUTH" -H 'Content-Type: application/json' --data "{\"items\":$items}" "$API" 2>/dev/null || echo 000)
    logger -t fail2ban-cloudflare "removed $IP from Cloudflare list: http $code"
    ;;
  *) echo "unknown action $ACTION" >&2; exit 1;;
esac
exit 0
