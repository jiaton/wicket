# fail2ban → Cloudflare IP list

For hosts you keep **direct** (DNS-only, no Cloudflare proxy: media servers, a KVM), fail2ban on the box still does the banning. This action pushes each of those bans into the same Cloudflare IP list wicket writes to, so an address that attacked a direct host is also blocked at the edge on every proxied one. `fail2ban-client unban <ip>` removes it again. wicket's hourly reconcile never touches these items (it only manages items whose comment starts with `wicket `).

Note the reverse is not needed: an attacker banned by wicket never reaches your direct hosts through Cloudflare anyway, and if they find the direct hosts, fail2ban is there.

## Install

```sh
sudo cp cloudflare-list.conf /etc/fail2ban/action.d/cloudflare-list.conf
sudo cp cloudflare-list.sh /etc/fail2ban/cloudflare-list.sh && sudo chmod 755 /etc/fail2ban/cloudflare-list.sh
sudo cp cloudflare-list.env.example /etc/fail2ban/cloudflare-list.env && sudo chmod 600 /etc/fail2ban/cloudflare-list.env
sudoedit /etc/fail2ban/cloudflare-list.env    # token, account id, list id
```

Then add `cloudflare-list` to the `action` of each jail, next to whatever it already has:

```ini
[jellyfin]
enabled = true
...
action = iptables-multiport[name=jellyfin, port="http,https"]
         cloudflare-list
```

`sudo fail2ban-client reload`, then test with a documentation address: `sudo fail2ban-client set jellyfin banip 192.0.2.1`, check the list in the dashboard, `sudo fail2ban-client set jellyfin unbanip 192.0.2.1`.

Requirements on the host: `curl`, `python3` (used to parse the unban lookup), `logger`. Failures are logged to syslog with the tag `fail2ban-cloudflare` and never fail the ban itself.

## If your proxy is behind the tunnel too

When your reverse proxy also serves tunnelled hosts, its logs show `cloudflared`'s address as the client. Make it log the real visitor (`Cf-Connecting-Ip`) and make your filters match that field, or fail2ban will ban the tunnel. Caddy:

```
servers {
    trusted_proxies static private_ranges
    client_ip_headers Cf-Connecting-Ip
}
```

and match `client_ip` instead of `remote_ip` in the filter. Add the Docker network range to `ignoreip` as a safety net.
