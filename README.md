# Kitty Partner Relay bridge (Go)

This is the private MassiveGrid bridge for the partner's **65-bot** pool. It
keeps the partner's base64 secret on the VPS, generates a fresh partner TOTP
for every upstream WebSocket, and preserves Kitty Bots' existing protected
external-relay protocol for browsers.

The browser never sees `PARTNER_SECRET_B64` and never talks to
`relay.rrelayservers.win` directly.

## What to enter in Kitty Bots

Choose **External VPS relay**, then enter:

1. `wss://your-relay-hostname/relay`
2. The private `RELAY_ACCESS_KEY` generated for this bridge
3. `65` for the VPS cap

The access key is local to this bridge. It is not the partner secret and it is
not a TOTP value.

## Deploy on MassiveGrid

Use a VPS with Go 1.22+ and a DNS name pointing to it. Caddy supplies the TLS
certificate, so the bridge itself listens only on localhost.

```sh
sudo useradd --system --home /opt/kitty-vps-relay --shell /usr/sbin/nologin kittyrelay
sudo mkdir -p /opt/kitty-vps-relay
sudo chown kittyrelay:kittyrelay /opt/kitty-vps-relay

# Copy this directory to /opt/kitty-vps-relay, then:
cd /opt/kitty-vps-relay
go mod download
go build -trimpath -ldflags='-s -w' -o kitty-vps-relay .
```

Create `/etc/kitty-vps-relay.env` with mode `600`:

```sh
sudo install -m 600 -o root -g root /dev/null /etc/kitty-vps-relay.env
sudoedit /etc/kitty-vps-relay.env
```

Use the values from `.env.example`. Paste the partner-provided
`PARTNER_SECRET_B64` there exactly once. Generate a separate local browser key:

```sh
openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n'
```

Set that generated value as `RELAY_ACCESS_KEY`, set `RELAY_MAX_TUNNELS=65`,
and leave `RELAY_BIND_HOST=127.0.0.1`. Do not put either secret in source
control, Caddy, or the userscript. Keep the VPS clock synchronized with NTP;
the upstream accepts five-minute TOTP windows.

Install and start the included service:

```sh
sudo cp kitty-vps-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kitty-vps-relay
sudo systemctl status kitty-vps-relay
```

Copy `Caddyfile.example` into your Caddy configuration, replace
`relay.example.com` with the real DNS hostname, and reload Caddy. Verify the
private process and public TLS endpoint:

```sh
curl http://127.0.0.1:10000/health
curl https://your-relay-hostname/health
```

The health response includes only local tunnel usage and the configured cap;
it never returns either secret.

## Protocol and safety

Kitty Bots opens `wss://your-relay-hostname/relay?key=<RELAY_ACCESS_KEY>` and
sends one initial frame:

```json
{"type":"open","target":"wss://<current-moomoo-shard>/?token=cf:..."}
```

The bridge validates the MooMoo browser origin, local access key, target host,
and local tunnel limit. In partner mode it then opens:

```text
wss://relay.rrelayservers.win/ws?pool=partner&token=<fresh-totp>&target=<encoded-target>
Sec-WebSocket-Protocol: totp.<fresh-totp>
```

Only `wss://` MooMoo targets matching `RELAY_TARGET_SUFFIXES` are accepted, so
this is not an open proxy. A partner pool limit is still authoritative: a 66th
connection is rejected upstream even if the local setting was changed.

## Optional per-player bridge credentials

For a shared owner setup, `RELAY_ACCESS_KEY` is simplest. The existing signed
token option remains available: omit `RELAY_ACCESS_KEY`, set
`RELAY_TOKEN_SIGNING_SECRET`, and issue the short-lived signed credentials
described in the previous relay integration. The partner secret remains VPS
only in either mode.
