# Kitty Partner Relay bridge (Go)

This is the small, stateless bridge between Kitty Bots and the partner's
65-slot relay pool. It runs on the VPS, keeps the partner base64 secret there,
and generates a fresh partner TOTP for each upstream WebSocket.

The browser never receives `PARTNER_SECRET_B64`, a partner TOTP, or a
long-lived VPS access key. It only receives a two-minute, one-time Kitty relay
ticket after its normal Kitty account session has been verified.

## Connection flow

```text
Kitty Bots → Kitty account service → one-time bridge ticket
Kitty Bots → this VPS bridge → partner relay (fresh server-side TOTP) → MooMoo
```

The ticket permits only one connection and is remembered as a hash in RAM
until it expires. The Go bridge has no database and does not persist player,
Discord, game-payload, TOTP, or partner-secret data. Its operational logs use
only the target hostname. Once the partner WebSocket is open, its connection
remains open when the five-minute TOTP window changes.

## Required configuration

Set these on the **MassiveGrid VPS** in `/etc/kitty-vps-relay.env`:

```env
# Given by the partner. This stays on the VPS only.
PARTNER_SECRET_B64=replace-with-the-partner-secret
PARTNER_UPSTREAM=wss://relay.rrelayservers.win/ws

# Generate this yourself. It must exactly match BOT_RELAY_SIGNING_SECRET on
# the Kitty account service; it is not the partner secret.
RELAY_TOKEN_SIGNING_SECRET=replace-with-a-different-random-32-plus-character-secret

RELAY_MAX_TUNNELS=65
RELAY_TARGET_SUFFIXES=moomoo.io
RELAY_BIND_HOST=127.0.0.1
PORT=10000
```

Then set these on the **Kitty account service** (for example, its Render
environment):

```env
BOT_RELAY_URL=wss://relay.example.com
BOT_RELAY_SIGNING_SECRET=the-exact-same-value-as-RELAY_TOKEN_SIGNING_SECRET
BOT_RELAY_MAX_TUNNELS=65
```

`relay.example.com` must be the hostname pointing to this VPS. Never put any
of these secrets in the userscript, browser storage, Caddy configuration, or a
chat message.

## Deploy on MassiveGrid

Use Go 1.22+ and a DNS hostname pointing to the VPS. Caddy provides TLS; the
bridge itself listens only on localhost.

```sh
sudo useradd --system --home /opt/kitty-vps-relay --shell /usr/sbin/nologin kittyrelay
sudo mkdir -p /opt/kitty-vps-relay
sudo chown kittyrelay:kittyrelay /opt/kitty-vps-relay

# Copy this directory to /opt/kitty-vps-relay, then:
cd /opt/kitty-vps-relay
go mod download
go build -trimpath -ldflags='-s -w' -o kitty-vps-relay .

sudo install -m 600 -o root -g root /dev/null /etc/kitty-vps-relay.env
sudoedit /etc/kitty-vps-relay.env
```

Copy the values above into that environment file. Generate the bridge-ticket
signing secret with:

```sh
openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n'
```

Install and start the included service:

```sh
sudo cp kitty-vps-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kitty-vps-relay
sudo systemctl status kitty-vps-relay
```

Copy `Caddyfile.example` into the Caddy configuration, replace
`relay.example.com` with the real hostname, then reload Caddy. Verify the
private process and public TLS endpoint:

```sh
curl http://127.0.0.1:10000/health
curl https://relay.example.com/health
```

The health response contains only connection counts and configuration state;
it never returns credentials or a target URL. Keep the VPS clock synchronized
with NTP because the partner accepts five-minute TOTP windows.

## Using it in Kitty Bots

Sign into the regular Kitty account, choose **Kitty server-side relay**, and
set the bot count up to 65. There is no VPS URL/key form to fill in for this
mode: the account service returns the public bridge URL and a one-time ticket
automatically.

The older **External VPS relay** screen remains only for an unrelated,
manually configured legacy relay. Do not use it for this partner setup.

## Safety checks

- The bridge accepts only `https` MooMoo origins by default.
- It accepts only `wss://` targets matching `RELAY_TARGET_SUFFIXES`, so it is
  not an open proxy.
- The partner TOTP is generated in the bridge for every upstream connection,
  sent only to the partner relay, and never used to close an established bot.
- A 66th connection is still rejected by the partner pool even if a local
  setting is changed.
