# vpn-cookie

`vpn-cookie` logs into a Cisco WebVPN/AnyConnect portal in a fresh Chromium app window, extracts the VPN cookie, and can pass it directly to OpenConnect.

It is built for portals where browser login, SSO, Duo Push, or MFA is easier than driving OpenConnect's interactive login flow directly.

## Features

- Fresh, temporary Chromium profile for every login.
- Optional username and password prefill.
- Optional password encryption backed by one or more FIDO2 keys with `hmac-secret`.
- Raw cookie output for piping into other tools.
- OpenConnect integration using `--cookie-on-stdin`.
- Optional split-tunnel routing through `vpn-slice`.

## Requirements

- Python 3.10+
- `uv`
- `openconnect`
- Chromium installed through Playwright
- Optional: `vpn-slice` for split routing
- Optional: a FIDO2 key with `hmac-secret` support for password prefill

On Fedora, the system tools are typically:

```bash
sudo dnf install openconnect
```

Install `vpn-slice` from your distribution if available, or from upstream:

```bash
python3 -m pip install --user "vpn-slice[dnspython,setproctitle]"
```

## Install

For development from this checkout:

```bash
uv sync
uv run playwright install chromium
uv run vpn-cookie --help
```

To install `vpn-cookie` as a user-wide command from this checkout:

```bash
uv tool install .
uvx playwright install chromium
vpn-cookie --help
```

After code changes, reinstall the tool:

```bash
uv tool install --reinstall .
```

From a published Git repository, use:

```bash
uv tool install git+https://example.invalid/owner/vpn-cookie.git
```

## First Run

Create the config:

```bash
vpn-cookie init --username YOUR_USERNAME
```

The default VPN URL is:

```text
https://vpn.uni-luebeck.de
```

The default cookie name is:

```text
webvpn
```

Both can be changed:

```bash
vpn-cookie init --username YOUR_USERNAME --vpn-url https://vpn.example.edu --cookie-name webvpn
```

## Login And Connect

Print only the raw cookie value:

```bash
vpn-cookie login
```

Login and start OpenConnect:

```bash
vpn-cookie connect --sudo
```

The cookie is passed to OpenConnect via `--cookie-on-stdin`, so it is not exposed in the printed command line or process list.

Both the browser and OpenConnect use `AnyConnect` as their user agent by default. Override the OpenConnect user agent for one run:

```bash
vpn-cookie connect --useragent CustomUA --sudo
```

## Password Prefill

Username and password prefill are optional.

If no username is configured, no username is filled. If no registered FIDO key is connected, or the connected key has no saved password, the password field is left for manual entry.

Register a FIDO key and store the password encrypted for that key:

```bash
vpn-cookie fido-register
vpn-cookie password set
```

Repeat those two commands once for each FIDO key you want to use. Each key gets its own encrypted password entry.

The plaintext password is never written to disk.

## Split Routes

OpenConnect calls a vpnc-compatible script to configure local routes and DNS after the tunnel comes up. By default that is usually `vpnc-script`.

`vpn-slice` is a replacement script that only routes selected networks or hostnames through the VPN. `vpn-cookie` can configure OpenConnect to use it through `--script 'vpn-slice ...'`.

Generic example:

```bash
vpn-cookie routes set 10.0.0.0/8 intranet.example.edu
vpn-cookie connect --sudo
```

Uni Lübeck example:

```bash
vpn-cookie routes set 10.8.20.0/24 imi.uni-luebeck.de 141.83.0.0/16
vpn-cookie connect --sudo
```

Show configured routes:

```bash
vpn-cookie routes show
```

Return to OpenConnect's server-provided routes:

```bash
vpn-cookie routes clear
```

Useful route checks after connecting:

```bash
ip route
ip route get 1.1.1.1
ip route get 10.8.20.1
resolvectl dns
resolvectl domain
```

With split routing, normal internet traffic should use your local network interface, while configured VPN networks use `tun0`.
