# vpn-cookie

Small uv-managed CLI for logging into a Cisco WebVPN page in a fresh Playwright Chromium context and printing the configured VPN cookie.

## Setup

```bash
uv sync
uv run playwright install chromium
uv run vpn-cookie init --username YOUR_USERNAME
uv run vpn-cookie fido-register
uv run vpn-cookie password set
uv run vpn-cookie connect --sudo
```

By default the VPN URL is `https://vpn.uni-luebeck.de`, the cookie name is `webvpn`, and the browser is visible but uses a fresh non-persistent profile for every login.

The username, FIDO credential metadata, and encrypted password are stored in your user config directory. The plaintext password is never written to disk. Username and password prefill are optional: if no username is configured, no username is filled; if no configured FIDO key is connected or that key has no encrypted password yet, the password field is left for manual entry.

You can register multiple FIDO keys:

```bash
uv run vpn-cookie fido-register
uv run vpn-cookie password set
```

Run those two commands once for each key. Each key gets its own encrypted password entry.

Use `uv run vpn-cookie login` when you only want the raw cookie value on stdout. Use `uv run vpn-cookie connect` to retrieve the cookie and pass it to OpenConnect via `--cookie-on-stdin`; add `--sudo` when OpenConnect needs privileges to create the tunnel.

## Split routes

OpenConnect applies routes through its vpnc script. To route only selected networks or hosts through the VPN, install `vpn-slice` and configure routes:

```bash
uv run vpn-cookie routes set 10.0.0.0/8 intranet.uni-luebeck.de
uv run vpn-cookie connect --sudo
```

This stores a `routing` section in the config and makes `connect` pass `--script 'vpn-slice ...'` to OpenConnect. Use this to return to OpenConnect's server-provided routes:

```bash
uv run vpn-cookie routes clear
```
