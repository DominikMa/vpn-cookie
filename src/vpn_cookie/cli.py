from __future__ import annotations

from getpass import getpass
from pathlib import Path
from typing import Optional

import typer

from vpn_cookie.browser import login_and_extract_cookie
from vpn_cookie.config import AppConfig, default_config_path, load_config, save_config
from vpn_cookie.crypto import decrypt_password, encrypt_password
from vpn_cookie.fido import derive_secret, register_credential, try_derive_secret
from vpn_cookie.openconnect import openconnect_command, run_openconnect

app = typer.Typer(no_args_is_help=True)
password_app = typer.Typer(no_args_is_help=True)
routes_app = typer.Typer(no_args_is_help=True)
app.add_typer(password_app, name="password")
app.add_typer(routes_app, name="routes")


def _load(path: Optional[Path]) -> AppConfig:
    return load_config(path)


@app.command()
def init(
    username: str = typer.Option("", "--username", "-u", help="VPN username to store and prefill."),
    vpn_url: str = typer.Option("https://vpn.uni-luebeck.de", "--vpn-url", help="Cisco VPN login URL."),
    cookie_name: str = typer.Option("webvpn", "--cookie-name", help="Cookie name to print after login."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Create or update the config file."""
    config = _load(config_path)
    config.username = username
    config.vpn_url = vpn_url
    config.cookie_name = cookie_name
    path = save_config(config, config_path)
    typer.echo(f"Wrote config: {path}")


@app.command("show-config")
def show_config(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Print the active config path."""
    path = config_path or default_config_path()
    typer.echo(path)


@app.command("fido-register")
def fido_register(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Register a FIDO credential for password encryption."""
    config = _load(config_path)
    config = register_credential(config)
    path = save_config(config, config_path)
    typer.echo(f"Registered FIDO credential and wrote config: {path}")


@password_app.command("set")
def password_set(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Prompt once for the VPN password and save it encrypted."""
    config = _load(config_path)
    password = getpass("VPN password: ")
    confirm = getpass("VPN password again: ")
    if password != confirm:
        raise typer.BadParameter("Passwords did not match.")
    credential, secret = derive_secret(config)
    credential.password = encrypt_password(password, secret)
    path = save_config(config, config_path)
    typer.echo(f"Encrypted password saved for connected FIDO credential in: {path}")


@routes_app.command("set")
def routes_set(
    routes: list[str] = typer.Argument(
        ...,
        help="Routes/hosts for vpn-slice, for example 10.0.0.0/8 intranet.example.org.",
    ),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
    vpn_slice: str = typer.Option("vpn-slice", "--vpn-slice", help="vpn-slice executable."),
    vpn_slice_arg: list[str] = typer.Option(
        [],
        "--vpn-slice-arg",
        help="Extra argument passed to vpn-slice. Repeat for multiple arguments.",
    ),
) -> None:
    """Configure split-tunnel routes through vpn-slice."""
    config = _load(config_path)
    config.routing.mode = "vpn-slice"
    config.routing.include = routes
    config.routing.vpn_slice = vpn_slice
    config.routing.vpn_slice_args = vpn_slice_arg
    path = save_config(config, config_path)
    typer.echo(f"Wrote vpn-slice routes to: {path}")


@routes_app.command("clear")
def routes_clear(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Use server-provided OpenConnect routes again."""
    config = _load(config_path)
    config.routing.mode = "server"
    config.routing.include = []
    path = save_config(config, config_path)
    typer.echo(f"Cleared configured routes in: {path}")


@routes_app.command("show")
def routes_show(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
) -> None:
    """Show configured route behavior."""
    config = _load(config_path)
    typer.echo(f"mode: {config.routing.mode}")
    if config.routing.mode == "vpn-slice":
        typer.echo(f"vpn_slice: {config.routing.vpn_slice}")
        for route in config.routing.include:
            typer.echo(route)


@app.command()
def login(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
    timeout: int = typer.Option(300, "--timeout", help="Seconds to wait for the VPN cookie."),
) -> None:
    """Open the VPN login browser and print the webvpn cookie."""
    config = _load(config_path)
    password = _configured_password(config)
    typer.echo(login_and_extract_cookie(config, password, timeout_seconds=timeout))


@app.command()
def connect(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Override config file path."),
    timeout: int = typer.Option(300, "--timeout", help="Seconds to wait for the VPN cookie."),
    openconnect: str = typer.Option("openconnect", "--openconnect", help="OpenConnect executable."),
    protocol: str = typer.Option("anyconnect", "--protocol", help="OpenConnect protocol."),
    useragent: Optional[str] = typer.Option(
        None,
        "--useragent",
        help="Override OpenConnect User-Agent. Uses config value by default.",
    ),
    sudo: bool = typer.Option(False, "--sudo", help="Run OpenConnect through sudo."),
    background: bool = typer.Option(False, "--background", "-b", help="Ask OpenConnect to background after startup."),
    extra_arg: list[str] = typer.Option(
        [],
        "--openconnect-arg",
        help="Extra argument passed to OpenConnect. Repeat for multiple arguments.",
    ),
) -> None:
    """Log in with the browser, then start OpenConnect with the retrieved cookie."""
    config = _load(config_path)
    password = _configured_password(config)
    cookie = login_and_extract_cookie(config, password, timeout_seconds=timeout)
    command = openconnect_command(
        config,
        executable=openconnect,
        protocol=protocol,
        useragent=useragent,
        use_sudo=sudo,
        background=background,
        extra_args=extra_arg,
    )
    raise typer.Exit(run_openconnect(command, cookie))


def _configured_password(config: AppConfig) -> str | None:
    derived = try_derive_secret(config)
    if derived is None:
        return None
    credential, secret = derived
    if not credential.password.nonce or not credential.password.ciphertext:
        return None
    try:
        return decrypt_password(credential.password, secret)
    except Exception:
        return None
