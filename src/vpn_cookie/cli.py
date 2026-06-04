from __future__ import annotations

from pathlib import Path
from functools import wraps

import click

from vpn_cookie.browser import login_and_extract_cookie
from vpn_cookie.config import AppConfig, default_config_path, load_config, save_config
from vpn_cookie.crypto import decrypt_password, encrypt_password
from vpn_cookie.errors import FidoError, VpnCookieError
from vpn_cookie.fido import derive_secret, register_credential
from vpn_cookie.openconnect import openconnect_command, run_openconnect


def _load(path: Path | None) -> AppConfig:
    return load_config(path)


def _config_option(function):
    return click.option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path, dir_okay=False),
        help="Override config file path.",
    )(function)


def _handle_errors(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except click.ClickException:
            raise
        except VpnCookieError as error:
            raise click.ClickException(str(error)) from error

    return wrapper


@click.group(no_args_is_help=True)
def app() -> None:
    """Extract a Cisco WebVPN cookie and optionally start OpenConnect."""


@app.command()
@click.option("--username", "-u", default="", help="VPN username to store and prefill.")
@click.option("--vpn-url", default="https://vpn.uni-luebeck.de", help="Cisco VPN login URL.")
@click.option("--cookie-name", default="webvpn", help="Cookie name to print after login.")
@_config_option
@_handle_errors
def init(username: str, vpn_url: str, cookie_name: str, config_path: Path | None) -> None:
    """Create or update the config file."""
    config = _load(config_path)
    config.username = username
    config.vpn_url = vpn_url
    config.cookie_name = cookie_name
    path = save_config(config, config_path)
    click.echo(f"Wrote config: {path}")


@app.command("show-config")
@_config_option
@_handle_errors
def show_config(config_path: Path | None) -> None:
    """Print the active config path."""
    path = config_path or default_config_path()
    click.echo(path)


@app.command("fido-register")
@_config_option
@_handle_errors
def fido_register(config_path: Path | None) -> None:
    """Register a FIDO credential for password encryption."""
    config = _load(config_path)
    config = register_credential(config)
    path = save_config(config, config_path)
    click.echo(f"Registered FIDO credential and wrote config: {path}")


@click.group(no_args_is_help=True)
def password() -> None:
    """Manage stored VPN passwords."""


@password.command("set")
@_config_option
@_handle_errors
def password_set(config_path: Path | None) -> None:
    """Prompt once for the VPN password and save it encrypted."""
    config = _load(config_path)
    password_value = click.prompt(
        "VPN password",
        hide_input=True,
        confirmation_prompt=True,
    )
    credential, secret = derive_secret(config)
    credential.password = encrypt_password(password_value, secret)
    path = save_config(config, config_path)
    click.echo(f"Encrypted password saved for connected FIDO credential in: {path}")


@click.group(no_args_is_help=True)
def routes() -> None:
    """Manage OpenConnect route behavior."""


@routes.command("set")
@click.argument("route_values", nargs=-1, required=True)
@_config_option
@click.option("--vpn-slice", default="vpn-slice", help="vpn-slice executable.")
@click.option(
    "--vpn-slice-arg",
    multiple=True,
    help="Extra argument passed to vpn-slice. Repeat for multiple arguments.",
)
@click.option(
    "--disable-ipv6/--allow-ipv6",
    default=True,
    show_default=True,
    help="Pass --disable-ipv6 to OpenConnect when using vpn-slice.",
)
@_handle_errors
def routes_set(
    route_values: tuple[str, ...],
    config_path: Path | None,
    vpn_slice: str,
    vpn_slice_arg: tuple[str, ...],
    disable_ipv6: bool,
) -> None:
    """Configure split-tunnel routes through vpn-slice."""
    config = _load(config_path)
    config.routing.mode = "vpn-slice"
    config.routing.include = list(route_values)
    config.routing.vpn_slice = vpn_slice
    config.routing.vpn_slice_args = list(vpn_slice_arg)
    config.routing.disable_ipv6 = disable_ipv6
    path = save_config(config, config_path)
    click.echo(f"Wrote vpn-slice routes to: {path}")


@routes.command("clear")
@_config_option
@_handle_errors
def routes_clear(config_path: Path | None) -> None:
    """Use server-provided OpenConnect routes again."""
    config = _load(config_path)
    config.routing.mode = "server"
    config.routing.include = []
    path = save_config(config, config_path)
    click.echo(f"Cleared configured routes in: {path}")


@routes.command("show")
@_config_option
@_handle_errors
def routes_show(config_path: Path | None) -> None:
    """Show configured route behavior."""
    config = _load(config_path)
    click.echo(f"mode: {config.routing.mode}")
    if config.routing.mode == "vpn-slice":
        click.echo(f"vpn_slice: {config.routing.vpn_slice}")
        click.echo(f"disable_ipv6: {config.routing.disable_ipv6}")
        for route in config.routing.include:
            click.echo(route)


@app.command()
@_config_option
@click.option("--timeout", default=300, show_default=True, help="Seconds to wait for the VPN cookie.")
@_handle_errors
def login(config_path: Path | None, timeout: int) -> None:
    """Open the VPN login browser and print the webvpn cookie."""
    config = _load(config_path)
    password_value = _configured_password(config)
    click.echo(login_and_extract_cookie(config, password_value, timeout_seconds=timeout))


@app.command()
@_config_option
@click.option("--timeout", default=300, show_default=True, help="Seconds to wait for the VPN cookie.")
@click.option("--openconnect", default="openconnect", show_default=True, help="OpenConnect executable.")
@click.option("--protocol", default="anyconnect", show_default=True, help="OpenConnect protocol.")
@click.option("--useragent", default=None, help="Override OpenConnect User-Agent. Uses config value by default.")
@click.option("--sudo", is_flag=True, help="Run OpenConnect through sudo.")
@click.option("--background", "-b", is_flag=True, help="Ask OpenConnect to background after startup.")
@click.option(
    "--openconnect-arg",
    multiple=True,
    help="Extra argument passed to OpenConnect. Repeat for multiple arguments.",
)
@_handle_errors
def connect(
    config_path: Path | None,
    timeout: int,
    openconnect: str,
    protocol: str,
    useragent: str | None,
    sudo: bool,
    background: bool,
    openconnect_arg: tuple[str, ...],
) -> None:
    """Log in with the browser, then start OpenConnect with the retrieved cookie."""
    config = _load(config_path)
    password_value = _configured_password(config)
    cookie = login_and_extract_cookie(config, password_value, timeout_seconds=timeout)
    command = openconnect_command(
        config,
        executable=openconnect,
        protocol=protocol,
        useragent=useragent,
        use_sudo=sudo,
        background=background,
        extra_args=list(openconnect_arg),
    )
    raise click.exceptions.Exit(run_openconnect(command, cookie))


app.add_command(password)
app.add_command(routes)


def _configured_password(config: AppConfig) -> str | None:
    if not config.fido.credentials:
        return None
    try:
        derived = derive_secret(config)
    except FidoError as error:
        click.echo(f"Password prefill skipped: {error}", err=True)
        return None
    credential, secret = derived
    if not credential.password.nonce or not credential.password.ciphertext:
        click.echo(
            "Password prefill skipped: the connected FIDO key has no saved encrypted password. "
            "Run `vpn-cookie password set` for this key, or enter the password manually.",
            err=True,
        )
        return None
    try:
        return decrypt_password(credential.password, secret)
    except Exception as error:
        click.echo(
            f"Password prefill skipped: saved password could not be decrypted with the connected FIDO key ({error}). "
            "Enter the password manually, or run `vpn-cookie password set` again for this key.",
            err=True,
        )
        return None
