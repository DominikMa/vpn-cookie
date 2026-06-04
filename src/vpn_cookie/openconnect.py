from __future__ import annotations

import shlex
import subprocess
import sys

from vpn_cookie.config import AppConfig
from vpn_cookie.errors import OpenConnectError


def vpn_slice_script(config: AppConfig) -> str | None:
    if config.routing.mode != "vpn-slice" or not config.routing.include:
        return None
    return shlex.join(
        [
            config.routing.vpn_slice,
            *config.routing.vpn_slice_args,
            *config.routing.include,
        ]
    )


def openconnect_command(
    config: AppConfig,
    *,
    executable: str = "openconnect",
    protocol: str = "anyconnect",
    use_sudo: bool = False,
    background: bool = False,
    useragent: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    effective_useragent = useragent if useragent is not None else config.openconnect.useragent
    command = [
        executable,
        f"--protocol={protocol}",
        "--cookie-on-stdin",
    ]
    if config.username:
        command.insert(2, f"--user={config.username}")
    if effective_useragent:
        command.extend(["--useragent", effective_useragent])
    if background:
        command.append("--background")
    script = vpn_slice_script(config)
    if script:
        command.extend(["--script", script])
    if extra_args:
        command.extend(extra_args)
    command.append(config.vpn_url)
    if use_sudo:
        return ["sudo", *command]
    return command


def run_openconnect(command: list[str], cookie: str) -> int:
    print(f"Running: {shlex.join(command)}", file=sys.stderr)
    try:
        completed = subprocess.run(command, input=f"{cookie}\n", text=True, check=False)
    except FileNotFoundError as error:
        raise OpenConnectError(
            f"Could not start {command[0]!r}. Install OpenConnect or pass --openconnect with the executable path."
        ) from error
    except PermissionError as error:
        raise OpenConnectError(
            f"Could not execute {command[0]!r}: permission denied. Check the executable path or use --sudo."
        ) from error
    except OSError as error:
        raise OpenConnectError(f"Could not start OpenConnect: {error}") from error
    if completed.returncode != 0:
        raise OpenConnectError(
            f"OpenConnect exited with status {completed.returncode}. "
            "Check the output above for the VPN gateway's reason."
        )
    return completed.returncode
