from __future__ import annotations

import shlex
import subprocess
import sys

from vpn_cookie.config import AppConfig


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
    completed = subprocess.run(command, input=f"{cookie}\n", text=True, check=False)
    return completed.returncode
