from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

from vpn_cookie.config import AppConfig, TpmCredentialConfig, b64decode, b64encode
from vpn_cookie.errors import TpmError

SUPPORTED_TPM_DEVICES = {"/dev/tpmrm0", "/dev/tpm0"}
PRIMARY_TEMPLATE_VERSION = 1
TPM_MECHANISM = "hmac-tools"


@dataclass
class TpmToolsRunner:
    executable_prefix: tuple[str, ...] = ()

    def create_hmac_key(self, *, device: str, pin: str) -> tuple[bytes, bytes]:
        with tempfile.TemporaryDirectory(prefix="vpn-cookie-tpm-") as temp_dir:
            workspace = Path(temp_dir)
            pin_file = _write_secret_file(workspace / "pin.auth", pin.encode("utf-8"))
            primary_ctx = workspace / "primary.ctx"
            public_file = workspace / "key.pub"
            private_file = workspace / "key.priv"

            try:
                self._run(
                    "tpm2_createprimary",
                    "-C",
                    "o",
                    "-G",
                    "ecc",
                    "-g",
                    "sha256",
                    "-c",
                    str(primary_ctx),
                    device=device,
                )
                self._run(
                    "tpm2_create",
                    "-C",
                    str(primary_ctx),
                    "-G",
                    "hmac",
                    "-p",
                    f"file:{pin_file}",
                    "-u",
                    str(public_file),
                    "-r",
                    str(private_file),
                    device=device,
                )
                return public_file.read_bytes(), private_file.read_bytes()
            finally:
                self.flush_context(primary_ctx, device=device)

    def hmac(self, *, device: str, public: bytes, private: bytes, salt: bytes, pin: str) -> bytes:
        with tempfile.TemporaryDirectory(prefix="vpn-cookie-tpm-") as temp_dir:
            workspace = Path(temp_dir)
            pin_file = _write_secret_file(workspace / "pin.auth", pin.encode("utf-8"))
            public_file = _write_secret_file(workspace / "key.pub", public)
            private_file = _write_secret_file(workspace / "key.priv", private)
            salt_file = _write_secret_file(workspace / "salt.bin", salt)
            primary_ctx = workspace / "primary.ctx"
            key_ctx = workspace / "key.ctx"
            hmac_file = workspace / "hmac.bin"

            try:
                self._run(
                    "tpm2_createprimary",
                    "-C",
                    "o",
                    "-G",
                    "ecc",
                    "-g",
                    "sha256",
                    "-c",
                    str(primary_ctx),
                    device=device,
                )
                self._run(
                    "tpm2_load",
                    "-C",
                    str(primary_ctx),
                    "-u",
                    str(public_file),
                    "-r",
                    str(private_file),
                    "-c",
                    str(key_ctx),
                    device=device,
                )
                self._run(
                    "tpm2_hmac",
                    "-c",
                    str(key_ctx),
                    "-p",
                    f"file:{pin_file}",
                    "-g",
                    "sha256",
                    "-o",
                    str(hmac_file),
                    str(salt_file),
                    device=device,
                )
                return hmac_file.read_bytes()
            finally:
                self.flush_context(key_ctx, device=device)
                self.flush_context(primary_ctx, device=device)

    def flush_context(self, context: Path, *, device: str) -> None:
        if context.exists():
            self._run("tpm2_flushcontext", str(context), device=device, check=False)

    def _run(self, *args: str, device: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["TPM2TOOLS_TCTI"] = f"device:{device}"
        command = [*self.executable_prefix, *args]
        try:
            completed = subprocess.run(
                command,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise TpmError("TPM support requires the `tpm2-tools` command-line tools.") from error
        if check and completed.returncode != 0:
            raise _command_error(args[0], completed)
        return completed


def prompt_pin(prompt: str = "TPM PIN: ") -> str:
    return getpass(prompt)


def register_tpm(config: AppConfig, *, pin: str) -> AppConfig:
    _require_pin(pin)
    device = _hardware_device(config.tpm.device)
    public, private = _runner().create_hmac_key(device=device, pin=pin)
    config.tpm.credentials.append(
        TpmCredentialConfig(
            public=b64encode(public),
            private=b64encode(private),
            hmac_salt=b64encode(os.urandom(32)),
            mechanism=TPM_MECHANISM,
            primary_template_version=PRIMARY_TEMPLATE_VERSION,
        )
    )
    return config


def derive_secret(config: AppConfig, *, pin: str | None = None) -> tuple[TpmCredentialConfig, bytes]:
    if not config.tpm.credentials:
        raise TpmError("No TPM credential is configured. Run `vpn-cookie tpm-register` first.")
    device = _hardware_device(config.tpm.device)
    pin = prompt_pin() if pin is None else pin
    _require_pin(pin)

    last_error: Exception | None = None
    runner = _runner()
    for credential in config.tpm.credentials:
        if credential.mechanism not in {"hmac", TPM_MECHANISM}:
            last_error = TpmError(f"Unsupported TPM credential mechanism: {credential.mechanism}")
            continue
        try:
            secret = runner.hmac(
                device=device,
                public=b64decode(credential.public),
                private=b64decode(credential.private),
                salt=b64decode(credential.hmac_salt),
                pin=pin,
            )
            return credential, secret
        except TpmError as error:
            last_error = error
    raise TpmError(
        "Could not derive the password key from the configured TPM credential. "
        "Check that this is the same machine, the TPM is accessible, and the PIN is correct."
    ) from last_error


def _runner() -> TpmToolsRunner:
    return TpmToolsRunner()


def _require_pin(pin: str) -> None:
    if not pin:
        raise TpmError("TPM PIN must not be empty.")


def _hardware_device(device: str) -> str:
    if device not in SUPPORTED_TPM_DEVICES:
        raise TpmError(
            "Unsupported TPM device. Stored VPN passwords require a hardware TPM at "
            "/dev/tpmrm0 or /dev/tpm0; software TPMs and simulator TCTIs are not supported."
        )
    if device == "/dev/tpmrm0" and not Path(device).exists() and Path("/dev/tpm0").exists():
        return "/dev/tpm0"
    if not Path(device).exists():
        raise TpmError(
            f"TPM device {device} was not found. Enable the system TPM and make sure "
            "your user has access, typically by joining the `tss` group."
        )
    return device


def _write_secret_file(path: Path, value: bytes) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(value)
    return path


def _command_error(command: str, completed: subprocess.CompletedProcess[str]) -> TpmError:
    details = (completed.stderr or completed.stdout or "").strip()
    lowered = details.lower()
    if "lockout" in lowered:
        return TpmError("TPM is in dictionary-attack lockout. Wait or reset the TPM lockout state.")
    if "authorization" in lowered or "auth" in lowered or "bad value" in lowered:
        return TpmError("TPM authorization failed. Check the TPM PIN and retry.")
    if "permission" in lowered or "access" in lowered:
        return TpmError("Could not access the TPM device. Add your user to the `tss` group or fix device permissions.")
    if details:
        return TpmError(f"{command} failed: {details}")
    return TpmError(f"{command} failed with exit status {completed.returncode}.")
