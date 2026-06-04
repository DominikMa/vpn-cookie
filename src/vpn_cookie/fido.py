from __future__ import annotations

import ctypes
import os
import sys
from getpass import getpass
from typing import Any, Iterable

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server

from vpn_cookie.config import AppConfig, FidoCredentialConfig, b64decode, b64encode

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:  # pragma: no cover - optional dependency
    CtapPcscDevice = None

try:
    from fido2.client.windows import WindowsClient
except Exception:  # pragma: no cover - platform-specific optional import
    WindowsClient = None


class CliInteraction(UserInteraction):
    def __init__(self) -> None:
        self._pin: str | None = None

    def prompt_up(self) -> None:
        print("Touch your FIDO authenticator now...", file=sys.stderr)

    def request_pin(self, permissions: Any, rp_id: str) -> str:
        if self._pin is None:
            self._pin = getpass("FIDO PIN: ")
        return self._pin

    def request_uv(self, permissions: Any, rp_id: str) -> bool:
        print("User verification is required on the authenticator.", file=sys.stderr)
        return True


def _use_windows_client() -> bool:
    if WindowsClient is None:
        return False
    try:
        return bool(WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _enumerate_devices() -> Iterable[Any]:
    yield from CtapHidDevice.list_devices()
    if CtapPcscDevice is not None:
        yield from CtapPcscDevice.list_devices()


def _client(config: AppConfig) -> Any:
    collector = DefaultClientDataCollector(config.fido.origin)
    if _use_windows_client():
        return WindowsClient(collector, allow_hmac_secret=True)

    for device in _enumerate_devices():
        client = Fido2Client(
            device,
            client_data_collector=collector,
            user_interaction=CliInteraction(),
            extensions=[HmacSecretExtension(allow_hmac_secret=True)],
        )
        if "hmac-secret" in client.info.extensions:
            return client
    raise RuntimeError("No FIDO2 authenticator with hmac-secret support was found.")


def register_credential(config: AppConfig) -> AppConfig:
    client = _client(config)
    server = Fido2Server(
        {"id": config.fido.rp_id, "name": config.fido.rp_name},
        attestation="none",
    )
    user = {"id": os.urandom(16), "name": config.username or "vpn-user"}
    options, _state = server.register_begin(
        user,
        resident_key_requirement="discouraged",
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    result = client.make_credential(
        {
            **options["publicKey"],
            "extensions": {"hmacCreateSecret": True},
        }
    )
    if not result.client_extension_results.get("hmacCreateSecret"):
        print(
            "Warning: the authenticator did not confirm hmac-secret creation; continuing anyway.",
            file=sys.stderr,
        )
    credential_id = b64encode(result.raw_id)
    if not any(entry.credential_id == credential_id for entry in config.fido.credentials):
        config.fido.credentials.append(
            FidoCredentialConfig(
                credential_id=credential_id,
                hmac_salt=b64encode(os.urandom(32)),
            )
        )
    return config


def derive_secret_for_credential(config: AppConfig, credential: FidoCredentialConfig, client: Any | None = None) -> bytes:
    client = client or _client(config)
    result = client.get_assertion(
        {
            "rpId": config.fido.rp_id,
            "challenge": os.urandom(32),
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": b64decode(credential.credential_id),
                }
            ],
            "userVerification": "discouraged",
            "extensions": {
                "hmacGetSecret": {
                    "salt1": b64decode(credential.hmac_salt),
                }
            },
        }
    ).get_response(0)
    extension_results = result.client_extension_results
    hmac_secret = getattr(extension_results, "hmac_get_secret", None)
    if hmac_secret is None and isinstance(extension_results, dict):
        hmac_secret = extension_results.get("hmacGetSecret") or extension_results.get("hmac_get_secret")
    output = getattr(hmac_secret, "output1", None)
    if output is None and isinstance(hmac_secret, dict):
        output = hmac_secret.get("output1")
    if not output:
        raise RuntimeError("FIDO authenticator did not return an hmac-secret output.")
    return output


def derive_secret(config: AppConfig) -> tuple[FidoCredentialConfig, bytes]:
    if not config.fido.credentials:
        raise ValueError("No FIDO credential is configured. Run `vpn-cookie fido-register` first.")

    client = _client(config)
    last_error: Exception | None = None
    for credential in config.fido.credentials:
        try:
            return credential, derive_secret_for_credential(config, credential, client=client)
        except Exception as error:
            last_error = error
    raise RuntimeError("No configured FIDO credential matched the connected authenticator.") from last_error


def try_derive_secret(config: AppConfig) -> tuple[FidoCredentialConfig, bytes] | None:
    try:
        return derive_secret(config)
    except Exception:
        return None
