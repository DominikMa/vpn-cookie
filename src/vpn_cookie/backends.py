from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from vpn_cookie.config import AppConfig, PasswordConfig
from vpn_cookie.crypto import decrypt_password
from vpn_cookie.errors import FidoError, TpmError
from vpn_cookie.fido import derive_secret as derive_fido_secret


SkipReporter = Callable[[str], None]


@dataclass
class DerivedSecret:
    backend: str
    password: PasswordConfig
    secret: bytes


class SecretBackend(Protocol):
    name: str

    def is_configured(self, config: AppConfig) -> bool: ...

    def derive_secret(self, config: AppConfig) -> DerivedSecret: ...


class FidoBackend:
    name = "fido"

    def is_configured(self, config: AppConfig) -> bool:
        return bool(config.fido.credentials)

    def derive_secret(self, config: AppConfig) -> DerivedSecret:
        credential, secret = derive_fido_secret(config)
        return DerivedSecret(self.name, credential.password, secret)


class TpmBackend:
    name = "tpm"

    def is_configured(self, config: AppConfig) -> bool:
        return bool(config.tpm.credentials)

    def derive_secret(self, config: AppConfig) -> DerivedSecret:
        from vpn_cookie.tpm import derive_secret

        credential, secret = derive_secret(config)
        return DerivedSecret(self.name, credential.password, secret)


def configured_backend_names(config: AppConfig) -> list[str]:
    return [backend.name for backend in _backend_order(config) if backend.is_configured(config)]


def available_password(config: AppConfig, on_skip: SkipReporter | None = None) -> str | None:
    for backend in _backend_order(config):
        if not backend.is_configured(config):
            continue
        try:
            derived = backend.derive_secret(config)
        except (FidoError, TpmError) as error:
            _report(on_skip, f"Password prefill skipped: {error}")
            continue

        if not derived.password.nonce or not derived.password.ciphertext:
            _report(
                on_skip,
                "Password prefill skipped: the configured "
                f"{derived.backend.upper()} credential has no saved encrypted password. "
                f"Run `vpn-cookie password set --backend {derived.backend}`, "
                "or enter the password manually.",
            )
            continue

        try:
            return decrypt_password(derived.password, derived.secret)
        except Exception as error:
            _report(
                on_skip,
                "Password prefill skipped: saved password could not be decrypted with the configured "
                f"{derived.backend.upper()} credential ({error}). Enter the password manually, "
                f"or run `vpn-cookie password set --backend {derived.backend}` again.",
            )
    return None


def _backend_order(config: AppConfig) -> list[SecretBackend]:
    backends: list[SecretBackend] = []
    if config.tpm.credentials:
        backends.append(TpmBackend())
    backends.append(FidoBackend())
    return backends


def _report(on_skip: SkipReporter | None, message: str) -> None:
    if on_skip is not None:
        on_skip(message)
