from __future__ import annotations

from vpn_cookie.backends import available_password, configured_backend_names
from vpn_cookie.config import AppConfig, FidoCredentialConfig, TpmCredentialConfig
from vpn_cookie.crypto import encrypt_password
from vpn_cookie.errors import TpmError


def test_configured_backend_names_prefers_tpm_then_fido():
    config = AppConfig()
    config.fido.credentials = [FidoCredentialConfig(credential_id="cred", hmac_salt="salt")]
    config.tpm.credentials = [TpmCredentialConfig(public="pub", private="priv", hmac_salt="salt")]

    assert configured_backend_names(config) == ["tpm", "fido"]


def test_available_password_falls_back_from_tpm_to_fido(monkeypatch):
    secret = b"x" * 32
    config = AppConfig()
    fido_credential = FidoCredentialConfig(credential_id="cred", hmac_salt="salt")
    fido_credential.password = encrypt_password("vpn-password", secret)
    config.fido.credentials = [fido_credential]
    config.tpm.credentials = [TpmCredentialConfig(public="pub", private="priv", hmac_salt="salt")]
    messages = []

    def fail_tpm(self, config):
        raise TpmError("TPM unavailable")

    monkeypatch.setattr("vpn_cookie.backends.TpmBackend.derive_secret", fail_tpm)
    monkeypatch.setattr("vpn_cookie.backends.derive_fido_secret", lambda config: (fido_credential, secret))

    assert available_password(config, on_skip=messages.append) == "vpn-password"
    assert messages == ["Password prefill skipped: TPM unavailable"]


def test_available_password_reports_missing_password(monkeypatch):
    secret = b"x" * 32
    config = AppConfig()
    credential = FidoCredentialConfig(credential_id="cred", hmac_salt="salt")
    config.fido.credentials = [credential]
    messages = []

    monkeypatch.setattr("vpn_cookie.backends.derive_fido_secret", lambda config: (credential, secret))

    assert available_password(config, on_skip=messages.append) is None
    assert "has no saved encrypted password" in messages[0]
