from __future__ import annotations

from click.testing import CliRunner

from vpn_cookie.cli import _configured_password, app
from vpn_cookie.config import AppConfig, FidoCredentialConfig
from vpn_cookie.errors import BrowserError


def test_click_prints_browser_errors(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"

    def fake_login(config, password, *, timeout_seconds):
        raise BrowserError("Browser was closed before the VPN cookie was available.")

    monkeypatch.setattr("vpn_cookie.cli.login_and_extract_cookie", fake_login)

    result = CliRunner().invoke(app, ["login", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Error: Browser was closed before the VPN cookie was available." in result.output


def test_configured_password_warns_when_registered_key_is_not_available(monkeypatch, capsys):
    config = AppConfig()
    config.fido.credentials = [FidoCredentialConfig(credential_id="cred", hmac_salt="salt")]

    def fake_derive_secret(config):
        from vpn_cookie.errors import FidoError

        raise FidoError("No configured FIDO credential matched the connected authenticator.")

    monkeypatch.setattr("vpn_cookie.cli.derive_secret", fake_derive_secret)

    assert _configured_password(config) is None
    captured = capsys.readouterr()
    assert "Password prefill skipped: No configured FIDO credential matched" in captured.err
