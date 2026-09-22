from __future__ import annotations

from click.testing import CliRunner

from vpn_cookie.cli import _configured_password, app
from vpn_cookie.config import AppConfig, FidoCredentialConfig, TpmCredentialConfig, load_config
from vpn_cookie.errors import BrowserError


def test_click_prints_browser_errors(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"

    def fake_login(config, password, *, timeout_seconds, headless):
        raise BrowserError("Browser was closed before the VPN cookie was available.")

    monkeypatch.setattr("vpn_cookie.cli.login_and_extract_cookie", fake_login)

    result = CliRunner().invoke(app, ["login", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Error: Browser was closed before the VPN cookie was available." in result.output


def test_login_runs_headless_by_default(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    calls = {}

    def fake_login(config, password, *, timeout_seconds, headless):
        calls["headless"] = headless
        calls["config_headless"] = config.browser.headless
        return "cookie-value"

    monkeypatch.setattr("vpn_cookie.cli.login_and_extract_cookie", fake_login)

    result = CliRunner().invoke(app, ["login", "--config", str(config_path)])

    assert result.exit_code == 0
    assert calls["headless"] is None
    assert calls["config_headless"] is True


def test_login_can_force_a_visible_browser_window(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    calls = {}

    def fake_login(config, password, *, timeout_seconds, headless):
        calls["headless"] = headless
        return "cookie-value"

    monkeypatch.setattr("vpn_cookie.cli.login_and_extract_cookie", fake_login)

    result = CliRunner().invoke(app, ["login", "--no-headless", "--config", str(config_path)])

    assert result.exit_code == 0
    assert calls["headless"] is False


def test_configured_password_warns_when_registered_key_is_not_available(monkeypatch, capsys):
    config = AppConfig()
    config.fido.credentials = [FidoCredentialConfig(credential_id="cred", hmac_salt="salt")]

    def fake_derive_secret(config):
        from vpn_cookie.errors import FidoError

        raise FidoError("No configured FIDO credential matched the connected authenticator.")

    monkeypatch.setattr("vpn_cookie.backends.derive_fido_secret", fake_derive_secret)

    assert _configured_password(config) is None
    captured = capsys.readouterr()
    assert "Password prefill skipped: No configured FIDO credential matched" in captured.err


def test_password_set_requires_backend_when_fido_and_tpm_are_configured(tmp_path):
    config_path = tmp_path / "config.json"
    config = AppConfig()
    config.fido.credentials = [FidoCredentialConfig(credential_id="cred", hmac_salt="salt")]
    config.tpm.credentials = [TpmCredentialConfig(public="pub", private="priv", hmac_salt="salt")]
    from vpn_cookie.config import save_config

    save_config(config, config_path)

    result = CliRunner().invoke(app, ["password", "set", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Choose where to store this password with `--backend fido` or `--backend tpm`" in result.output


def test_password_set_rejects_unconfigured_backend(tmp_path):
    config_path = tmp_path / "config.json"

    result = CliRunner().invoke(app, ["password", "set", "--backend", "tpm", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "No TPM credential is configured" in result.output


def test_routes_set_can_allow_ipv6(tmp_path):
    config_path = tmp_path / "config.json"

    result = CliRunner().invoke(
        app,
        ["routes", "set", "--config", str(config_path), "--allow-ipv6", "10.8.20.0/24"],
    )

    assert result.exit_code == 0
    config = load_config(config_path)
    assert config.routing.mode == "vpn-slice"
    assert config.routing.include == ["10.8.20.0/24"]
    assert config.routing.disable_ipv6 is False


def test_install_browser_runs_playwright_in_this_interpreter(monkeypatch):
    import subprocess
    import sys

    calls = []

    def fake_run(command, *, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("vpn_cookie.browser.subprocess.run", fake_run)

    result = CliRunner().invoke(app, ["install-browser"])

    assert result.exit_code == 0
    assert calls == [[sys.executable, "-m", "playwright", "install", "chromium"]]
    assert "Chromium is installed." in result.output


def test_install_browser_reports_a_failed_install(monkeypatch):
    import subprocess

    def fake_run(command, *, check):
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr("vpn_cookie.browser.subprocess.run", fake_run)

    result = CliRunner().invoke(app, ["install-browser"])

    assert result.exit_code == 1
    assert "Installing Chromium failed with exit status 1" in result.output


def test_login_points_at_install_browser_when_chromium_is_missing(monkeypatch, tmp_path):
    from playwright.sync_api import Error as PlaywrightError

    class FailingPlaywright:
        def __enter__(self):
            raise PlaywrightError(
                "Executable doesn't exist at /home/user/.cache/ms-playwright/chromium-1234/chrome"
            )

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("vpn_cookie.browser.sync_playwright", lambda: FailingPlaywright())

    result = CliRunner().invoke(app, ["login", "--config", str(tmp_path / "config.json")])

    assert result.exit_code == 1
    assert "Chromium required by vpn-cookie is not installed." in result.output
    assert "vpn-cookie install-browser" in result.output
