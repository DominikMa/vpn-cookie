from __future__ import annotations

from vpn_cookie.browser import cookie_value
from vpn_cookie.config import AppConfig, FidoCredentialConfig, PasswordConfig, config_from_dict, load_config, save_config
from vpn_cookie.crypto import decrypt_password, encrypt_password
from vpn_cookie.errors import OpenConnectError
from vpn_cookie.openconnect import openconnect_command, run_openconnect, vpn_slice_script


def test_config_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")
    config.routing.mode = "vpn-slice"
    config.routing.include = ["10.0.0.0/8"]
    save_config(config, path)

    loaded = load_config(path)

    assert loaded.username == "alice"
    assert loaded.vpn_url == "https://vpn.example.test"
    assert loaded.cookie_name == "webvpn"
    assert loaded.browser.useragent == "AnyConnect"
    assert loaded.openconnect.useragent == "AnyConnect"
    assert loaded.routing.mode == "vpn-slice"
    assert loaded.routing.include == ["10.0.0.0/8"]


def test_password_encryption_roundtrip():
    secret = b"x" * 32
    encrypted = encrypt_password("correct horse battery staple", secret)

    assert encrypted.ciphertext
    assert encrypted.nonce
    assert "correct horse" not in encrypted.ciphertext
    assert decrypt_password(encrypted, secret) == "correct horse battery staple"


def test_config_migrates_legacy_single_fido_password():
    data = {
        "fido": {"credential_id": "cred", "hmac_salt": "salt"},
        "password": {"nonce": "nonce", "ciphertext": "ciphertext"},
    }

    config = config_from_dict(data)

    assert config.fido.credentials == [
        FidoCredentialConfig(
            credential_id="cred",
            hmac_salt="salt",
            password=PasswordConfig(nonce="nonce", ciphertext="ciphertext"),
        )
    ]


def test_config_roundtrips_multiple_fido_passwords(tmp_path):
    path = tmp_path / "config.json"
    config = AppConfig()
    config.fido.credentials = [
        FidoCredentialConfig(
            credential_id="cred-1",
            hmac_salt="salt-1",
            password=PasswordConfig(nonce="nonce-1", ciphertext="ciphertext-1"),
        ),
        FidoCredentialConfig(
            credential_id="cred-2",
            hmac_salt="salt-2",
            password=PasswordConfig(nonce="nonce-2", ciphertext="ciphertext-2"),
        ),
    ]

    save_config(config, path)
    loaded = load_config(path)

    assert loaded.fido.credentials == config.fido.credentials


def test_cookie_value_finds_named_cookie():
    cookies = [
        {"name": "other", "value": "1"},
        {"name": "webvpn", "value": "abc"},
    ]

    assert cookie_value(cookies, "webvpn") == "abc"


def test_cookie_value_returns_none_for_missing_cookie():
    assert cookie_value([{"name": "other", "value": "1"}], "webvpn") is None


def test_openconnect_command_uses_cookie_on_stdin():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")

    command = openconnect_command(config)

    assert command == [
        "openconnect",
        "--protocol=anyconnect",
        "--user=alice",
        "--cookie-on-stdin",
        "--useragent",
        "AnyConnect",
        "https://vpn.example.test",
    ]


def test_openconnect_command_omits_empty_username():
    config = AppConfig(vpn_url="https://vpn.example.test")

    command = openconnect_command(config)

    assert command == [
        "openconnect",
        "--protocol=anyconnect",
        "--cookie-on-stdin",
        "--useragent",
        "AnyConnect",
        "https://vpn.example.test",
    ]


def test_openconnect_command_can_use_sudo_background_and_extra_args():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")

    command = openconnect_command(
        config,
        use_sudo=True,
        background=True,
        extra_args=["--disable-ipv6"],
    )

    assert command == [
        "sudo",
        "openconnect",
        "--protocol=anyconnect",
        "--user=alice",
        "--cookie-on-stdin",
        "--useragent",
        "AnyConnect",
        "--background",
        "--disable-ipv6",
        "https://vpn.example.test",
    ]


def test_vpn_slice_script_quotes_routes_and_hosts():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")
    config.routing.mode = "vpn-slice"
    config.routing.include = ["10.0.0.0/8", "host name"]
    config.routing.vpn_slice_args = ["--no-host-names"]

    assert vpn_slice_script(config) == "vpn-slice --no-host-names 10.0.0.0/8 'host name'"


def test_openconnect_command_uses_configured_vpn_slice_routes():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")
    config.routing.mode = "vpn-slice"
    config.routing.include = ["10.0.0.0/8", "%10.1.2.0/24"]

    command = openconnect_command(config)

    assert command == [
        "openconnect",
        "--protocol=anyconnect",
        "--user=alice",
        "--cookie-on-stdin",
        "--useragent",
        "AnyConnect",
        "--script",
        "vpn-slice 10.0.0.0/8 %10.1.2.0/24",
        "https://vpn.example.test",
    ]


def test_openconnect_command_can_disable_useragent():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")
    config.openconnect.useragent = None

    command = openconnect_command(config)

    assert "--useragent" not in command


def test_openconnect_command_can_override_useragent():
    config = AppConfig(username="alice", vpn_url="https://vpn.example.test")

    command = openconnect_command(config, useragent="CustomUA")

    assert "--useragent" in command
    assert command[command.index("--useragent") + 1] == "CustomUA"


def test_run_openconnect_prints_command_without_cookie(monkeypatch, capsys):
    calls = []

    class Completed:
        returncode = 0

    def fake_run(command, *, input, text, check):
        calls.append((command, input, text, check))
        return Completed()

    monkeypatch.setattr("vpn_cookie.openconnect.subprocess.run", fake_run)

    returncode = run_openconnect(["openconnect", "--useragent", "AnyConnect", "https://vpn.example.test"], "secret-cookie")

    captured = capsys.readouterr()
    assert returncode == 0
    assert "Running: openconnect --useragent AnyConnect https://vpn.example.test" in captured.err
    assert "secret-cookie" not in captured.err
    assert calls == [
        (
            ["openconnect", "--useragent", "AnyConnect", "https://vpn.example.test"],
            "secret-cookie\n",
            True,
            False,
        )
    ]


def test_run_openconnect_reports_missing_executable(monkeypatch):
    def fake_run(command, *, input, text, check):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr("vpn_cookie.openconnect.subprocess.run", fake_run)

    try:
        run_openconnect(["missing-openconnect", "https://vpn.example.test"], "cookie")
    except OpenConnectError as error:
        assert "Could not start 'missing-openconnect'" in str(error)
    else:
        raise AssertionError("Expected OpenConnectError")


def test_run_openconnect_reports_nonzero_exit(monkeypatch):
    class Completed:
        returncode = 7

    def fake_run(command, *, input, text, check):
        return Completed()

    monkeypatch.setattr("vpn_cookie.openconnect.subprocess.run", fake_run)

    try:
        run_openconnect(["openconnect", "https://vpn.example.test"], "cookie")
    except OpenConnectError as error:
        assert "OpenConnect exited with status 7" in str(error)
    else:
        raise AssertionError("Expected OpenConnectError")
