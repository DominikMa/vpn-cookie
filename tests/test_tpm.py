from __future__ import annotations

import subprocess
from pathlib import Path

from vpn_cookie.config import AppConfig, TpmCredentialConfig, b64encode
from vpn_cookie.errors import TpmError
from vpn_cookie.tpm import TpmToolsRunner, _hardware_device, derive_secret, register_tpm


class FakeRunner:
    def create_hmac_key(self, *, device, pin):
        return b"public", b"private"

    def hmac(self, *, device, public, private, salt, pin):
        assert device == "/dev/tpmrm0"
        assert public == b"public"
        assert private == b"private"
        assert salt == b"salt"
        assert pin == "1234"
        return b"derived-secret"


def test_hardware_device_rejects_software_tcti():
    try:
        _hardware_device("mssim:host=localhost,port=2321")
    except TpmError as error:
        assert "software TPMs and simulator TCTIs are not supported" in str(error)
    else:
        raise AssertionError("Expected TpmError")


def test_hardware_device_falls_back_to_tpm0(monkeypatch):
    def fake_exists(path):
        return str(path) == "/dev/tpm0"

    monkeypatch.setattr("vpn_cookie.tpm.Path.exists", fake_exists)

    assert _hardware_device("/dev/tpmrm0") == "/dev/tpm0"


def test_register_tpm_stores_hmac_tools_credential(monkeypatch):
    config = AppConfig()
    monkeypatch.setattr("vpn_cookie.tpm._hardware_device", lambda device: device)
    monkeypatch.setattr("vpn_cookie.tpm._runner", lambda: FakeRunner())

    register_tpm(config, pin="1234")

    assert len(config.tpm.credentials) == 1
    assert config.tpm.credentials[0].public == b64encode(b"public")
    assert config.tpm.credentials[0].private == b64encode(b"private")
    assert config.tpm.credentials[0].mechanism == "hmac-tools"
    assert config.tpm.credentials[0].hmac_salt
    assert config.tpm.credentials[0].requires_pin is True


def test_register_tpm_rejects_empty_pin(monkeypatch):
    config = AppConfig()
    monkeypatch.setattr("vpn_cookie.tpm._hardware_device", lambda device: device)
    monkeypatch.setattr("vpn_cookie.tpm._runner", lambda: FakeRunner())

    try:
        register_tpm(config, pin="")
    except TpmError as error:
        assert "must not be empty" in str(error)
    else:
        raise AssertionError("Expected TpmError")


def test_derive_secret_uses_stored_tpm_blobs(monkeypatch):
    config = AppConfig()
    config.tpm.credentials = [
        TpmCredentialConfig(
            public=b64encode(b"public"),
            private=b64encode(b"private"),
            hmac_salt=b64encode(b"salt"),
        )
    ]
    monkeypatch.setattr("vpn_cookie.tpm._hardware_device", lambda device: device)
    monkeypatch.setattr("vpn_cookie.tpm._runner", lambda: FakeRunner())

    credential, secret = derive_secret(config, pin="1234")

    assert credential is config.tpm.credentials[0]
    assert secret == b"derived-secret"


def test_runner_register_uses_tpm2_tools_and_file_auth(monkeypatch):
    calls = []

    def fake_run(command, *, env, check, capture_output, text):
        calls.append((command, env))
        if command[0] == "tpm2_create":
            Path(command[command.index("-u") + 1]).write_bytes(b"public")
            Path(command[command.index("-r") + 1]).write_bytes(b"private")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("vpn_cookie.tpm.subprocess.run", fake_run)

    public, private = TpmToolsRunner().create_hmac_key(device="/dev/tpmrm0", pin="1234")

    assert public == b"public"
    assert private == b"private"
    assert [call[0][0] for call in calls[:2]] == ["tpm2_createprimary", "tpm2_create"]
    assert all(call[1]["TPM2TOOLS_TCTI"] == "device:/dev/tpmrm0" for call in calls)
    create_args = calls[1][0]
    assert "-p" in create_args
    assert create_args[create_args.index("-p") + 1].startswith("file:")
    assert "1234" not in create_args


def test_runner_derive_uses_load_hmac_and_file_auth(monkeypatch):
    calls = []

    def fake_run(command, *, env, check, capture_output, text):
        calls.append((command, env))
        if command[0] == "tpm2_hmac":
            Path(command[command.index("-o") + 1]).write_bytes(b"derived-secret")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("vpn_cookie.tpm.subprocess.run", fake_run)

    secret = TpmToolsRunner().hmac(
        device="/dev/tpm0",
        public=b"public",
        private=b"private",
        salt=b"salt",
        pin="1234",
    )

    assert secret == b"derived-secret"
    assert [call[0][0] for call in calls[:3]] == ["tpm2_createprimary", "tpm2_load", "tpm2_hmac"]
    assert all(call[1]["TPM2TOOLS_TCTI"] == "device:/dev/tpm0" for call in calls)
    hmac_args = calls[2][0]
    assert hmac_args[hmac_args.index("-p") + 1].startswith("file:")
    assert "1234" not in hmac_args


def test_runner_maps_nonzero_exit_to_tpm_error(monkeypatch):
    def fake_run(command, *, env, check, capture_output, text):
        return subprocess.CompletedProcess(command, 1, "", "authorization failed")

    monkeypatch.setattr("vpn_cookie.tpm.subprocess.run", fake_run)

    try:
        TpmToolsRunner().create_hmac_key(device="/dev/tpmrm0", pin="1234")
    except TpmError as error:
        assert "authorization failed" in str(error).lower()
    else:
        raise AssertionError("Expected TpmError")
