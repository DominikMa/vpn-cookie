from __future__ import annotations

from vpn_cookie.config import AppConfig, FidoCredentialConfig, b64encode
from fido2.ctap2.extensions import CredProtectExtension, HmacSecretExtension

from vpn_cookie.fido import _client, derive_secret_for_credential, register_credential


class FakeRegistrationResult:
    raw_id = b"credential-id"
    client_extension_results = {"hmacCreateSecret": True}


class FakeRegistrationClient:
    def __init__(self) -> None:
        self.request = None

    def make_credential(self, request):
        self.request = request
        return FakeRegistrationResult()


class FakeServer:
    last_instance = None

    def __init__(self, rp, attestation):
        self.rp = rp
        self.attestation = attestation
        self.register_begin_kwargs = None
        FakeServer.last_instance = self

    def register_begin(self, user, **kwargs):
        self.register_begin_kwargs = kwargs
        return {"publicKey": {"challenge": b"challenge"}}, {}


def test_register_credential_requires_user_verification_by_default(monkeypatch):
    client = FakeRegistrationClient()
    monkeypatch.setattr("vpn_cookie.fido._client", lambda config: client)
    monkeypatch.setattr("vpn_cookie.fido.Fido2Server", FakeServer)

    config = register_credential(AppConfig())

    assert FakeServer.last_instance.register_begin_kwargs["user_verification"] == "required"
    assert client.request["extensions"] == {
        "hmacCreateSecret": True,
        "credentialProtectionPolicy": "userVerificationRequired",
        "enforceCredentialProtectionPolicy": True,
    }
    assert config.fido.credentials[0].user_verification == "required"


def test_register_credential_can_disable_user_verification(monkeypatch):
    client = FakeRegistrationClient()
    monkeypatch.setattr("vpn_cookie.fido._client", lambda config: client)
    monkeypatch.setattr("vpn_cookie.fido.Fido2Server", FakeServer)

    config = register_credential(AppConfig(), require_user_verification=False)

    assert FakeServer.last_instance.register_begin_kwargs["user_verification"] == "discouraged"
    assert client.request["extensions"] == {"hmacCreateSecret": True}
    assert config.fido.credentials[0].user_verification == "discouraged"


class FakeDevice:
    pass


class FakeInfo:
    extensions = ["hmac-secret", "credProtect"]


class FakeFido2Client:
    instances = []

    def __init__(self, device, *, client_data_collector, user_interaction, extensions):
        self.device = device
        self.info = FakeInfo()
        self.extensions = extensions
        FakeFido2Client.instances.append(self)


def test_client_enables_hmac_secret_and_cred_protect_extensions(monkeypatch):
    FakeFido2Client.instances = []
    monkeypatch.setattr("vpn_cookie.fido._enumerate_devices", lambda: [FakeDevice()])
    monkeypatch.setattr("vpn_cookie.fido.Fido2Client", FakeFido2Client)

    client = _client(AppConfig())

    assert client is FakeFido2Client.instances[0]
    assert any(isinstance(extension, HmacSecretExtension) for extension in client.extensions)
    assert any(isinstance(extension, CredProtectExtension) for extension in client.extensions)


class FakeAssertion:
    client_extension_results = {"hmacGetSecret": {"output1": b"derived-secret"}}

    def get_response(self, index):
        return self


class FakeAssertionClient:
    def __init__(self) -> None:
        self.request = None

    def get_assertion(self, request):
        self.request = request
        return FakeAssertion()


def test_derive_secret_uses_configured_user_verification():
    credential = FidoCredentialConfig(
        credential_id=b64encode(b"credential-id"),
        hmac_salt=b64encode(b"0" * 32),
        user_verification="required",
    )
    client = FakeAssertionClient()

    secret = derive_secret_for_credential(AppConfig(), credential, client=client)

    assert secret == b"derived-secret"
    assert client.request["userVerification"] == "required"
