from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir

APP_NAME = "vpn-cookie"
DEFAULT_VPN_URL = "https://vpn.uni-luebeck.de"
DEFAULT_COOKIE_NAME = "webvpn"


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass
class FidoConfig:
    rp_id: str = "vpn-cookie.local"
    rp_name: str = "VPN Cookie"
    origin: str = "https://vpn-cookie.local"
    credential_id: str | None = None
    hmac_salt: str | None = None
    credentials: list[FidoCredentialConfig] = field(default_factory=list)


@dataclass
class PasswordConfig:
    nonce: str | None = None
    ciphertext: str | None = None


@dataclass
class FidoCredentialConfig:
    credential_id: str
    hmac_salt: str
    user_verification: str = "required"
    password: PasswordConfig = field(default_factory=PasswordConfig)


@dataclass
class TpmCredentialConfig:
    public: str
    private: str
    hmac_salt: str
    mechanism: str = "hmac-tools"
    primary_template_version: int = 1
    requires_pin: bool = True
    password: PasswordConfig = field(default_factory=PasswordConfig)


@dataclass
class TpmConfig:
    device: str = "/dev/tpmrm0"
    credentials: list[TpmCredentialConfig] = field(default_factory=list)


@dataclass
class BrowserConfig:
    headless: bool = True
    width: int = 900
    height: int = 720
    executable_path: str | None = None
    useragent: str | None = "AnyConnect"


@dataclass
class RoutingConfig:
    mode: str = "server"
    include: list[str] = field(default_factory=list)
    vpn_slice: str = "vpn-slice"
    vpn_slice_args: list[str] = field(default_factory=list)
    disable_ipv6: bool = True


@dataclass
class OpenConnectConfig:
    useragent: str | None = "AnyConnect"


@dataclass
class AppConfig:
    vpn_url: str = DEFAULT_VPN_URL
    username: str = ""
    cookie_name: str = DEFAULT_COOKIE_NAME
    fido: FidoConfig = field(default_factory=FidoConfig)
    tpm: TpmConfig = field(default_factory=TpmConfig)
    password: PasswordConfig = field(default_factory=PasswordConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    openconnect: OpenConnectConfig = field(default_factory=OpenConnectConfig)


def default_config_path() -> Path:
    return Path(user_config_dir(APP_NAME)) / "config.json"


def load_config(path: Path | None = None) -> AppConfig:
    path = path or default_config_path()
    if not path.exists():
        return AppConfig()
    data = json.loads(path.read_text(encoding="utf-8"))
    return config_from_dict(data)


def save_config(config: AppConfig, path: Path | None = None) -> Path:
    path = path or default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def config_from_dict(data: dict[str, Any]) -> AppConfig:
    password = PasswordConfig(**data.get("password", {}))
    fido_data = data.get("fido", {})
    credential_entries = []
    for entry in fido_data.get("credentials", []):
        entry_data = dict(entry)
        entry_password = PasswordConfig(**entry_data.get("password", {}))
        credential_entries.append(
            FidoCredentialConfig(
                credential_id=entry_data["credential_id"],
                hmac_salt=entry_data["hmac_salt"],
                user_verification=entry_data.get("user_verification", "required"),
                password=entry_password,
            )
        )
    if not credential_entries and fido_data.get("credential_id") and fido_data.get("hmac_salt"):
        credential_entries.append(
            FidoCredentialConfig(
                credential_id=fido_data["credential_id"],
                hmac_salt=fido_data["hmac_salt"],
                user_verification=fido_data.get("user_verification", "required"),
                password=password,
            )
        )
    fido = FidoConfig(
        rp_id=fido_data.get("rp_id", "vpn-cookie.local"),
        rp_name=fido_data.get("rp_name", "VPN Cookie"),
        origin=fido_data.get("origin", "https://vpn-cookie.local"),
        credentials=credential_entries,
    )
    tpm_data = data.get("tpm", {})
    tpm_credentials = []
    for entry in tpm_data.get("credentials", []):
        entry_data = dict(entry)
        entry_password = PasswordConfig(**entry_data.get("password", {}))
        tpm_credentials.append(
            TpmCredentialConfig(
                public=entry_data["public"],
                private=entry_data["private"],
                hmac_salt=entry_data["hmac_salt"],
                mechanism=entry_data.get("mechanism", "hmac-tools"),
                primary_template_version=entry_data.get("primary_template_version", 1),
                requires_pin=entry_data.get("requires_pin", True),
                password=entry_password,
            )
        )
    tpm = TpmConfig(
        device=tpm_data.get("device", "/dev/tpmrm0"),
        credentials=tpm_credentials,
    )
    browser = BrowserConfig(**data.get("browser", {}))
    routing = RoutingConfig(**data.get("routing", {}))
    openconnect = OpenConnectConfig(**data.get("openconnect", {}))
    fields = {
        "vpn_url": data.get("vpn_url", DEFAULT_VPN_URL),
        "username": data.get("username", ""),
        "cookie_name": data.get("cookie_name", DEFAULT_COOKIE_NAME),
        "fido": fido,
        "tpm": tpm,
        "password": password,
        "browser": browser,
        "routing": routing,
        "openconnect": openconnect,
    }
    return AppConfig(**fields)
