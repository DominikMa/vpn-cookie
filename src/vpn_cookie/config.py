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
    password: PasswordConfig = field(default_factory=PasswordConfig)


@dataclass
class BrowserConfig:
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


@dataclass
class OpenConnectConfig:
    useragent: str | None = "AnyConnect"


@dataclass
class AppConfig:
    vpn_url: str = DEFAULT_VPN_URL
    username: str = ""
    cookie_name: str = DEFAULT_COOKIE_NAME
    fido: FidoConfig = field(default_factory=FidoConfig)
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
                password=entry_password,
            )
        )
    if not credential_entries and fido_data.get("credential_id") and fido_data.get("hmac_salt"):
        credential_entries.append(
            FidoCredentialConfig(
                credential_id=fido_data["credential_id"],
                hmac_salt=fido_data["hmac_salt"],
                password=password,
            )
        )
    fido = FidoConfig(
        rp_id=fido_data.get("rp_id", "vpn-cookie.local"),
        rp_name=fido_data.get("rp_name", "VPN Cookie"),
        origin=fido_data.get("origin", "https://vpn-cookie.local"),
        credentials=credential_entries,
    )
    browser = BrowserConfig(**data.get("browser", {}))
    routing = RoutingConfig(**data.get("routing", {}))
    openconnect = OpenConnectConfig(**data.get("openconnect", {}))
    fields = {
        "vpn_url": data.get("vpn_url", DEFAULT_VPN_URL),
        "username": data.get("username", ""),
        "cookie_name": data.get("cookie_name", DEFAULT_COOKIE_NAME),
        "fido": fido,
        "password": password,
        "browser": browser,
        "routing": routing,
        "openconnect": openconnect,
    }
    return AppConfig(**fields)
