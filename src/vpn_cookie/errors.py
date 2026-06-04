from __future__ import annotations


class VpnCookieError(Exception):
    """Base class for expected user-facing failures."""


class BrowserError(VpnCookieError):
    """Browser login or cookie extraction failed."""


class FidoError(VpnCookieError):
    """FIDO credential or hmac-secret handling failed."""


class OpenConnectError(VpnCookieError):
    """OpenConnect failed to start or exited unsuccessfully."""
