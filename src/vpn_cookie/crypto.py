from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vpn_cookie.config import PasswordConfig, b64decode, b64encode

HKDF_INFO = b"vpn-cookie password encryption v1"
NONCE_LEN = 12


def _aes_key(fido_secret: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=HKDF_INFO).derive(fido_secret)


def encrypt_password(password: str, fido_secret: bytes) -> PasswordConfig:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_aes_key(fido_secret)).encrypt(nonce, password.encode("utf-8"), None)
    return PasswordConfig(nonce=b64encode(nonce), ciphertext=b64encode(ciphertext))


def decrypt_password(config: PasswordConfig, fido_secret: bytes) -> str:
    if not config.nonce or not config.ciphertext:
        raise ValueError("No encrypted password is configured. Run `vpn-cookie password set` first.")
    plaintext = AESGCM(_aes_key(fido_secret)).decrypt(
        b64decode(config.nonce),
        b64decode(config.ciphertext),
        None,
    )
    return plaintext.decode("utf-8")
