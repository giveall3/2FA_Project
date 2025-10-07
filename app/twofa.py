# app/twofa.py
# all things 2FA (TOTP secrets, QR codes, encryption helpers)
import os, io, base64
import pyotp, qrcode
from flask import current_app
from cryptography.fernet import Fernet, InvalidToken  # InvalidToken used for decrypt errors

# get fernet key for encrypting 2FA secret (prefer app config, fallback to env var)
def _get_fernet():
    # try to read key from Flask config; if no app context, just ignore
    try:
        cfg_key = current_app.config.get("FERNET_KEY")
    except RuntimeError:
        cfg_key = None

    # if no key in config, try environment
    env_key = os.getenv("FERNET_KEY") if not cfg_key else None

    # final chosen key
    key = cfg_key or env_key
    if not key:
        return None

    # normalize to bytes and build Fernet
    key_bytes = key.encode() if isinstance(key, str) else key
    try:
        return Fernet(key_bytes)
    except (ValueError, TypeError):
        # key has wrong format -> no encryption (we’ll treat secrets as plain)
        return None

# encrypt secret (if fernet available), otherwise just return plain
def encrypt_secret(plain: str) -> str:
    f = _get_fernet()
    if not f:
        return plain
    return f.encrypt(plain.encode()).decode()

# decrypt secret (if encrypted); if something's off, assume it's already plain
def decrypt_secret(cipher_or_plain: str) -> str:
    f = _get_fernet()
    if not f:
        return cipher_or_plain
    try:
        return f.decrypt(cipher_or_plain.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        # not encrypted / wrong key / wrong format -> just return input
        return cipher_or_plain

# make new totp secret + uri for authenticator app
def new_totp_secret(issuer: str, email: str):
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    return secret, uri

# make qr code for authenticator app (PNG if Pillow available, else SVG)
def qr_data_url(uri: str) -> str:
    try:
        img = qrcode.make(uri)  # uses PIL if available
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except (ImportError, OSError, AttributeError, ValueError):
        # Pillow not installed or saving failed -> fallback to SVG
        from qrcode.image.svg import SvgImage
        buf = io.BytesIO()
        qrcode.make(uri, image_factory=SvgImage).save(buf)
        return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()

# check totp code
def verify_totp(secret_encrypted_or_plain: str, token: str) -> bool:
    secret = decrypt_secret(secret_encrypted_or_plain or "")
    if not secret:
        return False
    try:
        return pyotp.TOTP(secret).verify(token, valid_window=1)
    except (TypeError, ValueError):
        return False

# get current totp code (for debug / test)
def current_totp(secret_encrypted_or_plain: str) -> str:
    secret = decrypt_secret(secret_encrypted_or_plain or "")
    return pyotp.TOTP(secret).now() if secret else ""
