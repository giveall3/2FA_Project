# app/security.py
# password hashing + jwt helpers (keep it simple, easy to swap)
# we prefer argon2 (better), but fall back to Werkzeug PBKDF2 if argon2 isn't installed

# try to import argon2; if not available, we define the fallback AND also define
# the names so IDE doesn't complain (PasswordHasher / VerifyMismatchError).
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _ph = PasswordHasher()

    # hash password with argon2
    def hash_pw(pw: str) -> str:
        return _ph.hash(pw)

    # verify password with argon2
    def verify_pw(hash_: str, pw: str) -> bool:
        try:
            return _ph.verify(hash_, pw)
        except VerifyMismatchError:
            return False

except ImportError:
    # define these so PyCharm doesn't whine about them missing in the except branch
    PasswordHasher = None  # type: ignore[assignment]
    class VerifyMismatchError(Exception):
        pass

    # fallback hasher (PBKDF2 via Werkzeug)
    from werkzeug.security import generate_password_hash, check_password_hash

    def hash_pw(pw: str) -> str:
        return generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)

    def verify_pw(hash_: str, pw: str) -> bool:
        return check_password_hash(hash_, pw)

import jwt, time
from flask import current_app

# make jwt token
def encode_jwt(payload: dict) -> str:
    secret = current_app.config["JWT_SECRET"]
    return jwt.encode(payload, secret, algorithm="HS256")

# read jwt token
def decode_jwt(token: str):
    secret = current_app.config["JWT_SECRET"]
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

# issue token for game (short-lived)
def issue_game_token(user_id: int, email: str) -> str:
    now = int(time.time())
    exp = now + int(current_app.config["JWT_EXP_SECONDS"])  # how long the token lives
    payload = {"user_id": int(user_id), "email": email, "exp": exp}
    return encode_jwt(payload)
