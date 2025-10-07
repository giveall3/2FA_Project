# app/models.py
from flask import g
from datetime import datetime, timezone
import sqlite3

# find user by email
def find_user_by_email(email: str):
    cur = g.db.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    return cur.fetchone()

# find user by id
def find_user_by_id(user_id: int):
    cur = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

# create new user
def create_user(email: str, password_hash: str):
    ts = datetime.now(timezone.utc).isoformat()
    try:
        g.db.execute(
            "INSERT INTO users(email, password_hash, created_at) VALUES(?,?,?)",
            (email.lower(), password_hash, ts),
        )
    except (sqlite3.OperationalError, sqlite3.ProgrammingError):
        # if DB is old and has no created_at column
        g.db.execute(
            "INSERT INTO users(email, password_hash) VALUES(?,?)",
            (email.lower(), password_hash),
        )
    g.db.commit()

# set or remove 2FA secret
def set_totp_secret(user_id: int, secret_or_encrypted: str | None):
    g.db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret_or_encrypted, user_id))
    g.db.commit()

# change password
def replace_password(user_id: int, new_hash: str):
    g.db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
    g.db.commit()

# delete all recovery codes
def delete_recovery_codes(user_id: int):
    g.db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
    g.db.commit()

# insert new recovery codes
def insert_recovery_codes(user_id: int, code_hashes):
    g.db.executemany(
        "INSERT INTO recovery_codes(user_id, code_hash) VALUES(?, ?)",
        [(user_id, h) for h in code_hashes],
    )
    g.db.commit()

# count recovery codes
def count_recovery_codes(user_id: int) -> int:
    cur = g.db.execute("SELECT COUNT(*) AS c FROM recovery_codes WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    return int(row["c"]) if row else 0

# list all recovery codes
def list_recovery_codes(user_id: int):
    cur = g.db.execute("SELECT id, code_hash FROM recovery_codes WHERE user_id=?", (user_id,))
    return cur.fetchall()

# delete one recovery code after use
def consume_recovery_code(user_id: int, code_id: int):
    g.db.execute("DELETE FROM recovery_codes WHERE user_id=? AND id=?", (user_id, code_id))
    g.db.commit()

# NEW: write an audit record when a recovery code is used
def log_recovery_code_use(user_id: int, code_id: int | None, ip: str | None, user_agent: str | None):
    ts = datetime.now(timezone.utc).isoformat()
    g.db.execute(
        "INSERT INTO recovery_code_audit(user_id, recovery_code_id, used_at, ip, user_agent) VALUES(?,?,?,?,?)",
        (user_id, code_id, ts, ip, (user_agent or "")[:255]),
    )
    g.db.commit()

# OPTIONAL: list last N audit entries for a user (for Account page history)
def list_recovery_code_audit(user_id: int, limit: int = 10):
    cur = g.db.execute(
        "SELECT used_at, ip, user_agent FROM recovery_code_audit WHERE user_id=? ORDER BY used_at DESC LIMIT ?",
        (user_id, limit),
    )
    return cur.fetchall()
