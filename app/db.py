# app/db.py
import sqlite3, os
from flask import g

# make sure folder for DB exists
def _ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

# open DB connection (one per request)
def get_db(path: str):
    db = getattr(g, "_db", None)
    if db is None:
        _ensure_dir(path)
        # connect to sqlite file
        db = g._db = sqlite3.connect(path, check_same_thread=False)
        db.row_factory = sqlite3.Row  # rows as dict-like
    return db

# init DB when app starts
def init_db(app):
    # bind DB for each request
    @app.before_request
    def _bind():
        g.db = get_db(app.config["DB_PATH"])

    # close DB after app context ends
    @app.teardown_appcontext
    def _close(_exc):
        db = getattr(g, "_db", None)
        if db:
            db.close()

    # create tables if not exist
    with app.app_context():
        conn = get_db(app.config["DB_PATH"])  # renamed from 'db' to avoid shadowing
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          totp_secret TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_codes(
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL,
          code_hash TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        -- NEW: audit table for recovery code usage (history)
        CREATE TABLE IF NOT EXISTS recovery_code_audit(
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL,
          recovery_code_id INTEGER,
          used_at TEXT NOT NULL,
          ip TEXT,
          user_agent TEXT,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
        )
        conn.commit()
