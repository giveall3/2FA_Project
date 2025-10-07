# tests/test_contract.py

import sqlite3
from app.security import decode_jwt


def test_verify_token_without_api_key_returns_403(client):
    """Brak X-Api-Key powinien kończyć się 403 (forbidden)."""
    r = client.post("/api/verify-token", json={"token": "x"})
    assert r.status_code == 403
    data = r.get_json()
    assert data and data.get("ok") is False


def test_verify_token_with_key_invalid_token_returns_400(client, api_key):
    """Z kluczem, ale zły token -> 400/422 (invalid token)."""
    r = client.post(
        "/api/verify-token",
        headers={"X-Api-Key": api_key},
        json={"token": "definitely-not-a-valid-token"},
    )
    assert r.status_code in (400, 422)
    data = r.get_json()
    assert data and data.get("ok") is False


def test_game_page_requires_login_redirects(client):
    """Wejście na /game bez sesji powinno przekierować do logowania (302)."""
    r = client.get("/game", follow_redirects=False)
    assert r.status_code in (302, 303)


def _create_user_and_get_id(app, client, email="player@example.com", password="Password123!"):
    """
    Tworzy usera w testowej bazie i zwraca jego ID.
    Kroki:
      1) próbuje helperów z app.models/app.db
      2) próbuje /register (może działa u Ciebie)
      3) W OSTATECZNOŚCI: bezpośredni INSERT do SQLite z poprawnym password_hash
    """
    import os, sqlite3
    from flask import current_app

    with app.app_context():
        created_id = None

        # 1) helpery (jeśli istnieją)
        try:
            try:
                from app.models import create_user, find_user_by_email
            except Exception:
                from app.db import create_user, find_user_by_email  # type: ignore

            created = create_user(email, password)
            if isinstance(created, dict):
                created_id = created.get("id") or created.get("user_id")
            elif isinstance(created, int):
                created_id = created
            else:
                u = find_user_by_email(email)
                if isinstance(u, dict):
                    created_id = u.get("id") or u.get("user_id")
        except Exception:
            pass

        # 2) /register (może od razu doda usera)
        if not created_id:
            client.post(
                "/register",
                data={"email": email, "password": password, "password2": password},
                follow_redirects=False,
            )
            # sprawdźmy, czy user się pojawił
            try:
                from app.db import find_user_by_email  # type: ignore
                u = find_user_by_email(email)
                if isinstance(u, dict):
                    created_id = u.get("id") or u.get("user_id")
            except Exception:
                pass

        # 3) BEZPOŚREDNIO: Insert do SQLite (najbardziej niezależne)
        if not created_id:
            db_path = current_app.config.get("DB_PATH")
            assert db_path and os.path.exists(db_path), f"DB file not found: {db_path}"

            # zrób hash hasła jak w aplikacji (argon2 lub werkzeug)
            try:
                from app.security import hash_pw  # jeśli masz helper
                password_hash = hash_pw(password)
            except Exception:
                # awaryjnie: spróbuj argon2, a jeśli brak, użyj werkzeug
                try:
                    from argon2 import PasswordHasher
                    password_hash = PasswordHasher().hash(password)
                except Exception:
                    from werkzeug.security import generate_password_hash
                    password_hash = generate_password_hash(password)

            conn = sqlite3.connect(db_path)
            try:
                cur = conn.cursor()
                # kolumny w Twojej bazie: id (PK), email, password_hash, totp_secret, created_at
                cur.execute(
                    "INSERT INTO users (email, password_hash, totp_secret, created_at) "
                    "VALUES (?, ?, NULL, CURRENT_TIMESTAMP)",
                    (email, password_hash),
                )
                conn.commit()
                created_id = cur.lastrowid
            finally:
                conn.close()

        assert created_id, "User was not created in test DB"
        return created_id


def test_issue_game_token_when_logged_in(client, app):
    """Zalogowany użytkownik może wygenerować token do gry."""
    user_id = _create_user_and_get_id(app, client)

    # ustaw sesję jako zalogowaną
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["email"] = "player@example.com"

    # wołamy endpoint
    r = client.post("/account/game-token")
    assert r.status_code == 200
    data = r.get_json()
    assert data and data.get("ok") is True and "token" in data

    # sanity-check JWT (needs app context)
    from app.security import decode_jwt
    with app.app_context():
        claims = decode_jwt(data["token"])
    assert claims["user_id"] == user_id
    assert claims["email"] == "player@example.com"
    assert "exp" in claims


def test_logout_endpoint_exists(client):
    """Wylogowanie istnieje i zwraca sensowny status."""
    r = client.post("/api/session/logout")
    assert r.status_code in (200, 204, 302)
