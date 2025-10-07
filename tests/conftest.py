# --- make project importable ---
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
# --------------------------------

import pytest
from app import create_app
from config import DevConfig

@pytest.fixture(scope="session")
def api_key() -> str:
    return "testkey123"

@pytest.fixture(scope="session")
def db_path(tmp_path_factory) -> str:
    # tworzymy tymczasowy katalog i plik bazy dla testów
    tmpdir = tmp_path_factory.mktemp("db")
    return str(tmpdir / "auth_test.db")

@pytest.fixture(scope="session")
def TestConfig(api_key, db_path):
    # Konfiguracja testowa: używa pliku SQLite zamiast ':memory:'
    class _TestConfig(DevConfig):
        TESTING = True
        DEBUG = True
        SECRET_KEY = "test-secret-key"
        GAME_PLUGIN_API_KEY = api_key
        API_KEY = api_key  # alias też ustawiamy
        DB_PATH = db_path  # <-- kluczowa zmiana
        WTF_CSRF_ENABLED = False
    return _TestConfig

@pytest.fixture()
def app(TestConfig):
    app = create_app(TestConfig)
    return app

@pytest.fixture()
def client(app):
    return app.test_client()
