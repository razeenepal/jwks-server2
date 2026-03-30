"""
Tests for JWKS Server - Project 2
Run with: pytest --cov=app --cov-report=term-missing
"""

import sqlite3
import time
import pytest
from fastapi.testclient import TestClient
import app.main as main_module


# ------------------------------------------------------------------ #
# Fixtures - these run before each test to set up a clean environment
# ------------------------------------------------------------------ #

@pytest.fixture(autouse=True)
def use_temp_db(monkeypatch, tmp_path):
    """Use a temporary database for every test so they don't interfere."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "DB_FILE", db_path)
    yield db_path


@pytest.fixture()
def client(use_temp_db):
    """Create a test client that runs the full server startup."""
    with TestClient(main_module.app) as c:
        yield c


# ------------------------------------------------------------------ #
# Database tests
# ------------------------------------------------------------------ #

def test_init_db_creates_table(use_temp_db):
    conn = sqlite3.connect(use_temp_db)
    main_module.init_db(conn)
    result = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
    ).fetchone()
    assert result is not None
    conn.close()


def test_seed_keys_inserts_two_rows(use_temp_db):
    conn = sqlite3.connect(use_temp_db)
    conn.row_factory = sqlite3.Row
    main_module.init_db(conn)
    main_module.seed_keys(conn)
    count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    assert count == 2
    conn.close()


def test_seed_keys_has_one_expired_one_valid(use_temp_db):
    conn = sqlite3.connect(use_temp_db)
    conn.row_factory = sqlite3.Row
    main_module.init_db(conn)
    main_module.seed_keys(conn)
    now = int(time.time())
    expired = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)
    ).fetchone()[0]
    valid = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)
    ).fetchone()[0]
    assert expired >= 1
    assert valid >= 1
    conn.close()


def test_get_db_returns_connection(use_temp_db):
    conn = main_module.get_db()
    assert isinstance(conn, sqlite3.Connection)
    conn.close()


# ------------------------------------------------------------------ #
# JWKS endpoint tests
# ------------------------------------------------------------------ #

def test_jwks_returns_200(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200


def test_jwks_has_keys_array(client):
    resp = client.get("/.well-known/jwks.json")
    assert "keys" in resp.json()


def test_jwks_only_has_valid_keys(client):
    resp = client.get("/.well-known/jwks.json")
    assert len(resp.json()["keys"]) >= 1


def test_jwks_key_has_correct_fields(client):
    resp = client.get("/.well-known/jwks.json")
    for key in resp.json()["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key


# ------------------------------------------------------------------ #
# /auth endpoint tests
# ------------------------------------------------------------------ #

def test_auth_post_returns_200(client):
    resp = client.post("/auth")
    assert resp.status_code == 200


def test_auth_post_returns_token(client):
    resp = client.post("/auth")
    assert "token" in resp.json()


def test_auth_valid_token_not_expired(client):
    import jwt as pyjwt
    token = client.post("/auth").json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] > int(time.time())


def test_auth_expired_param_returns_200(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200


def test_auth_expired_token_is_expired(client):
    import jwt as pyjwt
    token = client.post("/auth?expired=true").json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert payload["exp"] < int(time.time())


def test_auth_token_has_kid_in_header(client):
    import jwt as pyjwt
    token = client.post("/auth").json()["token"]
    header = pyjwt.get_unverified_header(token)
    assert "kid" in header


def test_auth_expired_kid_not_in_jwks(client):
    import jwt as pyjwt
    token = client.post("/auth?expired=true").json()["token"]
    expired_kid = pyjwt.get_unverified_header(token)["kid"]
    jwks_kids = [k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]]
    assert expired_kid not in jwks_kids


def test_auth_get_returns_405(client):
    resp = client.get("/auth")
    assert resp.status_code == 405


def test_auth_accepts_basic_auth(client):
    resp = client.post("/auth", auth=("userABC", "password123"))
    assert resp.status_code == 200


def test_auth_accepts_json_body(client):
    resp = client.post("/auth", json={"username": "userABC", "password": "password123"})
    assert resp.status_code == 200
