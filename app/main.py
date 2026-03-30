"""
JWKS Server - Project 2
Stores RSA private keys in a SQLite database.
Serves public keys as JWKS and issues signed JWTs.
All SQL queries use parameterized statements to prevent SQL injection.
"""

import sqlite3
import time
import base64
from contextlib import asynccontextmanager, closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import jwt

# The database file name (required by the grader)
DB_FILE = "totally_not_my_privateKeys.db"


def get_db():
    """Open the SQLite database and return a connection."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


def init_db(conn):
    """
    Create the keys table if it doesn't exist yet.
    Schema is defined by the project requirements.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()


def seed_keys(conn):
    """
    Generate two RSA key pairs and save them to the database:
    - one already expired (for testing the expired JWT path)
    - one valid for 1 hour (for normal JWT issuance)
    Keys are serialized to PKCS1 PEM format for storage as text.
    """
    now = int(time.time())

    for expiry in (now - 1, now + 3600):
        # Generate a 2048-bit RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Serialize to PEM so SQLite can store it as text
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Parameterized query prevents SQL injection
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, expiry),
        )

    conn.commit()


def int_to_base64url(n):
    """
    Convert a large integer (RSA modulus or exponent)
    to a base64url-encoded string, as required by the JWK spec.
    """
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_length, "big")
    ).rstrip(b"=").decode()


def private_key_to_jwk(kid, private_key):
    """
    Build a JWK (JSON Web Key) dict from a private key.
    Only the public components (n, e) are included — never the private key.
    """
    pub_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "alg": "RS256",
        "n": int_to_base64url(pub_numbers.n),
        "e": int_to_base64url(pub_numbers.e),
    }


def sign_jwt(kid, private_key, exp):
    """
    Create and sign a JWT using RS256.
    The kid is included in the JWT header so verifiers know which key to use.
    """
    now = int(time.time())
    payload = {
        "sub": "userABC",
        "iat": now,
        "exp": exp,
    }
    # Re-serialize the key to bytes for the jwt library
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": str(kid)})


def load_private_key(pem_str):
    """Deserialize a PEM string back into a private key object."""
    return serialization.load_pem_private_key(
        pem_str.encode("utf-8"), password=None
    )


@asynccontextmanager
async def lifespan(app):
    """Runs once when the server starts: initializes and seeds the database."""
    with closing(get_db()) as conn:
        init_db(conn)
        seed_keys(conn)
    yield


# Create the FastAPI app
app = FastAPI(lifespan=lifespan)


@app.get("/.well-known/jwks.json")
async def jwks():
    """
    Return all non-expired public keys in JWKS format.
    Expired keys are excluded via a parameterized SQL WHERE clause.
    """
    now = int(time.time())
    with closing(get_db()) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?", (now,)
        ).fetchall()

    keys = []
    for row in rows:
        private_key = load_private_key(row["key"])
        keys.append(private_key_to_jwk(row["kid"], private_key))

    return JSONResponse(content={"keys": keys})


@app.post("/auth")
async def auth(request: Request, expired: str = Query(default=None)):
    """
    Issue a signed JWT.
    - If ?expired is present: sign with the most recently expired key.
    - Otherwise: sign with a currently valid key.
    HTTP Basic Auth and JSON body are accepted but not validated (per spec).
    """
    now = int(time.time())
    with closing(get_db()) as conn:
        if expired is not None:
            # Fetch the most recently expired key
            row = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,),
            ).fetchone()
        else:
            # Fetch the soonest-expiring valid key
            row = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
                (now,),
            ).fetchone()

    if row is None:
        return JSONResponse(status_code=404, content={"detail": "No key found"})

    private_key = load_private_key(row["key"])
    token = sign_jwt(row["kid"], private_key, row["exp"])
    return JSONResponse(content={"token": token})


@app.get("/auth")
async def auth_get():
    """Return 405 Method Not Allowed for GET requests to /auth."""
    return JSONResponse(status_code=405, content={"detail": "Method Not Allowed"})
