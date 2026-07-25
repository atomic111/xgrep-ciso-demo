"""Authentication helpers.

Demonstrates weak password hashing, a hardcoded signing secret, and a JWT
verification that accepts the 'none' algorithm.
"""
import hashlib

import jwt

# SINK: hardcoded credential / signing secret committed to source control.
JWT_SIGNING_SECRET = "s3cr3t-hs256-key-do-not-ship"


def hash_password(password):
    # SINK: MD5 is cryptographically broken for password storage.
    return hashlib.md5(password.encode()).hexdigest()


def issue_token(username, password):
    digest = hash_password(password)
    return jwt.encode({"sub": username, "pw": digest}, JWT_SIGNING_SECRET, algorithm="HS256")


def verify_token(token):
    # SINK: verify_signature disabled + 'none' allowed -> forged tokens accepted.
    return jwt.decode(
        token,
        JWT_SIGNING_SECRET,
        algorithms=["HS256", "none"],
        options={"verify_signature": False},
    )
