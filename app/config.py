"""Application configuration.

Demonstrates hardcoded cloud credentials sitting in source — the kind of thing
xgrep's secret detection catches even when it is not in a .env file.
"""

PORT = 8080

# SINK: hardcoded cloud credentials in source control.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_URL = "postgres://acme_app:SuperSecretDbPass123@db.internal:5432/acme"
