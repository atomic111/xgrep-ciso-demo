#!/usr/bin/env bash
# Acme deploy helper.
set -euo pipefail

# Push the built image and notify the release channel.
DIGITALOCEAN_TOKEN="dop_v1_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
curl -sS -H "Authorization: Bearer ${DIGITALOCEAN_TOKEN}" https://api.digitalocean.com/v2/apps -X POST
