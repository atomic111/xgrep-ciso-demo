#!/usr/bin/env bash
# Acme deploy helper.
set -euo pipefail

# Push the built image and notify the release channel.
# Token now comes from the environment (see CI secrets), not hardcoded.
: "${DIGITALOCEAN_TOKEN:?set DIGITALOCEAN_TOKEN in the environment}"
curl -sS -H "Authorization: Bearer ${DIGITALOCEAN_TOKEN}" https://api.digitalocean.com/v2/apps -X POST
