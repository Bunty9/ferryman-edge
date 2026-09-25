#!/usr/bin/env bash
# mint-jwt.sh — mint an RS256 JWT signed by the JWT issuer private key.
#
# Usage:  scripts/mint-jwt.sh [sub] [ttl_secs] [scope]
# Defaults: sub=tenant-a, ttl_secs=3600, scope=read
#
# Outputs the complete JWT token to stdout.
# Env override: JWT_PRIV_KEY (path to private key; default: certs/jwt-priv.pem)
# Optional claims: JWT_ISS, JWT_AUD (match [jwt] issuer / audience in config.toml)

set -euo pipefail

# Parse arguments with defaults
SUB="${1:-tenant-a}"
TTL_SECS="${2:-3600}"
SCOPE="${3:-read}"

# Resolve certs directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="${PROJ_ROOT}/certs"
JWT_PRIV_KEY="${JWT_PRIV_KEY:-${CERTS_DIR}/jwt-priv.pem}"

# Verify private key exists
if [ ! -f "$JWT_PRIV_KEY" ]; then
    echo "ERROR: JWT private key not found at $JWT_PRIV_KEY" >&2
    echo "Run scripts/gen-test-certs.sh first to generate test certificates" >&2
    exit 1
fi

# Helper: base64url encode (standard base64 → remove padding → replace + with - and / with _)
base64url_encode() {
    base64 -w 0 | tr '+/' '-_' | tr -d '='
}

# Calculate expiry as current unix time + TTL
NOW=$(date +%s)
EXP=$((NOW + TTL_SECS))

# Build header
HEADER='{"alg":"RS256","typ":"JWT"}'
HEADER_B64=$(echo -n "$HEADER" | base64url_encode)

# Build payload
EXTRA=""
[ -n "${JWT_ISS:-}" ] && EXTRA="${EXTRA},\"iss\":\"${JWT_ISS}\""
[ -n "${JWT_AUD:-}" ] && EXTRA="${EXTRA},\"aud\":\"${JWT_AUD}\""
PAYLOAD="{\"sub\":\"${SUB}\",\"exp\":${EXP},\"scope\":\"${SCOPE}\"${EXTRA}}"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64url_encode)

# Build message to sign
MESSAGE="${HEADER_B64}.${PAYLOAD_B64}"

# Sign the message with private key
# openssl dgst -sha256 -sign outputs binary; base64url encode it
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -sign "$JWT_PRIV_KEY" | base64url_encode)

# Output the complete JWT
echo "${MESSAGE}.${SIGNATURE}"
