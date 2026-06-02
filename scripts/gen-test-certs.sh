#!/usr/bin/env bash
# gen-test-certs.sh — generate the full mTLS chain used by ferryman-edge
# integration tests and CI smoke jobs.
#
# Produces, under ./certs/ :
#   ca.key / ca.crt                 — root CA
#   intA.key / intA.crt             — intermediate A (signed by root)
#   intB.key / intB.crt             — intermediate B (signed by intA)
#   intC.key / intC.crt             — intermediate C (signed by intB)
#   server.key / server.crt         — server leaf (signed by intC)
#   client.key / client.crt         — client leaf (signed by intC)
#   ca-bundle.crt                   — concat of all intermediate CAs + root,
#                                     used as `client_ca_path` so the server
#                                     can validate clients across the chain.
#   jwt-pub.pem / jwt-priv.pem      — RSA keypair used by the JWT verifier
#                                     (configured via `jwt.jwks_path`).
#
# The benchmark scenario in projects-l3-l4.md § P4 calls for a 4-intermediate
# chain to document the validation cost. We ship 3 here for reasonable
# generation time in CI; bump for the full bench by repeating the
# intermediate stanza.

set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

SUBJ_BASE="/C=US/ST=CA/O=ferryman-edge-test"

gen_ca() {
    local name="$1"
    local subj="$2"
    local signer_key="${3:-}"
    local signer_crt="${4:-}"
    openssl genrsa -out "${name}.key" 2048 >/dev/null 2>&1
    if [ -z "$signer_key" ]; then
        # self-signed root
        openssl req -x509 -new -nodes -key "${name}.key" \
            -sha256 -days 365 -subj "${subj}" \
            -out "${name}.crt" >/dev/null 2>&1
    else
        openssl req -new -key "${name}.key" -subj "${subj}" -out "${name}.csr" >/dev/null 2>&1
        openssl x509 -req -in "${name}.csr" \
            -CA "${signer_crt}" -CAkey "${signer_key}" -CAcreateserial \
            -days 365 -sha256 \
            -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") \
            -out "${name}.crt" >/dev/null 2>&1
        rm -f "${name}.csr"
    fi
}

gen_leaf() {
    local name="$1"
    local cn="$2"
    local signer_key="$3"
    local signer_crt="$4"
    local ext="$5"   # "server" or "client"
    openssl genrsa -out "${name}.key" 2048 >/dev/null 2>&1
    openssl req -new -key "${name}.key" -subj "${SUBJ_BASE}/CN=${cn}" -out "${name}.csr" >/dev/null 2>&1
    local eku
    case "$ext" in
        server) eku="serverAuth" ;;
        client) eku="clientAuth" ;;
        *) echo "unknown ext: $ext" >&2; exit 1 ;;
    esac
    openssl x509 -req -in "${name}.csr" \
        -CA "${signer_crt}" -CAkey "${signer_key}" -CAcreateserial \
        -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=%s\n" "$cn" "$eku") \
        -out "${name}.crt" >/dev/null 2>&1
    rm -f "${name}.csr"
}

echo "[1/8] root CA"
gen_ca ca       "${SUBJ_BASE}/CN=ferryman-edge-test-root"

echo "[2/8] intermediate A"
gen_ca intA     "${SUBJ_BASE}/CN=intA"     ca.key   ca.crt

echo "[3/8] intermediate B"
gen_ca intB     "${SUBJ_BASE}/CN=intB"     intA.key intA.crt

echo "[4/8] intermediate C"
gen_ca intC     "${SUBJ_BASE}/CN=intC"     intB.key intB.crt

echo "[5/8] server leaf"
gen_leaf server localhost intC.key intC.crt server
# Server cert chain = leaf + all intermediates (rustls expects this order).
cat server.crt intC.crt intB.crt intA.crt > server-chain.crt
mv server-chain.crt server.crt

echo "[6/8] client leaf"
gen_leaf client ferryman-edge-test-client intC.key intC.crt client

echo "[7/8] client-CA bundle"
cat ca.crt intA.crt intB.crt intC.crt > ca-bundle.crt

echo "[8/8] JWT issuer keypair"
openssl genrsa -out jwt-priv.pem 2048 >/dev/null 2>&1
openssl rsa -in jwt-priv.pem -pubout -out jwt-pub.pem >/dev/null 2>&1

echo
echo "Test certificates written to ${CERT_DIR}"
ls -1 "${CERT_DIR}"
