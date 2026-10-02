#!/usr/bin/env bash
# Honeypot PKI helper — generate CA + orchestrator server cert + per-node client certs
# Usage: ./gen_pki.sh node-eu-west-1 node-us-east-1 node-ap-southeast-1 ...
#
# Output:
#   certs/ca.{key,crt}
#   certs/server.{key,crt}      (for Nginx TLS)
#   certs/<node-id>.{key,crt}   (deploy to each honeypot node)

set -euo pipefail

CERTS_DIR="certs"
DAYS_CA=3650     # 10 years
DAYS_CERT=825    # ~2.5 years (Apple/browser policies)
KEY_BITS=4096
DIGEST="-sha256"

ORCHESTRATOR_CN="${ORCHESTRATOR_CN:-orchestrator.example.com}"

mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

# ─── 1. CA ────────────────────────────────────────────────────────────────────
if [[ ! -f ca.key ]]; then
    echo "[PKI] Generating CA key and self-signed certificate…"
    openssl genrsa -out ca.key ${KEY_BITS}
    openssl req -new -x509 ${DIGEST} \
        -key ca.key \
        -out ca.crt \
        -days ${DAYS_CA} \
        -subj "/CN=Honeypot-CA/O=Research/C=DE"
    echo "[PKI] CA created: ca.crt"
else
    echo "[PKI] CA already exists — skipping."
fi

# ─── 2. Orchestrator server certificate ───────────────────────────────────────
if [[ ! -f server.key ]]; then
    echo "[PKI] Generating orchestrator server certificate (CN=${ORCHESTRATOR_CN})…"
    openssl genrsa -out server.key ${KEY_BITS}
    openssl req -new ${DIGEST} \
        -key server.key \
        -out server.csr \
        -subj "/CN=${ORCHESTRATOR_CN}/O=Research/C=DE"

    # SAN extension
    cat > server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${ORCHESTRATOR_CN},DNS:localhost,IP:127.0.0.1
EOF

    openssl x509 -req ${DIGEST} \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out server.crt \
        -days ${DAYS_CERT} \
        -extfile server.ext
    rm server.csr server.ext
    echo "[PKI] Server cert: server.crt"
fi

# ─── 3. Per-node client certificates ─────────────────────────────────────────
for NODE_ID in "$@"; do
    if [[ -f "${NODE_ID}.key" ]]; then
        echo "[PKI] ${NODE_ID}: already exists — skipping."
        continue
    fi

    echo "[PKI] Generating client certificate for node: ${NODE_ID}…"
    openssl genrsa -out "${NODE_ID}.key" ${KEY_BITS}
    openssl req -new ${DIGEST} \
        -key "${NODE_ID}.key" \
        -out "${NODE_ID}.csr" \
        -subj "/CN=${NODE_ID}/O=Research/C=DE"

    cat > "${NODE_ID}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

    openssl x509 -req ${DIGEST} \
        -in "${NODE_ID}.csr" \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out "${NODE_ID}.crt" \
        -days ${DAYS_CERT} \
        -extfile "${NODE_ID}.ext"
    rm "${NODE_ID}.csr" "${NODE_ID}.ext"
    echo "[PKI] Node cert: ${CERTS_DIR}/${NODE_ID}.{key,crt}"
done

echo ""
echo "[PKI] Done. Files in ${CERTS_DIR}/:"
ls -1 ../"${CERTS_DIR}"/ 2>/dev/null || ls -1 .
echo ""
echo "[PKI] Deploy to each node:"
echo "   scp certs/<node-id>.{key,crt} certs/ca.crt honeypot@<node-ip>:~/honeypots/certs/"
echo ""
echo "[PKI] Deploy to Nginx:"
echo "   cp certs/server.{key,crt} /etc/nginx/ssl/"
echo "   cp certs/ca.crt /etc/nginx/ssl/ca.crt   # for ssl_client_certificate"
