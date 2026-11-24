#!/usr/bin/env bash
# ==============================================================================
#  generate_certs.sh — Generate mTLS Certificates for AutoSOC
#  Creates:
#    1. Root CA (ca.key, ca.crt)
#    2. Server Certificate with SAN (server.key, server.crt)
#    3. Client Certificate for EDR Sensors (client.key, client.crt)
# ==============================================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="$PROJECT_DIR/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "🔐 Generating cryptographic certificates for mTLS..."

# 1. Generate Internal Root Certificate Authority (CA)
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=US/ST=Security/L=Cyber/O=AutoSOC/OU=SecurityOperations/CN=AutoSOC-Root-CA" 2>/dev/null

# 2. OpenSSL SAN Configuration (Crucial for modern TLS & gRPC)
cat > server_ext.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = autosoc-grpc
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# 3. Generate Server Key & CSR, then Sign with CA
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/C=US/ST=Security/L=Cyber/O=AutoSOC/OU=Ingress/CN=localhost" \
    -config server_ext.cnf 2>/dev/null

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server_ext.cnf -extensions v3_req 2>/dev/null

# 4. Generate Client Key & CSR (representing an EDR sensor), then Sign with CA
openssl req -newkey rsa:2048 -nodes \
    -keyout client.key -out client.csr \
    -subj "/C=US/ST=Security/L=Cyber/O=AutoSOC/OU=EDR-Sensor/CN=sensor-linux-01" 2>/dev/null

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 2>/dev/null

# Cleanup intermediate CSR and extension files
rm -f server.csr client.csr server_ext.cnf ca.srl

echo "✅ mTLS Certificates successfully generated in certs/:"
echo "   - Root CA     : certs/ca.crt"
echo "   - Server Cert : certs/server.crt & certs/server.key"
echo "   - Client Cert : certs/client.crt & certs/client.key"
