#!/bin/bash
# Generates the local PKI for the demo (stub of FR-6 enrollment / NFR-6 mTLS):
#   ca.pem/ca.key           local root CA, pinned by the sensor (only trusted CA)
#   server.pem/server.key   backend ingress cert for localhost / 127.0.0.1 (collector + control plane)
#   endpoint.pem/.key/.p12  endpoint client identity; CN = endpoint id (tenant/endpoint derive from the cert, §11)
# Output: backend/certs/out/ (gitignored). Idempotent: keeps an existing CA unless --force.
set -euo pipefail
DIR="${IESO_CERT_OUT:-$(cd "$(dirname "$0")" && pwd)/out}"   # override for tests
ENDPOINT_ID="${1:-ep-demo}"
[ "${2:-}" = "--force" ] && rm -rf "$DIR"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=ieso local root CA" \
    -keyout ca.key -out ca.pem 2>/dev/null
fi

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:otel-collector,DNS:control-plane,IP:127.0.0.1
EOF
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -sha256 \
  -extfile server.ext -out server.pem 2>/dev/null

cat > client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl req -newkey rsa:2048 -nodes -subj "/CN=${ENDPOINT_ID}/O=tenant-demo" -keyout endpoint.key -out endpoint.csr 2>/dev/null
openssl x509 -req -in endpoint.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -sha256 \
  -extfile client.ext -out endpoint.pem 2>/dev/null
# PKCS#12 identity for libcurl (mirrors a Keychain identity). -legacy keeps it readable by LibreSSL.
openssl pkcs12 -export -legacy -in endpoint.pem -inkey endpoint.key -certfile ca.pem \
  -passout pass:ieso -name "$ENDPOINT_ID" -out endpoint.p12 2>/dev/null \
  || openssl pkcs12 -export -in endpoint.pem -inkey endpoint.key -certfile ca.pem \
       -passout pass:ieso -name "$ENDPOINT_ID" -out endpoint.p12
# --- Step 4: probe signing (FR-14). The control plane signs probe requests; the sensor pins the public key.
if [ ! -f probe-signing.key ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out probe-signing.key 2>/dev/null
  openssl ec -in probe-signing.key -pubout -out probe-signing.pub.pem 2>/dev/null
fi

# --- Step 4 network-failure demo (fictional names): the app's own backend CA and a TLS-inspecting proxy's CA.
mkdir -p demo corpguard
if [ ! -f demo/backend-ca.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=DemoApp Backend CA/O=DemoApp Inc" \
    -keyout demo/backend-ca.key -out demo/backend-ca.pem 2>/dev/null
fi
printf '%s\n' "basicConstraints=CA:FALSE" "keyUsage=digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,DNS:app-backend,IP:127.0.0.1" > demo/backend.ext
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost/O=DemoApp Inc" \
  -keyout demo/backend.key -out demo/backend.csr 2>/dev/null
openssl x509 -req -in demo/backend.csr -CA demo/backend-ca.pem -CAkey demo/backend-ca.key -CAcreateserial \
  -days 397 -sha256 -extfile demo/backend.ext -out demo/backend.pem 2>/dev/null
if [ ! -f corpguard/mitmproxy-ca.pem ]; then
  printf '%s\n' "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign" > corpguard/ca.ext
  openssl req -newkey rsa:2048 -nodes -subj "/CN=CorpGuard TLS Inspection CA/O=CorpGuard SWG" \
    -keyout corpguard/ca.key -out corpguard/ca.csr 2>/dev/null
  openssl x509 -req -in corpguard/ca.csr -signkey corpguard/ca.key -days 825 -sha256 -extfile corpguard/ca.ext \
    -out corpguard/ca.pem 2>/dev/null
  cat corpguard/ca.key corpguard/ca.pem > corpguard/mitmproxy-ca.pem   # mitmproxy: key + cert in one file
  cp corpguard/ca.pem corpguard/mitmproxy-ca-cert.pem
fi
rm -f demo/*.csr demo/*.ext demo/*.srl corpguard/*.csr corpguard/*.ext
chmod 644 demo/* corpguard/* probe-signing.*   # read by non-root containers (demo PKI only)

rm -f ./*.csr ./*.ext ca.srl
chmod 644 ./*.pem ./*.p12 ./*.key   # containers run as non-root and must read the server key (demo only)
echo "certs in $DIR (endpoint CN=$ENDPOINT_ID)"
