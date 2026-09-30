#!/usr/bin/env bash
# Edge Console launcher.
#
# Serves the FastAPI app on two listeners from one container:
#   - HTTP  on ${CONSOLE_HTTP_PORT}  (default 8090) — unchanged, for health
#     checks / plain access.
#   - HTTPS on ${CONSOLE_HTTPS_PORT} (default 8443) — TLS with a self-signed
#     certificate so the box can be reached at https://sensel.local:8443.
#
# .local names cannot get a public-CA cert, so the appliance runs its OWN local
# CA: a persistent root (${TLS_DIR}/ca/rootCA.*) signs the console leaf cert.
# Operators install the root once per client (download via
# http://<name>.local:8090/sensel-root-ca.crt) for a green-lock, warning-free
# HTTPS. The CA + leaf live on the data volume and survive container rebuilds,
# and the leaf is only re-issued when missing or when the SAN list changes.
set -euo pipefail

TLS_DIR="${CONSOLE_TLS_DIR:-/data/agent/tls}"
CA_DIR="${TLS_DIR}/ca"
CA_KEY="${CA_DIR}/rootCA.key"
CA_CRT="${CA_DIR}/rootCA.crt"
CRT="${TLS_DIR}/console.crt"
KEY="${TLS_DIR}/console.key"
HTTP_PORT="${CONSOLE_HTTP_PORT:-8090}"
HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}"
CA_CN="${CONSOLE_CA_CN:-SenseL Edge Local CA}"
# Comma-separated names/IPs to embed in the cert SAN. Names -> DNS:, dotted
# quads -> IP:. Default covers the mDNS name + loopback.
TLS_HOSTS="${CONSOLE_TLS_HOSTS:-sensel.local,localhost,127.0.0.1}"

mkdir -p "${CA_DIR}"
chmod 700 "${CA_DIR}" || true

# Build the OpenSSL subjectAltName string from TLS_HOSTS.
SAN=""
CN=""
IFS=',' read -ra _hosts <<< "${TLS_HOSTS}"
for h in "${_hosts[@]}"; do
  h="$(echo "$h" | xargs)"
  [ -z "$h" ] && continue
  [ -z "$CN" ] && CN="$h"
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="${SAN},IP:${h}"
  else
    SAN="${SAN},DNS:${h}"
  fi
done
SAN="${SAN#,}"
CN="${CN:-sensel.local}"

# 1) Local CA root — generated once, then reused forever (long-lived).
if [[ ! -f "${CA_CRT}" || ! -f "${CA_KEY}" ]]; then
  echo "[entrypoint] Creating local CA root (CN=${CA_CN})"
  openssl genrsa -out "${CA_KEY}" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 7300 \
    -subj "/CN=${CA_CN}/O=SenseL" -out "${CA_CRT}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  chmod 600 "${CA_KEY}" || true
  rm -f "${CRT}" "${KEY}" "${TLS_DIR}/.san"  # force a fresh leaf under the new CA
fi

# 2) Console leaf cert — re-issued only when missing or SAN changed. The stamp
#    carries a "ca-v1" marker so leaves from the old plain self-signed scheme
#    are automatically re-issued under the CA on upgrade.
SAN_STAMP="${TLS_DIR}/.san"
WANT_STAMP="${SAN}|ca-v1"
if [[ ! -f "${CRT}" || ! -f "${KEY}" || "$(cat "${SAN_STAMP}" 2>/dev/null || true)" != "${WANT_STAMP}" ]]; then
  echo "[entrypoint] Issuing CA-signed console cert (CN=${CN}, SAN=${SAN})"
  openssl genrsa -out "${KEY}" 2048 >/dev/null 2>&1
  openssl req -new -key "${KEY}" -subj "/CN=${CN}" -out "${TLS_DIR}/console.csr" >/dev/null 2>&1
  openssl x509 -req -in "${TLS_DIR}/console.csr" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${CRT}" -days 3650 -sha256 \
    -extfile <(printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "${SAN}") >/dev/null 2>&1
  rm -f "${TLS_DIR}/console.csr"
  printf '%s' "${WANT_STAMP}" > "${SAN_STAMP}"
  chmod 600 "${KEY}" || true
fi

echo "[entrypoint] HTTP  on :${HTTP_PORT}  | HTTPS on :${HTTPS_PORT} (SAN=${SAN})"

uvicorn src.main:app --host 0.0.0.0 --port "${HTTP_PORT}" &
HTTP_PID=$!
uvicorn src.main:app --host 0.0.0.0 --port "${HTTPS_PORT}" \
  --ssl-keyfile "${KEY}" --ssl-certfile "${CRT}" &
HTTPS_PID=$!

_term() { kill -TERM "${HTTP_PID}" "${HTTPS_PID}" 2>/dev/null || true; }
trap _term TERM INT

# If either listener exits, tear the whole container down so the orchestrator
# (restart: unless-stopped) brings a clean replacement up.
wait -n "${HTTP_PID}" "${HTTPS_PID}"
_term
wait || true
