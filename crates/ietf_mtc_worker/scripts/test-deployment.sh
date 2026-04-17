#!/usr/bin/env bash
#
# End-to-end smoke test against a deployed IETF MTC CA worker.
#
# Generates a CSR, submits it via /add-entry to get a standalone MTC certificate
# (§6.2), waits for a landmark to be produced, and fetches a landmark-relative
# MTC certificate (§6.3) for the same entry. Prints a summary of each response
# (certificate size, subject, issuer, validity, and signature-algorithm OID).
#
# This is a smoke test only: it confirms that the HTTP endpoints work end-to-end
# and that the DER-encoded certificates parse. It does NOT verify the Merkle
# inclusion proof or the cosignature — for that, run the Rust integration
# tests against the same base URL:
#
#   BASE_URL=<url> IETF_MTC_LOG_NAME=<log> cargo test -p integration_tests --test ietf_mtc_api
#
# Usage:
#
#   scripts/test-deployment.sh \
#       --base-url https://ietf-mtc-dev.<subdomain>.workers.dev \
#       --log dev1 \
#       [--algorithm ed25519|ML-DSA-44]
#
# Requires: openssl (>= 3.5 for ML-DSA), curl, jq, base64.

set -e -o pipefail

BASE_URL=""
LOG=""
ALGORITHM="ed25519"
LANDMARK_TIMEOUT=30

while [ $# -gt 0 ]; do
    case "$1" in
        --base-url) BASE_URL="$2"; shift 2 ;;
        --log) LOG="$2"; shift 2 ;;
        --algorithm) ALGORITHM="$2"; shift 2 ;;
        --landmark-timeout) LANDMARK_TIMEOUT="$2"; shift 2 ;;
        -h|--help)
            sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "${BASE_URL}" ] || [ -z "${LOG}" ]; then
    echo "Usage: $0 --base-url <url> --log <name> [--algorithm ed25519|ML-DSA-44]" >&2
    exit 1
fi

BASE_URL=${BASE_URL%/}

for cmd in openssl curl jq base64; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Required command not found: ${cmd}" >&2
        exit 1
    fi
done

WORKDIR=$(mktemp -d -t ietf-mtc-test-XXXXXXXX)
trap 'rm -rf "${WORKDIR}"' EXIT
echo "workdir: ${WORKDIR}"

call() {
    curl --silent --fail-with-body --max-time 30 "$@"
}

b64url_encode() {
    # stdin -> base64url (no padding)
    base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'
}

summarize_cert() {
    local label="$1"
    local der="$2"
    local size
    size=$(wc -c < "${der}" | tr -d ' ')
    echo "  ${label}: ${size} bytes DER"
    openssl x509 -in "${der}" -inform DER -noout \
        -serial -subject -issuer -dates 2>&1 | sed 's/^/    /'
    local sigalg
    sigalg=$(openssl asn1parse -inform DER -in "${der}" 2>&1 |
        awk -F':' '/OBJECT.*44363\.47\.0/ { print $NF; exit }')
    if [ -n "${sigalg}" ]; then
        echo "    sigalg OID: ${sigalg} (id-alg-mtcProof)"
    fi
}

echo "[1/4] GET ${BASE_URL}/logs/${LOG}/metadata"
call "${BASE_URL}/logs/${LOG}/metadata" > "${WORKDIR}/metadata.json"
jq -r '"  description: \(.description)\n  log_id: \(.log_id)\n  cosigner_id: \(.cosigner_id)"' \
    "${WORKDIR}/metadata.json"
jq -r '.cosigner_public_key' "${WORKDIR}/metadata.json" |
    base64 --decode > "${WORKDIR}/cosigner_spki.der"
echo "  cosigner SPKI: $(wc -c < "${WORKDIR}/cosigner_spki.der" | tr -d ' ') bytes DER"

echo "[2/4] Generating ${ALGORITHM} CSR"
genpkey_args=(genpkey -algorithm "${ALGORITHM}" -out "${WORKDIR}/key.pem")
case "${ALGORITHM}" in
    ML-DSA-44|ml-dsa-44)
        genpkey_args+=(-provparam ml-dsa.output_formats=seed-only) ;;
esac
openssl "${genpkey_args[@]}" 2>/dev/null
openssl req -new -key "${WORKDIR}/key.pem" -out "${WORKDIR}/csr.pem" \
    -subj "/CN=test.example.com" \
    -addext "subjectAltName=DNS:test.example.com,DNS:www.test.example.com" 2>/dev/null
openssl req -in "${WORKDIR}/csr.pem" -outform DER 2>/dev/null > "${WORKDIR}/csr.der"
openssl pkey -in "${WORKDIR}/key.pem" -pubout -outform DER 2>/dev/null > "${WORKDIR}/spki.der"
echo "  CSR: $(wc -c < "${WORKDIR}/csr.der" | tr -d ' ') bytes DER"
echo "  SPKI: $(wc -c < "${WORKDIR}/spki.der" | tr -d ' ') bytes DER"

echo "[3/4] POST ${BASE_URL}/logs/${LOG}/add-entry"
csr_b64url=$(b64url_encode < "${WORKDIR}/csr.der")
jq -n --arg csr "${csr_b64url}" '{csr: $csr}' > "${WORKDIR}/add-entry.json"
call -X POST "${BASE_URL}/logs/${LOG}/add-entry" \
    -H "content-type: application/json" \
    -d @"${WORKDIR}/add-entry.json" > "${WORKDIR}/add-entry-resp.json"
jq -r '.certificate' "${WORKDIR}/add-entry-resp.json" |
    base64 --decode > "${WORKDIR}/standalone.der"
summarize_cert "standalone cert" "${WORKDIR}/standalone.der"

# Extract the leaf index from the serial number (hex).
serial_hex=$(openssl x509 -in "${WORKDIR}/standalone.der" -inform DER -noout -serial |
    awk -F= '{print $2}')
leaf_index=$((16#${serial_hex}))
echo "  leaf_index (from serial): ${leaf_index}"

echo "[4/4] POST ${BASE_URL}/logs/${LOG}/get-certificate (polling up to ${LANDMARK_TIMEOUT}s for landmark)"
spki_b64=$(base64 < "${WORKDIR}/spki.der" | tr -d '\n')
jq -n --argjson leaf "${leaf_index}" --arg spki "${spki_b64}" \
    '{leaf_index: $leaf, spki_der: $spki}' > "${WORKDIR}/get-certificate.json"

deadline=$(( $(date +%s) + LANDMARK_TIMEOUT ))
last_http_status=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
    # `curl --fail-with-body` returns non-zero on 4xx/5xx; capture status
    # and body independently.
    http_status=$(curl --silent --max-time 30 \
        -o "${WORKDIR}/get-certificate-resp.json" \
        -w "%{http_code}" \
        -X POST "${BASE_URL}/logs/${LOG}/get-certificate" \
        -H "content-type: application/json" \
        -d @"${WORKDIR}/get-certificate.json")
    last_http_status="${http_status}"
    if [ "${http_status}" = "200" ]; then
        jq -r '.data' "${WORKDIR}/get-certificate-resp.json" |
            base64 --decode > "${WORKDIR}/landmark.der"
        landmark_id=$(jq -r '.landmark_id' "${WORKDIR}/get-certificate-resp.json")
        echo "  landmark_id: ${landmark_id}"
        summarize_cert "landmark-relative cert" "${WORKDIR}/landmark.der"
        exit 0
    fi
    sleep 2
done

echo "  timed out waiting for landmark (last HTTP ${last_http_status})" >&2
exit 1
