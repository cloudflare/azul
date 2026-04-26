#!/usr/bin/env bash
#
# Helper script to provision resources for an IETF MTC log shard:
#   - R2 bucket for public log data (tiles, checkpoints, subtree signatures)
#   - SIGNING_KEY_<LOG_NAME> secret with the per-shard cosigner signing key
#
# IETF MTC does not use witness keys (unlike static-ct-api logs), so only a
# single signing key is created per shard. The algorithm (Ed25519 or
# ML-DSA-44) is selected via the ALGORITHM env var.
#
# Usage:
#
#   ENV=dev LOG_NAME=dev1 ALGORITHM=ml-dsa-44 \
#     CLOUDFLARE_ACCOUNT_ID=<account> ./scripts/create-log.sh
#
#   ENV=dev LOG_NAME=dev2 ALGORITHM=ed25519 \
#     CLOUDFLARE_ACCOUNT_ID=<account> ./scripts/create-log.sh
#
# Optional:
#   WRANGLER_CONF      - wrangler config to use (default: wrangler.jsonc)
#   LOCATION           - R2 bucket location hint (e.g. wnam, enam)

set -e -o pipefail
cd "$(dirname "$0")/.." || exit # this script assumes it's running inside the ietf_mtc_worker dir

if [ -z "${ENV}" ] || [ -z "${LOG_NAME}" ] || [ -z "${ALGORITHM}" ] || [ -z "${CLOUDFLARE_ACCOUNT_ID}" ]; then
    echo "ENV, LOG_NAME, ALGORITHM, and CLOUDFLARE_ACCOUNT_ID must all be set"
    echo "ALGORITHM must be one of: ed25519, ml-dsa-44"
    exit 1
fi

case "${ALGORITHM}" in
    ed25519|ML-DSA-44|ml-dsa-44) ;;
    *)
        echo "Unknown ALGORITHM='${ALGORITHM}'. Must be one of: ed25519, ml-dsa-44"
        exit 1
        ;;
esac

WRANGLER_CONF=${WRANGLER_CONF:-wrangler.jsonc}

while true; do
    if [ "${LOCATION}" ]; then
        L=", LOCATION=${LOCATION}"
    fi
    read -rp "Do you want to proceed with ENV=${ENV}, LOG_NAME=${LOG_NAME}, ALGORITHM=${ALGORITHM}${L}, CLOUDFLARE_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}? (y/N) " yn
    case $yn in
        [yY] ) echo "Proceeding..."; break;;
        [nN] ) echo "Exiting..."; exit;;
        * ) echo "Invalid input. Please enter 'y' or 'N'.";;
    esac
done

# https://github.com/cloudflare/azul/pull/169#discussion_r2582145507
location=()
if [ "${LOCATION}" ]; then
    location=(--location "${LOCATION}")
fi

# Create R2 bucket if it does not already exist
npx wrangler \
    -e="${ENV}" \
    -c "${WRANGLER_CONF}" \
    r2 bucket create \
    "ietf-mtc-public-${LOG_NAME}" \
    --update-config \
    --binding "public_${LOG_NAME}" "${location[@]}"

# Create the log signing key if one does not already exist.
#
# Note: for ML-DSA-44 we pass `-provparam ml-dsa.output_formats=seed-only`
# so the generated PEM is a compact 32-byte-seed PKCS#8 private key (the
# form that matches NIST ACVP test vectors and that `ml-dsa-0.1.0-rc.8`'s
# PKCS#8 decoder expects). The default OpenSSL output would be the full
# expanded-key form (~2.5 KB) which the worker will reject.
if npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret list | grep -q "SIGNING_KEY_${LOG_NAME}"; then
    echo "SIGNING_KEY_${LOG_NAME} already exists"
else
    case "${ALGORITHM}" in
        ed25519)
            openssl genpkey -algorithm ed25519 |
                npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret put "SIGNING_KEY_${LOG_NAME}"
            ;;
        ML-DSA-44|ml-dsa-44)
            openssl genpkey -algorithm ML-DSA-44 \
                -provparam ml-dsa.output_formats=seed-only |
                npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret put "SIGNING_KEY_${LOG_NAME}"
            ;;
    esac
fi

echo "DONE"
echo "NOTE: If you intend to run wrangler dev with this log, you must add the appropriate signing key to .dev.vars:"
echo "~~~~~~"
case "${ALGORITHM}" in
    ed25519)
        printf 'echo -n "SIGNING_KEY_%s=\\"" >> .dev.vars\n' "${LOG_NAME}"
        printf 'openssl genpkey -algorithm ed25519 | sed '\''s/$/\\\\n/g'\'' | tr -d '\''\\n'\'' >> .dev.vars\n'
        printf 'echo \\" >> .dev.vars\n'
        ;;
    ML-DSA-44|ml-dsa-44)
        printf 'echo -n "SIGNING_KEY_%s=\\"" >> .dev.vars\n' "${LOG_NAME}"
        printf 'openssl genpkey -algorithm ML-DSA-44 -provparam ml-dsa.output_formats=seed-only | sed '\''s/$/\\\\n/g'\'' | tr -d '\''\\n'\'' >> .dev.vars\n'
        printf 'echo \\" >> .dev.vars\n'
        ;;
esac
