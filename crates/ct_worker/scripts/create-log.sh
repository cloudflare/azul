#!/usr/bin/env bash

set -e -o pipefail
cd "$(dirname "$0")/.." || exit # this script assumes it's runnnig inside the ct_worker dir

# Helper script to create resources for a log shard.

if [ -z "${ENV}" ] || [ -z "${LOG_NAME}" ] || [ -z "${CLOUDFLARE_ACCOUNT_ID}" ]; then
	echo "ENV, LOG_NAME, and CLOUDFLARE_ACCOUNT_ID must all be set"
	exit 1
fi

WRANGLER_CONF=${WRANGLER_CONF:-wrangler.jsonc}

while true; do
    if [ "${LOCATION}" ]; then
        L=", LOCATION=${LOCATION}"
    fi
    read -rp "Do you want to proceed with ENV=${ENV}, LOG_NAME=${LOG_NAME}${L}, CLOUDFLARE_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}? (y/N) " yn
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
    "static-ct-public-${LOG_NAME}" \
    --update-config \
    --binding "public_${LOG_NAME}" "${location[@]}"

# Create KV namespace if it does not already exist
npx wrangler \
    -e="${ENV}" \
    -c "${WRANGLER_CONF}" \
    kv namespace create \
    "static-ct-cache-${LOG_NAME}" \
    --update-config \
    --binding "cache_${LOG_NAME}"

# Create witness and log signing keys if they do not already exist
if npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret list | grep -q "WITNESS_KEY_${LOG_NAME}"; then
	echo "WITNESS_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm ed25519 |
        npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret put "WITNESS_KEY_${LOG_NAME}"
fi
if npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret list | grep -q "SIGNING_KEY_${LOG_NAME}"; then
	echo "SIGNING_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 |
        npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" secret put "SIGNING_KEY_${LOG_NAME}"
fi

echo "DONE"
echo "NOTE: If you intend to run wrangler dev with this log, you must add the appropriate signing keys to .dev.vars"
echo "~~~~~~"
printf 'echo -n "SIGNING_KEY_%s=\\"" >> .dev.vars\n' "${LOG_NAME}"
printf 'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | sed '\''s/$/\\\\n/g'\'' | tr -d '\''\\n'\'' >> .dev.vars\n'
printf 'echo \\" >> .dev.vars\n'
printf 'echo -n "WITNESS_KEY_%s=\\"" >> .dev.vars\n' "${LOG_NAME}"
printf 'openssl genpkey -algorithm ed25519 | sed '\''s/$/\\\\n/g'\'' | tr -d '\''\\n'\'' >> .dev.vars\n'
printf 'echo \\" >> .dev.vars\n'
