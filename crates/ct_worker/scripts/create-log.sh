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

wrangler() {
    npx wrangler -e="${ENV}" -c "${WRANGLER_CONF}" "$@"
}

# https://github.com/cloudflare/azul/pull/169#discussion_r2582145507
location=()
if [ "${LOCATION}" ]; then
    location=(--location "${LOCATION}")
fi

# Create R2 bucket if it does not already exist
bucket_name=static-ct-public-${LOG_NAME}
if wrangler r2 bucket info "$bucket_name" 2>/dev/null ; then
    echo "r2 bucket '$bucket_name' already exists"
else
    wrangler r2 bucket create "$bucket_name" \
        --update-config \
        --binding "public_${LOG_NAME}" "${location[@]}"
fi

# Create KV namespace if it does not already exist
namespace_name=static-ct-cache-${LOG_NAME}
if wrangler kv namespace list | jq '.[].title' -r | grep -q "$namespace_name"; then
    echo "kv namespace '$namespace_name' already exists"
else
    wrangler kv namespace create "$namespace_name" \
        --update-config \
        --binding "cache_${LOG_NAME}"
fi

# Create witness and log signing keys if they do not already exist
if wrangler secret list | grep -q "WITNESS_KEY_${LOG_NAME}"; then
	echo "WITNESS_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm ed25519 |
        wrangler secret put "WITNESS_KEY_${LOG_NAME}"
fi
if wrangler secret list | grep -q "SIGNING_KEY_${LOG_NAME}"; then
	echo "SIGNING_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 |
        wrangler secret put "SIGNING_KEY_${LOG_NAME}"
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
