#!/usr/bin/env bash

set -e -o pipefail

# Helper script to create resources for a log shard.

if [ -z $ENV ] || [ -z $CLOUDFLARE_ACCOUNT_ID ]; then
	echo "ENV, LOG_NAME, LOCATION, and CLOUDFLARE_ACCOUNT_ID must all be set"
	exit 1
fi

WRANGLER_CONF=${WRANGLER_CONF:-wrangler.jsonc}

while true; do
    read -p "Do you want to proceed with ENV=${ENV}, CLOUDFLARE_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}? (y/N) " yn
    case $yn in
        [yY] ) echo "Proceeding..."; break;;
        [nN] ) echo "Exiting..."; exit;;
        * ) echo "Invalid input. Please enter 'y' or 'N'.";;
    esac
done

# Create KV namespace if it does not already exist
npx wrangler \
    -e="${ENV}" \
    -c "${WRANGLER_CONF}" \
    kv namespace create \
    static-ct-ccadb-roots \
    --update-config \
    --binding ccadb_roots
