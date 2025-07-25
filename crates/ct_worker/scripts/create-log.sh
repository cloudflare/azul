#!/bin/sh

# Helper script to create resources for a log shard.

if [ -z $ENV ] || [ -z $LOG_NAME ] || [ -z $LOCATION ] || [ -z $CLOUDFLARE_ACCOUNT_ID ]; then
	echo "ENV, LOG_NAME, LOCATION, and CLOUDFLARE_ACCOUNT_ID must all be set"
	exit 1
fi

while true; do
    read -p "Do you want to proceed with ENV=${ENV}, LOG_NAME=${LOG_NAME}, LOCATION=${LOCATION}, CLOUDFLARE_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}? (y/N) " yn
    case $yn in
        [yY] ) echo "Proceeding..."; break;;
        [nN] ) echo "Exiting..."; exit;;
        * ) echo "Invalid input. Please enter 'y' or 'N'.";;
    esac
done

# Create R2 bucket if it does not already exist
npx wrangler r2 bucket create static-ct-public-${LOG_NAME} --location ${LOCATION}

# Create KV namespace if it does not already exist
npx wrangler kv namespace create static-ct-cache-${LOG_NAME}

# Create witness and log signing keys if they do not already exist
if npx wrangler -e=${ENV} secret list | grep -q WITNESS_KEY_${LOG_NAME}; then
	echo "WITNESS_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm ed25519 | npx wrangler -e=${ENV} secret put WITNESS_KEY_${LOG_NAME}
fi
if npx wrangler -e=${ENV} secret list | grep -q SIGNING_KEY_${LOG_NAME}; then
	echo "SIGNING_KEY_${LOG_NAME} already exists"
else
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | npx wrangler -e=${ENV} secret put SIGNING_KEY_${LOG_NAME}
fi
