#!/bin/bash

set -e

bootstrap_cert_hostname="cloudflareresearch.com"
landmark_interval_secs=`jq '.logs.dev2.landmark_interval_secs' config.dev.json`
submission_url=`jq -r '.logs.dev2.submission_url' config.dev.json`

# Get a bootstrap certificate chain.
bootstrap_cert_chain=`mktemp`
echo | openssl s_client \
	-connect ${bootstrap_cert_hostname}:443 \
	-servername ${bootstrap_cert_hostname} \
	-showcerts 2>/dev/null |\
	sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
	> ${bootstrap_cert_chain}

spki_der=`openssl x509 -in ${bootstrap_cert_chain} -pubkey -noout |\
	openssl pkey -pubin -inform pem -outform der | base64`

add_entry_req=`cat ${bootstrap_cert_chain} |\
	while (set -o pipefail;
		openssl x509 -outform DER 2>/dev/null |\
			base64); do :; done |\
	sed '/^$/d' | sed 's/.*/"&"/' | jq -sc '{"chain":.}'`

# Add entry for the bootstrap certificate.
add_entry_resp=`curl -f --no-progress-meter -X POST \
  -H "Content-Type: application/json" \
  -d ${add_entry_req} \
  "${submission_url}add-entry"`

leaf_index=`echo ${add_entry_resp} | jq '.leaf_index'`
echo "Leaf index: ${leaf_index}"

# Wait for the next landmark to be minted.
echo "Waiting ${landmark_interval_secs}s for the next landmark"
sleep ${landmark_interval_secs}

get_cert_req="{\"leaf_index\":${leaf_index},\"spki_der\":\"${spki_der}\"}"

# Fetch the completed MTC.
get_cert_resp=`curl -f --no-progress-meter -X POST \
  -H "Content-Type: application/json" \
  -d ${get_cert_req} \
  "${submission_url}get-certificate"`

landmark_id=`echo ${get_cert_resp} | jq '.landmark_id'`
echo "Landmark id: ${landmark_id}"

echo ${get_cert_resp} | jq -r '.data' | base64 -d |\
	openssl x509  -inform DER -outform PEM
