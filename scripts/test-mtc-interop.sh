#!/usr/bin/env bash
set -euo pipefail

implementation=${1:?usage: test-mtc-interop.sh sunlight|tessera}
case "$implementation" in
  sunlight) mirror_id=44363.48.9 ;;
  tessera) mirror_id=44363.48.8 ;;
  *) echo "unsupported mirror implementation: $implementation" >&2; exit 2 ;;
esac

repo_root=$(git rev-parse --show-toplevel)
mirror_repo=${MIRROR_REPO:?MIRROR_REPO must point to the external mirror checkout}
cactus_repo=${CACTUS_REPO:?CACTUS_REPO must point to the Cactus checkout}
work_dir=$(mktemp -d)
mirror_name="oid/1.3.6.1.4.1.${mirror_id}"
log_origin=oid/1.3.6.1.4.1.44363.48.1.0.1
origin_hash=ba499ad0cd2229ad7737da766fc58ab549f67054ba3c95453dcee9d58e8bd4df
service_pids=()

terminate_tree() {
  local child
  while read -r child; do
    [[ -z $child ]] || terminate_tree "$child"
  done < <(pgrep -P "$1" 2>/dev/null || true)
  kill "$1" 2>/dev/null || true
}

cleanup() {
  status=$?
  if (( status != 0 )); then
    [[ ! -f $work_dir/azul.log ]] || cat "$work_dir/azul.log"
    [[ ! -f $work_dir/mirror.log ]] || cat "$work_dir/mirror.log"
  fi
  for pid in "${service_pids[@]}"; do
    terminate_tree "$pid"
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT

vkey_to_spki() {
  python3 - "$1" <<'PY'
import base64
import sys

vkey = open(sys.argv[1], encoding="utf-8").read().strip()
key = base64.b64decode(vkey.split("+", 2)[2])
if len(key) != 1313 or key[0] != 6:
    raise SystemExit("expected an ML-DSA-44 verifier key")
prefix = bytes.fromhex("30820532300b06096086480165030403110382052100")
print(base64.b64encode(prefix + key[1:]).decode())
PY
}

if [[ $implementation == sunlight ]]; then
  (
    cd "$mirror_repo"
    go run ./cmd/sunlight-keygen -json -f "$work_dir/mirror.seed" \
      -witness sunlight.witness.interop -mirror "$mirror_name"
  ) > "$work_dir/keys.json"
  jq -r .mirror_vkey_mldsa44 "$work_dir/keys.json" > "$work_dir/mirror.vkey"
else
  (
    cd "$mirror_repo"
    go run github.com/transparency-dev/witness/cmd/generate_keys \
      --mldsa --origin "$mirror_name" \
      --out_priv "$work_dir/mirror.sec" --out_pub "$work_dir/mirror.vkey"
  )
fi
mirror_spki=$(vkey_to_spki "$work_dir/mirror.vkey")

jq --arg id "$mirror_id" --arg key "$mirror_spki" '
  .logs = {"dev1": .logs.dev1}
  | .logs.dev1.cosigners = [{
      "id": $id,
      "submission_url": "http://localhost:18788/",
      "public_key": $key
    }]
' "$repo_root/crates/ietf_mtc_worker/config.dev.json" > "$work_dir/azul.json"

(
  cd "$repo_root/crates/ietf_mtc_worker"
  IETF_MTC_CONFIG="$work_dir/azul.json" wrangler -e=dev dev \
    --port 8787 --inspector-port 9230 --persist-to "$work_dir/wrangler"
) > "$work_dir/azul.log" 2>&1 &
service_pids+=("$!")

for _ in $(seq 1 90); do
  if curl -sf http://localhost:8787/logs/dev1/metadata > "$work_dir/metadata.json"; then
    break
  fi
  sleep 2
done
test -s "$work_dir/metadata.json" || { cat "$work_dir/azul.log"; exit 1; }

python3 - "$work_dir/metadata.json" > "$work_dir/log.vkey" <<'PY'
import base64
import hashlib
import json
import sys

metadata = json.load(open(sys.argv[1], encoding="utf-8"))
spki = base64.b64decode(metadata["cosigner_public_key"])
prefix = bytes.fromhex("30820532300b06096086480165030403110382052100")
if not spki.startswith(prefix) or len(spki) != len(prefix) + 1312:
    raise SystemExit("expected an ML-DSA-44 SubjectPublicKeyInfo")
name = "oid/1.3.6.1.4.1.44363.48.1"
key = b"\x06" + spki[len(prefix):]
key_id = hashlib.sha256(name.encode() + b"\n" + key).digest()[:4].hex()
print(f"{name}+{key_id}+{base64.b64encode(key).decode()}")
PY

{
  printf 'logs/v0\n\n'
  printf 'vkey %s\n' "$(<"$work_dir/log.vkey")"
  printf 'origin %s\n' "$log_origin"
  if [[ $implementation == sunlight ]]; then
    printf 'qpd 86400\ncontact interop@example.test\n'
  fi
} > "$work_dir/logs.txt"

if [[ $implementation == sunlight ]]; then
  mkdir "$work_dir/public"
  python3 - "$work_dir/checkpoints.db" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
db.execute("CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT")
db.close()
PY
  cat > "$work_dir/sunlight.yaml" <<EOF
listen:
  - "127.0.0.1:18788"
checkpoints: $work_dir/checkpoints.db
witness:
  name: sunlight.witness.interop
  mirrorname: $mirror_name
  submissionprefix: https://localhost
  monitoringprefix: https://localhost/mirror
  secret: $work_dir/mirror.seed
  localdirectory: $work_dir/public
  loglists:
    - $work_dir/logs.txt
  mirrorloglists:
    - $work_dir/logs.txt
EOF
  (cd "$mirror_repo" && go run ./cmd/sunlight -c "$work_dir/sunlight.yaml") \
    > "$work_dir/mirror.log" 2>&1 &
  service_pids+=("$!")
  monitoring_root="$work_dir/public"
  monitoring_dir="$monitoring_root/mirror/$origin_hash"
  monitoring_url="http://localhost:18789/mirror/$origin_hash"
else
  (cd "$mirror_repo" && go run ./cmd/mtc/mirror/posix \
    --listen_addr=127.0.0.1:18788 --storage_dir="$work_dir/tessera" \
    --mirror_cosigner_path="$work_dir/mirror.sec" --config_path="$work_dir/logs.txt") \
    > "$work_dir/mirror.log" 2>&1 &
  service_pids+=("$!")
  monitoring_root="$work_dir/tessera/public/mirrors"
  monitoring_dir="$monitoring_root/$origin_hash"
  monitoring_url="http://localhost:18789/$origin_hash"
fi

for _ in $(seq 1 90); do
  if curl -s -o /dev/null http://localhost:18788/; then
    break
  fi
  sleep 2
done
curl -s -o /dev/null http://localhost:18788/ || { cat "$work_dir/mirror.log"; exit 1; }

mkdir -p "$monitoring_root"
python3 -m http.server 18789 --bind 127.0.0.1 --directory "$monitoring_root" \
  > "$work_dir/http.log" 2>&1 &
service_pids+=("$!")

mirror_identity=$(jq -cn --arg name "$mirror_name" --arg public_key "$mirror_spki" \
  '{name: $name, public_key: $public_key}')
run_certificate_test() {
  IETF_MTC_LOG_NAME=dev1 \
  IETF_MTC_MIRROR_IDENTITY="$mirror_identity" \
  IETF_MTC_CERTIFICATE_OUT="$1" \
    perl -e '$timeout = shift; alarm $timeout; exec @ARGV' 180 \
      cargo test -p integration_tests --test ietf_mtc_api \
      add_entry_returns_valid_response -- --exact --nocapture
}
run_certificate_test "$work_dir/certificate.der"
sleep 11
run_certificate_test "$work_dir/landmark-trigger.der"

if [[ $implementation == sunlight ]]; then
  python3 - "$monitoring_root" <<'PY'
import gzip
import os
import pathlib
import sys

for directory, _, files in os.walk(sys.argv[1]):
    for name in files:
        path = pathlib.Path(directory, name)
        body = path.read_bytes()
        if body.startswith(b"\x1f\x8b"):
            path.chmod(path.stat().st_mode | 0o200)
            path.write_bytes(gzip.decompress(body))
PY
fi

curl -sf http://localhost:8787/logs/dev1/landmarks > "$monitoring_dir/landmarks"
openssl x509 -inform DER -in "$work_dir/certificate.der" -out "$work_dir/certificate.pem"
(cd "$cactus_repo" && go build -o "$work_dir/cactus" ./cmd/cactus-cli)
"$work_dir/cactus" tree verify "$monitoring_url"
"$work_dir/cactus" cert verify "$work_dir/certificate.pem" "$monitoring_url"
"$work_dir/cactus" cert landmark-relative "$work_dir/certificate.pem" "$monitoring_url"
