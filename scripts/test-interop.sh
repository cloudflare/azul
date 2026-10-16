#!/usr/bin/env bash
set -euo pipefail

# Interoperability checks against external c2sp.org/tlog-mirror server
# implementations, each pinned to a known revision by the calling workflow.
#
# The client suite in crates/tlog_mirror/tests/conformance.rs encodes request
# bodies with our wire format and sends them to a live server, so a framing
# disagreement fails here rather than passing two self-consistent suites.
#
# Usage: test-interop.sh <implementation>

implementation=${1:?usage: test-interop.sh sunlight|tessera}
repo_root=$(git rev-parse --show-toplevel)
work_dir=$(mktemp -d)
server_pid=""

# `go run` execs the built binary as a child, so the listener outlives a kill
# of the `go run` process itself.
terminate_tree() {
  local child
  while read -r child; do
    [[ -z $child ]] || terminate_tree "$child"
  done < <(pgrep -P "$1" 2>/dev/null || true)
  kill "$1" 2>/dev/null || true
}

cleanup() {
  status=$?
  if [[ -n $server_pid ]]; then
    terminate_tree "$server_pid"
    wait "$server_pid" 2>/dev/null || true
  fi
  if (( status != 0 )) && [[ -f $work_dir/server.log ]]; then
    echo "--- server log ---"
    cat "$work_dir/server.log"
  fi
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT

require_free_port() {
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/"; then
    echo "port $1 is already serving; refusing to run against a stale server" >&2
    return 1
  fi
}

wait_for_server() {
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "$1"; then
      return 0
    fi
    sleep 1
  done
  echo "server at $1 did not become ready" >&2
  return 1
}

# Tessera reads log_origin with a uint16 length prefix while the spec (and
# Sunlight since FiloSottile/sunlight#73) requires uint8, so its failures are
# reported without failing the run until that is fixed upstream.
expect_fail=0
mirror_host=""

require_free_port 18788

case "$implementation" in
  sunlight)
    repo=${SUNLIGHT_REPO:?SUNLIGHT_REPO must point to the Sunlight checkout}
    log_origin=conformance.example/log
    python3 - "$work_dir/checkpoints.db" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
db.execute("CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT")
db.close()
PY
    mkdir "$work_dir/public"
    (
      cd "$repo"
      go run ./cmd/sunlight-keygen -json -f "$work_dir/seed.bin" \
        -witness conformance.witness -mirror conformance.mirror
    ) > "$work_dir/keys.json"
    printf 'logs/v0\n\n' > "$work_dir/logs.txt"
    cat > "$work_dir/sunlight.yaml" <<EOF
listen:
  - "127.0.0.1:18788"
checkpoints: $work_dir/checkpoints.db
witness:
  name: conformance.witness
  mirrorname: conformance.mirror
  submissionprefix: https://localhost
  monitoringprefix: https://localhost/mirror
  secret: $work_dir/seed.bin
  localdirectory: $work_dir/public
  loglists:
    - $work_dir/logs.txt
  mirrorloglists:
    - $work_dir/logs.txt
EOF
    (cd "$repo" && go run ./cmd/sunlight -c "$work_dir/sunlight.yaml") \
      > "$work_dir/server.log" 2>&1 &
    server_pid=$!
    # Sunlight routes the witness mux under the submissionprefix host.
    mirror_host=localhost
    ;;
  tessera)
    repo=${TESSERA_REPO:?TESSERA_REPO must point to the Tessera checkout}
    expect_fail=1
    (
      cd "$repo"
      go run github.com/transparency-dev/witness/cmd/generate_keys \
        --mldsa --origin conformance.mirror \
        --out_priv "$work_dir/mirror.sec" --out_pub "$work_dir/mirror.vkey"
    )
    printf 'logs/v0\n\n' > "$work_dir/logs.txt"
    (
      cd "$repo"
      go run ./cmd/mtc/mirror/posix \
        --listen_addr=127.0.0.1:18788 \
        --storage_dir="$work_dir/tessera" \
        --mirror_cosigner_path="$work_dir/mirror.sec" \
        --config_path="$work_dir/logs.txt"
    ) > "$work_dir/server.log" 2>&1 &
    server_pid=$!
    ;;
  *)
    echo "unsupported implementation: $implementation" >&2
    exit 2
    ;;
esac

wait_for_server http://127.0.0.1:18788/

printf '==> %s mirror conformance\n' "$implementation"
cd "$repo_root"
TLOG_MIRROR_URL=http://127.0.0.1:18788 \
TLOG_MIRROR_HOST="$mirror_host" \
TLOG_MIRROR_EXPECT_FAIL="$expect_fail" \
  cargo test -p tlog_mirror --test conformance -- --nocapture
