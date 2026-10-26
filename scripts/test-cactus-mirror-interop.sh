#!/usr/bin/env bash
set -euo pipefail

# Interoperability check of the mirror_worker tlog-mirror server against an
# independent client: Cactus, a Go MTC CA that pushes its issuance log to a
# mirror (add-checkpoint, add-entries) and requests sign-subtree cosignatures.
#
# Cactus issues certificates through ACME. Each certificate can only be issued
# once Cactus holds the mirror's cosignature, so successful issuance shows that
# the mirror accepted the pushed log and signed a subtree that Cactus verified.
# Cactus also accepts the pre-v1.1.0 signed-note response form, so a recording
# proxy on the sign-subtree path checks the wire format of each response. The
# mirror's published checkpoint is then compared with Cactus's.
#
# Usage: CACTUS_REPO=<cactus checkout> test-cactus-mirror-interop.sh [certs]

cactus_repo=${CACTUS_REPO:?CACTUS_REPO must point to the Cactus checkout}
cert_count=${1:-300}
repo_root=$(git rev-parse --show-toplevel)
work_dir=$(mktemp -d)
service_pids=()

ca_id=44363.47.1.99
mirror_id=44363.47.2.1
log_number=1
mirror_name=oid/1.3.6.1.4.1.$mirror_id
signer_name=oid/1.3.6.1.4.1.$ca_id
log_origin=oid/1.3.6.1.4.1.$ca_id.0.$log_number
origin_hash=$(printf '%s' "$log_origin" | shasum -a 256 | cut -d' ' -f1)
mirror_port=18788
proxy_port=18789

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
    for log in cactus.log mirror.log proxy.log; do
      [[ ! -f $work_dir/$log ]] || { echo "--- $log ---"; tail -n 200 "$work_dir/$log"; }
    done
  fi
  for pid in "${service_pids[@]}"; do
    terminate_tree "$pid"
    wait "$pid" 2>/dev/null || true
  done
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

for port in "$mirror_port" "$proxy_port" 14000 14080 14090; do
  require_free_port "$port"
done

mkdir -p "$work_dir/bin" "$work_dir/cactus/keys"

# lego refuses a plain-HTTP ACME directory, so Cactus serves ACME over TLS with
# a throwaway certificate that lego is told to trust.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$work_dir/acme.key" -out "$work_dir/acme.crt" 2>/dev/null

(cd "$cactus_repo" && go build -o "$work_dir/bin/" ./cmd/cactus ./cmd/cactus-cli ./cmd/cactus-keygen)
GOBIN="$work_dir/bin" go install github.com/go-acme/lego/v4/cmd/lego@v4.35.2

# The CA cosigner key signs the issuance log's checkpoints, so the mirror is
# configured with its public key as a subtree/v1 checkpoint signer.
"$work_dir/bin/cactus-keygen" -o "$work_dir/cactus/keys/ca-cosigner.seed" 2>/dev/null
"$work_dir/bin/cactus-keygen" -pub -o "$work_dir/cactus/keys/ca-cosigner.seed" \
  > "$work_dir/ca-cosigner.pem"

# The ca-cosigner public key as the SubjectPublicKeyInfo the mirror expects.
python3 - "$work_dir" <<'PY'
import base64, pathlib, sys

work = pathlib.Path(sys.argv[1])
ca = (work / "ca-cosigner.pem").read_text()
ca_raw = base64.b64decode("".join(ca.splitlines()[1:-1]))
prefix = bytes.fromhex("30820532300b06096086480165030403110382052100")
(work / "ca-cosigner.spki").write_text(base64.b64encode(prefix + ca_raw).decode())
PY

jq -n \
  --arg origin "$log_origin" \
  --arg signer "$signer_name" \
  --arg mirror "$mirror_name" \
  --arg key "$(<"$work_dir/ca-cosigner.spki")" \
  --arg prefix "http://localhost:$mirror_port/" \
  '{
    logging_level: "info",
    submission_prefix: $prefix,
    enable_chrome_cosigners: false,
    mirror: {
      name: $mirror,
      description: "Cactus interop mirror",
      monitoring_prefix: "https://mirror.interop.example/",
      clean_interval_secs: 5,
      commit_packages: 2
    },
    logs: {
      ($origin): {
        checkpoint_signers: [{name: $signer, algorithm: "subtree/v1", public_key: $key}]
      }
    }
  }' > "$work_dir/mirror.json"

(
  cd "$repo_root/crates/mirror_worker"
  WORKER_CONFIG="$work_dir/mirror.json" wrangler -e=mirror dev \
    --port "$mirror_port" --inspector-port 9233 --persist-to "$work_dir/wrangler"
) > "$work_dir/mirror.log" 2>&1 &
service_pids+=("$!")

for _ in $(seq 1 120); do
  if curl -sf "http://localhost:$mirror_port/metadata" > "$work_dir/metadata.json"; then
    break
  fi
  sleep 2
done
test -s "$work_dir/metadata.json" || { echo "mirror did not become ready" >&2; exit 1; }
test "$(jq -r '.mirror.name' "$work_dir/metadata.json")" = "$mirror_name"

# The mirror signs with the dev key from mirror_worker/.dev.vars, published in
# its metadata as SubjectPublicKeyInfo (the first key is the current one).
# Cactus is given the raw ML-DSA-44 public key as a PEM block. OpenSSL is not
# used for the conversion because runner images ship a version without ML-DSA.
jq -r '.mirror.public_keys[0].public_key' "$work_dir/metadata.json" | python3 -c '
import base64, sys

spki = base64.b64decode(sys.stdin.read())
assert len(spki) == 1312 + 22, len(spki)
body = base64.encodebytes(spki[-1312:]).decode()
print(f"-----BEGIN PUBLIC KEY-----\n{body}-----END PUBLIC KEY-----")
' > "$work_dir/cactus/keys/mirror.pem"

# Forwards sign-subtree requests to the mirror unchanged and keeps each request
# and response body for inspection.
mkdir -p "$work_dir/sign-subtree"
cat > "$work_dir/record-proxy.py" <<'PY'
import http.server, itertools, sys, threading, urllib.error, urllib.request

port, upstream, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
counter = itertools.count(1)
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        request = urllib.request.Request(
            upstream + self.path, data=body, method="POST",
            headers={"Content-Type": self.headers.get("Content-Type", "")},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                status, data = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, data = error.code, error.read()
        with lock:
            n = next(counter)
        for suffix, content in ((f"{n}.status", f"{status}\n".encode()), (f"{n}.req", body), (f"{n}.resp", data)):
            with open(f"{out}/{suffix}", "wb") as f:
                f.write(content)
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        print(*args, file=sys.stderr, flush=True)


http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
python3 "$work_dir/record-proxy.py" "$proxy_port" "http://localhost:$mirror_port" \
  "$work_dir/sign-subtree" > "$work_dir/proxy.log" 2>&1 &
service_pids+=("$!")

jq \
  --arg dir "$work_dir/cactus" \
  --arg ca_id "$ca_id" \
  --arg mirror_id "$mirror_id" \
  --argjson log_number "$log_number" \
  --arg prefix "http://localhost:$mirror_port" \
  --arg proxy "http://localhost:$proxy_port" \
  --arg tls_cert "$work_dir/acme.crt" \
  --arg tls_key "$work_dir/acme.key" \
  '
  .data_dir = $dir
  | .log.number = $log_number
  | .log.checkpoint_period_ms = 1000
  | .ca_cosigner.id = $ca_id
  | .metrics.listen = "127.0.0.1:14090"
  | .acme.external_url = "https://localhost:14000"
  | .acme.tls_cert = $tls_cert
  | .acme.tls_key = $tls_key
  | .ca_cosigner_quorum = {
      mirrors: [{
        id: $mirror_id,
        url: ($proxy + "/sign-subtree"),
        algorithm: "mldsa-44",
        public_key_path: "keys/mirror.pem"
      }],
      min_signatures: 1,
      request_timeout_ms: 10000,
      best_effort_after_minimum: false,
      mirror_retry_deadline_ms: 30000
    }
  | .mirror_push = {
      targets: [{
        id: $mirror_id,
        submission_prefix: $prefix,
        algorithm: "mldsa-44",
        public_key_path: "keys/mirror.pem"
      }],
      request_timeout_ms: 15000,
      push_timeout_ms: 60000
    }
  | .log_level = "debug"
  ' "$cactus_repo/config-example.json" > "$work_dir/cactus-config.json"

"$work_dir/bin/cactus" -config "$work_dir/cactus-config.json" > "$work_dir/cactus.log" 2>&1 &
service_pids+=("$!")

for _ in $(seq 1 60); do
  if curl -sf --cacert "$work_dir/acme.crt" https://localhost:14000/directory > /dev/null &&
     curl -sf "http://localhost:14080/$log_number/checkpoint" > /dev/null; then
    break
  fi
  sleep 1
done
curl -sf --cacert "$work_dir/acme.crt" https://localhost:14000/directory > /dev/null \
  || { echo "cactus did not become ready" >&2; exit 1; }

issue() {
  local id=$1
  local dir="$work_dir/certs/$id"
  mkdir -p "$dir"
  LEGO_CA_CERTIFICATES="$work_dir/acme.crt" "$work_dir/bin/lego" \
    --server https://localhost:14000/directory \
    --email "interop-$id@example.test" \
    --domains "host-$id.example.test" \
    --accept-tos --http --http.port ":$((5100 + id % 800))" \
    --path "$dir" run > "$dir/lego.log" 2>&1 || { cat "$dir/lego.log" >&2; return 1; }
}

printf '==> issuing %s certificates through Cactus\n' "$cert_count"
pids=()
for id in $(seq 1 "$cert_count"); do
  issue "$id" &
  pids+=("$!")
  if (( ${#pids[@]} >= 8 )); then
    wait "${pids[0]}"
    pids=("${pids[@]:1}")
  fi
done
for pid in "${pids[@]}"; do
  wait "$pid"
done

sample="$work_dir/certs/1/certificates/host-1.example.test.crt"
test -s "$sample"
"$work_dir/bin/cactus-cli" cert text "$sample" | tee "$work_dir/cert.txt"
signatures=$(sed -n 's/^ *signatures: *//p' "$work_dir/cert.txt")
if [[ $signatures != 2 ]]; then
  echo "expected the CA and mirror cosignatures, got $signatures signature(s)" >&2
  exit 1
fi

# tlog-witness@v1.1.0 sign-subtree: a successful response body is exactly one
# line of canonical base64 holding the bare signature, and the request carries
# only the subtree header, consistency proof and reference checkpoint.
python3 - "$work_dir/sign-subtree" <<'PY'
import base64, pathlib, re, sys

out = pathlib.Path(sys.argv[1])
statuses = sorted(out.glob("*.status"))
ok = 0
for status_file in statuses:
    n = status_file.stem
    status = int(status_file.read_text())
    if status != 200:
        continue
    ok += 1
    body = (out / f"{n}.resp").read_bytes()
    assert re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}\n", body), f"response {n} is not one base64 line: {body[:80]!r}"
    signature = base64.b64decode(body[:-1], validate=True)
    assert base64.b64encode(signature) + b"\n" == body, f"response {n} is not canonical base64"
    assert len(signature) == 2420, f"response {n}: {len(signature)} byte signature, want ML-DSA-44 (2420)"
    header = (out / f"{n}.req").read_bytes().split(b"\n\n", 1)[0].decode().split("\n")
    assert header[0].startswith("subtree "), f"request {n}: bad range line {header[0]!r}"
    for line in header[2:]:
        assert re.fullmatch(r"[A-Za-z0-9+/]{43}=", line), f"request {n}: unexpected header line {line[:60]!r}"
assert ok > 0, "no successful sign-subtree exchange was recorded"
print(f"==> {ok} sign-subtree responses are a single canonical base64 line")
PY

"$work_dir/bin/cactus-cli" tree verify "http://localhost:14080/$log_number"
"$work_dir/bin/cactus-cli" cert verify "$sample" "http://localhost:14080/$log_number"

# The mirror publishes the checkpoint it committed. Once it has caught up, its
# tree matches Cactus's: same size and root hash.
cactus_tree() { curl -sf "http://localhost:14080/$log_number/checkpoint" | sed -n '2,3p'; }
mirror_tree() {
  (
    cd "$repo_root/crates/mirror_worker"
    wrangler r2 object get "mirror-worker-public-dev/$origin_hash/checkpoint" \
      --local --persist-to "$work_dir/wrangler" --pipe 2>/dev/null | sed -n '2,3p'
  )
}
for _ in $(seq 1 60); do
  expected=$(cactus_tree)
  actual=$(mirror_tree || true)
  if [[ -n $actual && $actual == "$expected" ]]; then
    printf '==> mirror matches Cactus: %s\n' "$(printf '%s' "$expected" | tr '\n' ' ')"
    exit 0
  fi
  sleep 2
done
printf 'mirror tree "%s" does not match Cactus tree "%s"\n' \
  "$(printf '%s' "$actual" | tr '\n' ' ')" "$(printf '%s' "$expected" | tr '\n' ' ')" >&2
exit 1
