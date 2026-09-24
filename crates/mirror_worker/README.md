# Transparency Log Mirror Worker

A configurable Cloudflare Worker implementing
[`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness),
[`c2sp.org/tlog-mirror`](https://c2sp.org/tlog-mirror), or both protocols
with one per-origin `MirrorState` Durable Object.

## Configuration

The presence of the `witness` and `mirror` identity sections enables each role.
Combined deployments use a shared submission prefix and distinct monitoring
prefixes per identity. `logs` is keyed by exact checkpoint origin and supports
structured Ed25519 and `subtree/v1` checkpoint signers.

When `enable_chrome_cosigners` is true, an hourly scheduled event synchronizes
the public MTC cosigner registry into the singleton `CosignerRegistry` SQLite
Durable Object. Synchronized issuer logs are merged with `logs`; static
configuration takes precedence for an origin. The option defaults to true.
Registry versions are opaque identifiers because the upstream schema does not
require semantic-version syntax. Replacement rejects changed content under the
same version and parseable timestamp regressions.

Witness and mirror monitoring prefixes are backed by separate public R2 buckets.
The Worker only serves submission and metadata APIs.

Role keys remain separate secrets:

- `WITNESS_SIGNING_KEY` signs successful `add-checkpoint` responses and witness subtree responses.
- `MIRROR_SIGNING_KEY` signs completed mirror checkpoints and mirror subtree responses.
- `MIRROR_TICKET_KEY` seals mirror upload tickets.

Disabled-role secrets and R2 bindings are not loaded. Ticket and cleaner access
is confined to mirror operations.

## Mirror State

For each origin, `MirrorState` maintains
`committed.size <= next_entry.size <= pending.size`. Checkpoint publication is
serialized and durably ordered as `publishing -> R2 -> committed -> clear`.
Every commit reconciles an existing `publishing` record first, so interrupted
publication is retried before an older or newer request is evaluated.

## Development

The dev configuration enables both roles. Run from this directory:

```bash
./reset-dev.sh
npx wrangler -e=dev dev --test-scheduled \
  --var COSIGNERS_JSON_URL:http://127.0.0.1:8790/cosigners.json \
  --var COSIGNERS_PEM_URL:http://127.0.0.1:8790/cosigners.pem
```

Run the integration suites from the workspace root against the same worker:

```bash
cargo test -p integration_tests --test tlog_witness
cargo test -p integration_tests --test tlog_mirror
```

The mirror integration test starts the registry fixture server on port 8790.
The URL overrides are only honored by the `dev` build and are needed for that
suite. Other builds use the public gstatic registry.
