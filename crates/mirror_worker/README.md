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
npx wrangler -e=dev dev
./reset-dev.sh
```

Run the integration suites from the workspace root against the same worker:

```bash
cargo test -p integration_tests --test tlog_witness
cargo test -p integration_tests --test tlog_mirror
```
