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

A read that finds no snapshot synchronizes once before falling back to an empty
registry, so a fresh deployment serves dynamic origins before the first hourly
event. A failure there is logged and leaves the static logs servable.

`chrome_cosigner_realms` lists the Chrome `realm` values accepted from the
registry. An issuer whose realm is absent from the list is not trusted, so
omitting the list trusts no dynamic cosigner. The registry currently publishes
`UNTRUSTED_VALIDATION_ONLY` test CAs. Realms are stored in the snapshot and
applied on read, so changing the list takes effect without a re-synchronization.

Witness and mirror monitoring prefixes are backed by separate public R2 buckets.
The Worker only serves submission and metadata APIs.

`MIRROR_TICKET_KEY` seals mirror upload tickets. It is a standard-base64
encoding of 32 random bytes, for example from
`head -c 32 /dev/urandom | base64`.

Bind `MIRROR_TICKET_KEY`, `MIRROR_SIGNING_KEY`, `MIRROR_SIGNING_KEY_NEXT`,
`WITNESS_SIGNING_KEY`, and `WITNESS_SIGNING_KEY_NEXT` from Secrets Store as
needed. Each signing-key binding contains one PKCS#8 PEM private key. For
example, add the ticket binding to the applicable Wrangler environment's
`secrets_store_secrets` array (using your store ID):

```jsonc
"secrets_store_secrets": [
    {
        "binding": "MIRROR_TICKET_KEY",
        "store_id": "<STORE_ID>",
        "secret_name": "MIRROR_TICKET_KEY"
    }
]
```

Local Wrangler development uses the same binding names in `.dev.vars` when
Secrets Store bindings are absent. When moving an existing deployment from a
Worker secret to Secrets Store, copy the **same** base64 ticket key value into
the store before switching the binding; changing the key invalidates tickets
already issued to clients. Remove the old Worker secret after the new binding
is deployed.

The current key is required and the `_NEXT` key is optional. During rotation, checkpoint cosignatures are produced with both keys. `sign-subtree` requires a reference checkpoint with exactly one signature and signs the subtree with the key that produced it, so a client that needs both keys' subtree cosignatures sends one request per key. If promotion temporarily leaves both secrets containing the same key, the duplicate public key is loaded once and produces one signature. Complete promotion by copying `_NEXT` to the current secret, then unsetting `_NEXT`.

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

## Operations

The mirror Durable Objects and hourly registry job send invocation counts,
latencies, errors, and buffered logs through the optional `WSHIM_SOCKET` /
`WSHIM_TOKEN` bindings. The `MirrorState` DO reports
`mirror_last_publication_timestamp_seconds{origin,role}` on successful checkpoint
publication. The cleaner alarm reports `mirror_cleaner_backlog_leaves{origin}`; registry
reads and syncs report `mirror_registry_last_sync_timestamp_seconds`.
`origin` is the SHA-256 origin hash used in the monitoring URL. Publication
and registry-sync timestamps are absent until the first successful operation.

Publication timestamps are emitted only after the existing checkpoint writes
succeed; the Worker does not persist monitoring timestamps. Registry-sync time
is emitted when synchronization succeeds. Frontier and gap gauges are deferred:
sampling state on `/get-state` alone would leave stale values when no read occurs.
Without a separate progress source, there are no missing-origin or
stalled-progress alerts.
The cleaner backlog is emitted on successful cleaner alarm wakes (one hour by
default). Publication timestamps are events: use the metrics backend's retained
history to obtain the last value, and do not interpret a missing recent sample
as no publication.
Missing cleaner samples do not imply zero backlog. The cleaner reserves two of
its 1,000 subrequests for the logs and metrics Wshim flushes; Wshim delivery
remains best-effort. The metrics backend can alert on missing samples using an
independent inventory of expected cleaner origins. Enroll a cleaner origin only
after its first persisted upload, since checkpoint acceptance alone does not
start the cleaner. The hourly registry job can likewise be monitored against
expected deployments where `enable_chrome_cosigners` is true. Failed witness
invocations emit per-origin event gauges. Incoming metrics need an `env` label
matching the deployment's Wrangler environment for per-environment monitoring.
