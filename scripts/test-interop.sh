#!/usr/bin/env bash
set -euo pipefail

# Interoperability checks against external transparency-log implementations,
# each pinned to a known revision by the calling workflow.
#
# Usage: test-interop.sh <implementation>

implementation=${1:?usage: test-interop.sh sunlight}
repo_root=$(git rev-parse --show-toplevel)

case "$implementation" in
  sunlight)
    sunlight_repo=${SUNLIGHT_REPO:?SUNLIGHT_REPO must point to the Sunlight checkout}

    # Sunlight's own mirror tests pin the add-entries framing, including the
    # uint8 log_origin length prefix.
    printf '%s\n' '==> Sunlight tlog-mirror tests'
    (cd "$sunlight_repo" && go test ./internal/witness -count=1)

    # The Azul side of the same framing.
    printf '%s\n' '==> Azul tlog-mirror wire tests'
    (cd "$repo_root" && cargo test -p tlog_mirror --verbose)
    ;;
  *)
    echo "unsupported implementation: $implementation" >&2
    exit 2
    ;;
esac
