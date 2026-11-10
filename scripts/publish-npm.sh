#!/usr/bin/env bash
# Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Publish built wasm-pack package directories to npm, skipping versions already
# on the registry so a partial run can be re-run.
#
# Usage: scripts/publish-npm.sh <pkg-dir>...
# Environment: DRY_RUN=1 to only report what would be published.

set -euo pipefail

registry=https://registry.npmjs.org

published() {
    local spec=$1 out err
    err=$(mktemp)
    if out=$(npm view "$spec" version --registry "$registry" 2>"$err"); then
        [[ -n "$out" ]]
        return
    fi
    if grep -q E404 "$err"; then
        return 1
    fi
    cat "$err" >&2
    exit 1
}

for dir in "$@"; do
    name=$(jq -r .name "$dir/package.json")
    version=$(jq -r .version "$dir/package.json")
    if published "$name@$version"; then
        echo "$name@$version is already published; skipping"
        continue
    fi
    echo "publishing $name@$version"
    if [[ -n "${DRY_RUN:-}" ]]; then
        continue
    fi
    (cd "$dir" && npm publish --access public)
done
