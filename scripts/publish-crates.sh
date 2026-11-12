#!/usr/bin/env bash
# Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Publish every publishable workspace crate to crates.io in dependency order,
# skipping versions already on the registry index so a partial run can be
# re-run.
#
# Usage: scripts/publish-crates.sh
# Environment: CARGO_REGISTRY_TOKEN, or DRY_RUN=1 to only report what would be
# published.

set -euo pipefail

cd "$(dirname "$0")/.."

index_path() {
    local name
    name=$(tr '[:upper:]' '[:lower:]' <<<"$1")
    case "${#name}" in
        1) echo "1/$name" ;;
        2) echo "2/$name" ;;
        3) echo "3/${name:0:1}/$name" ;;
        *) echo "${name:0:2}/${name:2:2}/$name" ;;
    esac
}

published() {
    local name=$1 version=$2 body status
    body=$(mktemp)
    status=$(curl -sS -o "$body" -w '%{http_code}' "https://index.crates.io/$(index_path "$name")")
    case "$status" in
        200) jq -e --arg v "$version" 'select(.vers == $v)' "$body" >/dev/null ;;
        404) return 1 ;;
        *)
            echo "unexpected HTTP $status from the crates.io index for $name" >&2
            exit 1
            ;;
    esac
}

packages=$(cargo metadata --format-version 1 --no-deps | python3 -c '
import json, sys
from graphlib import TopologicalSorter

meta = json.load(sys.stdin)
pkgs = {
    p["name"]: p
    for p in meta["packages"]
    if p["publish"] is None or "crates-io" in p["publish"]
}
graph = {
    name: {d["name"] for d in p["dependencies"] if d["name"] in pkgs}
    for name, p in pkgs.items()
}
for name in TopologicalSorter(graph).static_order():
    print(name, pkgs[name]["version"])
')

while read -r name version; do
    if published "$name" "$version"; then
        echo "$name $version is already published; skipping"
        continue
    fi
    echo "publishing $name $version"
    if [[ -n "${DRY_RUN:-}" ]]; then
        continue
    fi
    cargo publish --package "$name"
done <<<"$packages"
