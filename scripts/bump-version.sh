#!/usr/bin/env bash
# Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Set the workspace version in Cargo.toml and refresh Cargo.lock.
#
# Usage: scripts/bump-version.sh <X.Y.Z[-prerelease]|major|minor|patch>

set -euo pipefail

arg="${1:-}"
usage() {
    echo "usage: $0 <X.Y.Z[-prerelease]|major|minor|patch>" >&2
    exit 2
}

cd "$(dirname "$0")/.."

old=$(awk '/^\[workspace\.package\]/{f=1; next} /^\[/{f=0} f && /^version *=/{gsub(/"/, "", $3); print $3; exit}' Cargo.toml)
if [[ -z "$old" ]]; then
    echo "could not find [workspace.package] version in Cargo.toml" >&2
    exit 1
fi
IFS=. read -r major minor patch <<<"${old%%-*}"
case "$arg" in
    major) new="$((major + 1)).0.0" ;;
    minor) new="$major.$((minor + 1)).0" ;;
    patch) new="$major.$minor.$((patch + 1))" ;;
    *) new="$arg" ;;
esac
if [[ ! "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    usage
fi
if [[ "$old" == "$new" ]]; then
    echo "workspace version is already $new" >&2
    exit 1
fi

export OLD="$old" NEW="$new"
perl -0pi -e '
    s/(\[workspace\.package\][^\[]*?\nversion = ")\Q$ENV{OLD}\E(")/$1$ENV{NEW}$2/s;
    s/(path = "crates\/[^"]+", version = ")\Q$ENV{OLD}\E(")/$1$ENV{NEW}$2/g;
' Cargo.toml

cargo update --workspace

echo "bumped workspace version: $old -> $new"
