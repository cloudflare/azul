#!/usr/bin/env bash
# Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Print the [workspace.package] version from a Cargo.toml.
#
# Usage: scripts/workspace-version.sh [path]   (reads stdin when no path is given)

set -euo pipefail

awk '
    /^\[workspace\.package\]/ { found = 1; next }
    /^\[/ { found = 0 }
    found && /^version *=/ { gsub(/"/, "", $3); print $3; exit }
' "${1:--}"
