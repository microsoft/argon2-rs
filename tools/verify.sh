#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo verus verify --manifest-path verus/Cargo.toml --locked \
  --fwd-verus-args-to roots -- --no-cheating "$@"
