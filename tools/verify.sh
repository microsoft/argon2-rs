#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
verus_bin="${VERUS_BIN:-verus}"
mkdir -p target/verus
"$verus_bin" verus/shared.rs --crate-type lib --no-cheating --compile \
  --out-dir target/verus --rlimit 30 --log-dir target/verus/log
"$verus_bin" verus/block_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/block_g_rows_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/block_g_column_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/block_g_columns_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/block_g_fill_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/blake2b_compress_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/blake2b_tables_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/blake2b_buffer_verified.rs --crate-type lib --no-cheating \
  --rlimit 30
"$verus_bin" verus/blake2b_update_verified.rs --crate-type lib --no-cheating \
  --rlimit 30