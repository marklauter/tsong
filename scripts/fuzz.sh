#!/usr/bin/env bash
# Fuzzes every target for the given number of seconds each, growing the
# corpus under fuzz/corpus from the seeds under fuzz/seeds. Needs the
# nightly in $NIGHTLY and cargo-fuzz.
#
#   NIGHTLY=nightly-2026-10-01 scripts/fuzz.sh 20
#
# The target is named because a prebuilt cargo-fuzz defaults to musl,
# which the address sanitizer can't build for. Debug assertions and
# overflow checks are on, which release builds leave off.
set -euo pipefail

seconds="${1:?usage: scripts/fuzz.sh <seconds per target>}"
cd "$(dirname "$0")/.."
for target in jwt config forwarded token_form; do
  mkdir -p "fuzz/corpus/$target" "fuzz/seeds/$target"
  echo "fuzzing $target for ${seconds}s"
  cargo "+${NIGHTLY:?set NIGHTLY to the pinned nightly}" fuzz run \
    --debug-assertions --target x86_64-unknown-linux-gnu "$target" \
    "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
    -max_len=16384 -max_total_time="$seconds"
done
