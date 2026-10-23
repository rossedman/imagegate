#!/usr/bin/env bash
# Fail when statement coverage of hand-written code is below the gate.
# Generated files (tools/generated) and examples/ are dropped from the
# profile first, since counting them can hide or fake the real number.
#   tools/cover.sh [profile] [min]
set -euo pipefail
profile=${1:-coverage.out}
min=${2:-90}
hand=${profile%.out}.hand.out
gen=$(mktemp)
trap 'rm -f "$gen"' EXIT
go run ./tools/generated ./... >"$gen"
{
  head -1 "$profile"
  grep -v '^mode:' "$profile" | { if [ -s "$gen" ]; then grep -vFf "$gen"; else cat; fi; } | grep -v '/examples/' || true
} >"$hand"
total=$(go tool cover -func="$hand" | awk '/^total:/ {sub("%", "", $3); print $3}')
echo "coverage (hand-written code): ${total}% (gate ${min}%)"
awk -v t="$total" -v m="$min" 'BEGIN { exit (t + 0 < m + 0) }' || {
  echo "coverage ${total}% < ${min}%" >&2
  exit 1
}
