#!/usr/bin/env bash
# Run every Fuzz* target in the module for FUZZTIME (default 30s) each.
# Go can fuzz only one target per invocation, so loop over them.
#   FUZZTIME=30s tools/fuzz.sh [packages...]
set -euo pipefail
fuzztime=${FUZZTIME:-30s}
pkgs=("${@:-./...}")
fail=0
while read -r pkg; do
  for fn in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $pkg $fn ($fuzztime)"
    go test -run='^$' -fuzz="^${fn}\$" -fuzztime="$fuzztime" "$pkg" || fail=1
  done
done < <(go list "${pkgs[@]}")
exit $fail
