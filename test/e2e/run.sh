#!/usr/bin/env bash
# End-to-end tests: a dedicated dockerd with imagegate as its authorization
# plugin, a zot registry (OCI referrers), and cosign-signed fixtures.
#
# Requirements: root, dockerd + docker CLI, go, and cosign. COSIGN points at
# a cosign v2 binary (legacy .sig/.att tags); COSIGN_V3 optionally at a
# cosign v3 binary (Sigstore bundles via referrers). Signing is keyed: CI
# has no OIDC identity, keyless paths are covered by the Go tests.
#
# The script starts its own dockerd (separate data root and socket) and
# never touches the host's daemon. Run it on a disposable host or in a
# privileged Docker-in-Docker container.
set -euo pipefail

COSIGN=${COSIGN:-cosign}
COSIGN_V3=${COSIGN_V3:-}
PORT=${REGISTRY_PORT:-5055}
BASE=${BASE_IMAGE:-mirror.gcr.io/library/busybox:1.36}
REG=localhost:$PORT
PLUGIN=imagegate-e2e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d /tmp/imagegate-e2e.XXXXXX)
export DOCKER_HOST=unix://$W/docker.sock
export COSIGN_PASSWORD=""

pass=0
fail=0
log() { printf '\n== %s\n' "$*"; }

cleanup() {
  set +e
  docker rm -f zot >/dev/null 2>&1
  [ -f "$W/docker.pid" ] && kill "$(cat "$W/docker.pid")" 2>/dev/null
  [ -f "$W/imagegate.pid" ] && kill "$(cat "$W/imagegate.pid")" 2>/dev/null
  sleep 2
  umount -R "$W/data" "$W/exec/netns/default" "$W/exec" 2>/dev/null
  [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W" 2>/dev/null
}
trap cleanup EXIT

start_imagegate() {
  "$W/imagegate" serve \
    -socket "/run/docker/plugins/$PLUGIN.sock" -policy "$W/policy.yaml" -overrides "$W/overrides.d" \
    -registry-config "$W/registry" -cache "$W/cache.db" -tuf-cache "$W/tuf" \
    -admin-socket "$W/admin.sock" -metrics-addr 127.0.0.1:0 -docker-socket "$W/docker.sock" \
    >>"$W/audit.log" 2>>"$W/imagegate.log" &
  echo $! >"$W/imagegate.pid"
  for _ in $(seq 1 50); do
    "$W/imagegate" health -socket "/run/docker/plugins/$PLUGIN.sock" >/dev/null 2>&1 && return
    sleep 0.1
  done
  echo "imagegate did not start"; cat "$W/imagegate.log"; exit 1
}

reload() { kill -HUP "$(cat "$W/imagegate.pid")"; sleep 0.5; }

write_policy() { # mode
  cat >"$W/policy.yaml" <<EOF
apiVersion: imagegate.dev/v1
mode: $1
defaults:
  verifyTimeout: 10s
trust:
  sigstore: public-good
identities:
  ci-key:
    publicKey: $W/keys/cosign.pub
localImages: deny
rules:
  - name: internal
    images: ["$REG/acme/**"]
    signature:
      identities: [ci-key]
    sbom:
      identities: [ci-key]
EOF
}

# expect <name> <allow|REASON> <image> [docker run args...]
expect() {
  local name=$1 want=$2 image=$3 out
  shift 3
  if out=$(docker run --rm "$@" "$image" true 2>&1); then
    if [ "$want" = allow ]; then
      echo "PASS  $name"; pass=$((pass + 1)); return
    fi
    echo "FAIL  $name: allowed, want $want"; fail=$((fail + 1)); return
  fi
  if [ "$want" != allow ] && grep -q "reason: $want" <<<"$out"; then
    echo "PASS  $name ($want)"; pass=$((pass + 1)); return
  fi
  echo "FAIL  $name: want $want, got:"; echo "$out" | sed 's/^/      /'; fail=$((fail + 1))
}

check() { # name command...
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $name"; pass=$((pass + 1)); else echo "FAIL  $name"; fail=$((fail + 1)); fi
}

digest_of() { # repo:tag -> sha256:...
  curl -fsSI -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json' \
    "http://$REG/v2/${1%%:*}/manifests/${1##*:}" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}

build_push() { # name content
  printf 'FROM %s\nRUN echo %s > /id\n' "$BASE" "$2" | docker build -q --network host -t "$REG/acme/$1:1" - >/dev/null
  docker push -q "$REG/acme/$1:1" >/dev/null
  digest_of "acme/$1:1"
}

sign_v2() { "$COSIGN" sign --key "$W/keys/${3:-cosign}.key" -y --tlog-upload=false "$REG/acme/$1@$2" >/dev/null 2>&1; }
attest_v2() { "$COSIGN" attest --key "$W/keys/cosign.key" -y --tlog-upload=false --type "$3" --predicate "$W/sbom.$3.json" "$REG/acme/$1@$2" >/dev/null 2>&1; }
sign_v3() { "$COSIGN_V3" sign --key "$W/keys/cosign.key" -y --signing-config "$W/keys/notlog.json" "$REG/acme/$1@$2" >/dev/null 2>&1; }
attest_v3() { "$COSIGN_V3" attest --key "$W/keys/cosign.key" -y --signing-config "$W/keys/notlog.json" --type "$3" --predicate "$W/sbom.$3.json" "$REG/acme/$1@$2" >/dev/null 2>&1; }

log "build imagegate"
(cd "$ROOT" && go build -o "$W/imagegate" ./cmd/imagegate)
mkdir -p "$W/overrides.d" "$W/registry" "$W/keys"
(cd "$W/keys" && "$COSIGN" generate-key-pair >/dev/null 2>&1 && mkdir other && cd other && "$COSIGN" generate-key-pair >/dev/null 2>&1)
mv "$W/keys/other/cosign.key" "$W/keys/other.key"
echo '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"e2e","dataLicense":"CC0-1.0","documentNamespace":"https://e2e","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: e2e"]},"packages":[]}' >"$W/sbom.spdxjson.json"
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}' >"$W/sbom.cyclonedx.json"
if [ -n "$COSIGN_V3" ]; then
  "$COSIGN_V3" signing-config create --no-default-fulcio --no-default-rekor --no-default-oidc --no-default-tsa --out "$W/keys/notlog.json" >/dev/null
fi
write_policy enforce

log "start imagegate and a dedicated dockerd"
start_imagegate
dockerd --data-root "$W/data" --exec-root "$W/exec" -H "$DOCKER_HOST" --pidfile "$W/docker.pid" \
  --authorization-plugin "$PLUGIN" --iptables=false --ip6tables=false --bridge=none \
  >"$W/dockerd.log" 2>&1 &
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 0.5; done
docker info >/dev/null

log "registry (allowed through a break-glass override)"
docker pull -q ghcr.io/project-zot/zot-minimal-linux-amd64:v2.1.5 >/dev/null
docker pull -q "$BASE" >/dev/null
ZOT=$(docker image inspect ghcr.io/project-zot/zot-minimal-linux-amd64:v2.1.5 --format '{{index .RepoDigests 0}}')
cat >"$W/overrides.d/zot.yaml" <<EOF
- digest: ${ZOT#*@}
  expires: $(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
  ticket: E2E-1
  reason: test registry
EOF
reload
mkdir -p "$W/zot"
cat >"$W/zot/config.json" <<EOF
{"storage":{"rootDirectory":"/var/lib/registry"},"http":{"address":"127.0.0.1","port":"$PORT"},"log":{"level":"error"}}
EOF
docker run -d --name zot --network host -v "$W/zot/config.json:/etc/zot/config.json:ro" \
  ghcr.io/project-zot/zot-minimal-linux-amd64:v2.1.5 >/dev/null
for _ in $(seq 1 50); do curl -fs "http://$REG/v2/" >/dev/null && break; sleep 0.2; done
grep -q '"reason":"OVERRIDE"' "$W/audit.log" && grep -q '"ticket":"E2E-1"' "$W/audit.log" \
  && { echo "PASS  override used and audited"; pass=$((pass + 1)); } || { echo "FAIL  override audit"; fail=$((fail + 1)); }

log "fixtures"
D_SPDX=$(build_push spdx spdx); sign_v2 spdx "$D_SPDX"; attest_v2 spdx "$D_SPDX" spdxjson
D_CDX=$(build_push cdx cdx); sign_v2 cdx "$D_CDX"; attest_v2 cdx "$D_CDX" cyclonedx
D_NOSBOM=$(build_push nosbom nosbom); sign_v2 nosbom "$D_NOSBOM"
D_UNSIGNED=$(build_push unsigned unsigned)
D_OTHER=$(build_push otherkey otherkey); sign_v2 otherkey "$D_OTHER" other; attest_v2 otherkey "$D_OTHER" spdxjson
printf 'FROM %s\nRUN echo local > /id\n' "$BASE" | docker build -q --network host -t "$REG/acme/local:1" - >/dev/null
if [ -n "$COSIGN_V3" ]; then
  D_V3=$(build_push v3 v3); sign_v3 v3 "$D_V3"; attest_v3 v3 "$D_V3" spdxjson
  D_V3NOSBOM=$(build_push v3nosbom v3nosbom); sign_v3 v3nosbom "$D_V3NOSBOM"
fi

log "test matrix"
expect "signed, signed SPDX attestation (cosign v2 tags)" allow "$REG/acme/spdx:1"
expect "signed, signed CycloneDX attestation" allow "$REG/acme/cdx:1"
expect "pinned by digest" allow "$REG/acme/spdx@$D_SPDX"
expect "signed, no attestation" NO_SBOM "$REG/acme/nosbom:1"
expect "unsigned" NO_SIGNATURE "$REG/acme/unsigned:1"
expect "signed by another key" IDENTITY_MISMATCH "$REG/acme/otherkey:1"
expect "built locally" LOCAL_IMAGE "$REG/acme/local:1"
expect "no matching rule" NO_RULE "$BASE"
if [ -n "$COSIGN_V3" ]; then
  expect "signed, signed SPDX attestation (cosign v3 bundles)" allow "$REG/acme/v3:1"
  expect "signed, no attestation (cosign v3)" NO_SBOM "$REG/acme/v3nosbom:1"
fi
if docker buildx build --network host --sbom=true --push -q -t "$REG/acme/buildkit:1" - >/dev/null 2>&1 <<<"$(printf 'FROM %s\nRUN echo bk > /id\n' "$BASE")"; then
  D_BK=$(digest_of acme/buildkit:1); sign_v2 buildkit "$D_BK"
  expect "signed, BuildKit SBOM attached but unsigned" SBOM_UNTRUSTED "$REG/acme/buildkit:1"
else
  echo "SKIP  BuildKit --sbom (buildx cannot push SBOM attestations here)"
fi

log "overrides"
cat >"$W/overrides.d/hotfix.yaml" <<EOF
- digest: $D_NOSBOM
  expires: $(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
  ticket: INC-4821
  reason: vendor hotfix
EOF
reload
expect "valid override for digest" allow "$REG/acme/nosbom:1"
cat >"$W/overrides.d/hotfix.yaml" <<EOF
- digest: $D_NOSBOM
  expires: $(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)
  ticket: INC-4821
EOF
reload
expect "expired override" NO_SBOM "$REG/acme/nosbom:1"

log "audit mode and the start re-check"
write_policy audit; reload
expect "audit mode allows, logs would-be deny" allow "$REG/acme/unsigned:1"
grep -q '"decision":"deny","mode":"audit","reason":"NO_SIGNATURE"' "$W/audit.log" \
  && { echo "PASS  audit record shows would-be deny"; pass=$((pass + 1)); } || { echo "FAIL  audit record"; fail=$((fail + 1)); }
docker create --name pre-existing "$REG/acme/unsigned:1" true >/dev/null
write_policy enforce; reload
if out=$(docker start pre-existing 2>&1); then
  echo "FAIL  start re-check: container created under audit started under enforce"; fail=$((fail + 1))
elif grep -q "NO_SIGNATURE" <<<"$out"; then
  echo "PASS  start re-check denies a container created before enforcement"; pass=$((pass + 1))
else
  echo "FAIL  start re-check: $out"; fail=$((fail + 1))
fi

log "invalid policy reload keeps the last good policy"
cp "$W/policy.yaml" "$W/policy.good"; echo "apiVersion: broken" >"$W/policy.yaml"; reload
expect "last good policy still enforced" NO_SIGNATURE "$REG/acme/unsigned:1"
expect "last good policy still allows" allow "$REG/acme/spdx:1"
cp "$W/policy.good" "$W/policy.yaml"; reload

log "cache, warm and purge"
check "warm pre-verifies a signed image" "$W/imagegate" warm -admin-socket "$W/admin.sock" "$REG/acme/cdx:1"
check "cache purge" "$W/imagegate" cache purge -admin-socket "$W/admin.sock"
expect "re-verified after purge" allow "$REG/acme/spdx:1"

log "raw API paths dockerd routes to create/start"
for path in /v1.45.0/containers/create /v1/containers/create /v1.45.0.1/containers/create; do
  out=$(curl -s --unix-socket "$W/docker.sock" -X POST -H 'Content-Type: application/json' \
    -d "{\"Image\":\"$REG/acme/unsigned:1\"}" "http://d$path")
  if grep -q "authorization denied" <<<"$out"; then
    echo "PASS  POST $path is gated"; pass=$((pass + 1))
  else
    echo "FAIL  POST $path bypassed imagegate: $out"; fail=$((fail + 1))
  fi
done
docker create --name signed "$REG/acme/spdx:1" true >/dev/null
out=$(curl -s --unix-socket "$W/docker.sock" -X POST "http://d/v1.45/containers/signed/x/start")
grep -q "authorization denied" <<<"$out" \
  && { echo "PASS  start of a name containing / is gated"; pass=$((pass + 1)); } \
  || { echo "FAIL  start of a name containing / bypassed imagegate: $out"; fail=$((fail + 1)); }

log "management calls are never blocked"
check "docker ps" docker ps
check "docker info" docker info
check "docker images" docker images

log "chaos: imagegate down means dockerd rejects every call (lockout runbook)"
kill "$(cat "$W/imagegate.pid")"; sleep 0.5
if docker info >/dev/null 2>&1; then
  echo "NOTE  dockerd answered with the plugin down"
else
  echo "PASS  dockerd refuses API calls while the plugin is unreachable (see docs/runbook.md)"; pass=$((pass + 1))
fi
start_imagegate
check "recovers when imagegate restarts" docker info
expect "allowed again after restart (persistent cache)" allow "$REG/acme/spdx:1"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
