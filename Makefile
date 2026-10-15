VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test e2e docs docs-serve docs-contrast snapshot

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/imagegate ./cmd/imagegate

test:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	go test -race ./...

# Needs root, dockerd and cosign; see test/e2e/run.sh.
e2e:
	sudo -E ./test/e2e/run.sh

docs:
	mkdocs build --strict

docs-serve:
	mkdocs serve

# WCAG AA contrast on every page, both schemes, phone width (needs Node + Playwright).
docs-contrast: docs
	@cd site && python3 -m http.server 8799 >/dev/null 2>&1 & pid=$$!; sleep 1; \
	node docs/tools/contrast-check.cjs http://127.0.0.1:8799/; rc=$$?; kill $$pid; exit $$rc

# Local GoReleaser build of every artifact into dist/ (needs goreleaser,
# syft, and docker buildx for images).
snapshot:
	goreleaser release --snapshot --clean --skip=sign
