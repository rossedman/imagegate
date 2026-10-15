VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test e2e docs docs-serve snapshot

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

# Local GoReleaser build of every artifact into dist/ (needs goreleaser,
# syft, and docker buildx for images).
snapshot:
	goreleaser release --snapshot --clean --skip=sign
