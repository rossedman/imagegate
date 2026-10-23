VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint cover vuln doccheck bench bench-smoke fuzz check e2e docs docs-serve docs-contrast snapshot

GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
FUZZTIME ?= 30s

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/imagegate ./cmd/imagegate

test:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	go test -race ./...

lint:
	golangci-lint run ./...

# Race tests with a coverage profile, then the 90% gate on hand-written code.
cover:
	go test -race -coverprofile=coverage.out ./...
	tools/cover.sh coverage.out 90

vuln:
	go run $(GOVULNCHECK) ./...

doccheck:
	go run ./tools/doccheck ./...

# Saves results for benchstat: benchstat old.txt bench.txt
bench:
	go test -run='^$$' -bench=. -benchmem -count=6 ./... | tee bench.txt

bench-smoke:
	go test -run='^$$' -bench=. -benchtime=1x ./...

# Every Fuzz* target for FUZZTIME each (make fuzz FUZZTIME=5m).
fuzz:
	FUZZTIME=$(FUZZTIME) tools/fuzz.sh

# Everything CI runs, except the e2e suite (needs root) and with shorter
# fuzzing; docs needs mkdocs (pip install -r docs/requirements.txt).
check: test lint cover vuln doccheck bench-smoke
	$(MAKE) fuzz FUZZTIME=10s
	goreleaser check
	$(MAKE) docs

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
