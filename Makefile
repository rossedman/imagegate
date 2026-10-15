.PHONY: build test e2e vet

build:
	go build -o bin/imagegate ./cmd/imagegate

test:
	go vet ./...
	go test -race ./...

# Needs root, dockerd and cosign; see test/e2e/run.sh.
e2e:
	sudo -E ./test/e2e/run.sh
