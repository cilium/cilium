.PHONY: all build test test-race bench

all: build test test-race bench

build:
	go build ./...

test:
	go test ./... -cover -vet=all -test.count 1

test-race:
	go test -race ./... -test.count 1

bench:
	go test ./... -bench . -benchmem -test.run xxx
	go run ./reconciler/benchmark -quiet

bench-reconciler:
	go run ./reconciler/benchmark
