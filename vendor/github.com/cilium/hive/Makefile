.PHONY: all build test test-race bench

all: build test test-race bench

build:
	go build ./...

test:
	go test ./... -cover -test.count 1

test-race:
	go test -race ./... -test.count 1

bench:
	go test ./... -bench . -test.run xxx
