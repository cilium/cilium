.PHONY: all build test test-race bench

all: build test test-race bench

build:
	go build ./...

test:
	go test ./... -cover

test-race:
	go test -race ./...

bench:
	go test ./... -bench . -test.run xxx
