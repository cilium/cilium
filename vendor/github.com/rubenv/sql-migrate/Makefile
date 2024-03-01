.PHONY: test lint build

test:
	go test ./...

lint:
	golangci-lint run --fix --config .golangci.yaml

build:
	mkdir -p bin
	go build -o ./bin/sql-migrate ./sql-migrate
