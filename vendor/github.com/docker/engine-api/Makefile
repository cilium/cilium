.PHONY: all deps test validate lint

all: deps test validate

deps:
	go get -t ./...
	go get -u github.com/golang/lint/golint

test:
	go test -tags experimental -race -cover ./...

validate: lint
	go vet ./...
	test -z "$(gofmt -s -l . | tee /dev/stderr)"

lint:
	out="$$(golint ./...)"; \
	if [ -n "$$(golint ./...)" ]; then \
		echo "$$out"; \
		exit 1; \
	fi
