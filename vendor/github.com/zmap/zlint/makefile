SHELL := /bin/bash

CMDS = zlint zlint-gtld-update
CMD_PREFIX = ./cmd/
GO_ENV = GO111MODULE="on" GOFLAGS="-mod=vendor"
BUILD = $(GO_ENV) go build
TEST = $(GO_ENV) GORACE=halt_on_error=1 go test -race

all: $(CMDS)

zlint:
	$(BUILD) $(CMD_PREFIX)$(@)

zlint-gtld-update:
	$(BUILD) $(CMD_PREFIX)$(@)

clean:
	rm -f $(CMDS)

test:
	$(TEST) ./...

format-check:
	diff <(find . -name '*.go' -not -path './vendor/*' -print | xargs -n1 gofmt -l) <(printf "")

.PHONY: clean zlint zlint-gtld-update test format-check
