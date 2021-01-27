GO := CGO_ENABLED=0 go
GO_TAGS ?=
TARGET=cilium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell cat VERSION)
GIT_BRANCH = $(shell which git >/dev/null 2>&1 && git rev-parse --abbrev-ref HEAD)
GIT_HASH = $(shell which git >/dev/null 2>&1 && git rev-parse --short HEAD)

TEST_TIMEOUT ?= 5s

$(TARGET):
	$(GO) build $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/cilium/cilium-cli/internal/cli/cmd.GitBranch=${GIT_BRANCH}' \
		-X 'github.com/cilium/cilium-cli/internal/cli/cmd.GitHash=$(GIT_HASH)' \
		-X 'github.com/cilium/cilium-cli/internal/cli/cmd.Version=${VERSION}'" \
		-o $(TARGET) \
		./cmd/cilium

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)

test:
	go test -timeout=$(TEST_TIMEOUT) -race -cover $$(go list ./...)

bench:
	go test -timeout=30s -bench=. $$(go list ./...)

.PHONY: $(TARGET) install clean test bench
