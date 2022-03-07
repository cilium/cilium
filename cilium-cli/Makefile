GO := go
GO_BUILD = CGO_ENABLED=0 $(GO) build
GO_TAGS ?=
TARGET=cilium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)

TEST_TIMEOUT ?= 5s
RELEASE_UID ?= $(shell id -u)
RELEASE_GID ?= $(shell id -g)

GOLANGCILINT_WANT_VERSION = 1.42.1
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)

$(TARGET):
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/cilium/cilium-cli/internal/cli/cmd.Version=${VERSION}'" \
		-o $(TARGET) \
		./cmd/cilium

release:
	docker run \
		--env "RELEASE_UID=$(RELEASE_UID)" \
		--env "RELEASE_GID=$(RELEASE_GID)" \
		--rm \
		--workdir /cilium \
		--volume `pwd`:/cilium docker.io/library/golang:1.17.8-alpine3.15 \
		sh -c "apk add --no-cache make git && make local-release VERSION=${VERSION}"

local-release: clean
	for OS in darwin linux windows; do \
		EXT=; \
		ARCHS=; \
		case $$OS in \
			darwin) \
				ARCHS='amd64 arm64'; \
				;; \
			linux) \
				ARCHS='386 amd64 arm arm64'; \
				;; \
			windows) \
				ARCHS='386 amd64 arm64'; \
				EXT=".exe"; \
				;; \
		esac; \
		for ARCH in $$ARCHS; do \
			echo Building release binary for $$OS/$$ARCH...; \
			test -d release/$$OS/$$ARCH|| mkdir -p release/$$OS/$$ARCH; \
			env GOOS=$$OS GOARCH=$$ARCH $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) -ldflags "-w -s -X 'github.com/cilium/cilium-cli/internal/cli/cmd.Version=${VERSION}'" -o release/$$OS/$$ARCH/$(TARGET)$$EXT ./cmd/cilium; \
			tar -czf release/$(TARGET)-$$OS-$$ARCH.tar.gz -C release/$$OS/$$ARCH $(TARGET)$$EXT; \
			(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.tar.gz > $(TARGET)-$$OS-$$ARCH.tar.gz.sha256sum); \
		done; \
		rm -r release/$$OS; \
	done; \
	if [ $$(id -u) -eq 0 -a -n "$$RELEASE_UID" -a -n "$$RELEASE_GID" ]; then \
		chown -R "$$RELEASE_UID:$$RELEASE_GID" release; \
	fi

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	rm -rf ./release

test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

bench:
	$(GO) test -timeout=30s -bench=. $$($(GO) list ./...)

ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	docker run --rm -v `pwd`:/app -w /app docker.io/golangci/golangci-lint:v$(GOLANGCILINT_WANT_VERSION) golangci-lint run
endif

.PHONY: $(TARGET) release local-release install clean test bench check
