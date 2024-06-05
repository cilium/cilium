# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO := go
GO_BUILD = CGO_ENABLED=0 $(GO) build
GO_TAGS ?=
TARGET=cilium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)
STRIP_DEBUG=-w -s
ifdef DEBUG
	STRIP_DEBUG=
endif
GO_BUILD_LDFLAGS ?= $(STRIP_DEBUG) -X 'github.com/cilium/cilium-cli/defaults.CLIVersion=$(VERSION)'

TEST_TIMEOUT ?= 5s
RELEASE_UID ?= $(shell id -u)
RELEASE_GID ?= $(shell id -g)

# renovate: datasource=docker depName=golang
GO_IMAGE_VERSION = 1.22.4-alpine3.19
GO_IMAGE_SHA = sha256:65b5d2d0a312fd9ef65551ad7f9cb5db1f209b7517ef6d5625cfd29248bc6c85

# renovate: datasource=docker depName=golangci/golangci-lint
GOLANGCILINT_WANT_VERSION = v1.59.0
GOLANGCILINT_IMAGE_SHA = sha256:8ad7dc3d98d77dec753f07408c7683ab854752a3eb8dc6a5e5f0728f9a89ae2c
GOLANGCILINT_VERSION = $(shell golangci-lint version --format short 2>/dev/null)

$(TARGET):
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "$(GO_BUILD_LDFLAGS)" \
		-o $(TARGET) \
		./cmd/cilium

release:
	docker run \
		--rm \
		--workdir /cilium \
		--volume `pwd`:/cilium docker.io/library/golang:$(GO_IMAGE_VERSION)@$(GO_IMAGE_SHA) \
		sh -c "apk add --no-cache setpriv make git zip && \
			/usr/bin/setpriv --reuid=$(RELEASE_UID) --regid=$(RELEASE_GID) --clear-groups make GOCACHE=/tmp/gocache local-release"

local-release: clean
	set -o errexit; \
	for OS in darwin linux windows; do \
		EXT=; \
		ARCHS=; \
		case $$OS in \
			darwin) \
				ARCHS='amd64 arm64'; \
				;; \
			linux) \
				ARCHS='amd64 arm64'; \
				;; \
			windows) \
				ARCHS='amd64 arm64'; \
				EXT=".exe"; \
				;; \
		esac; \
		for ARCH in $$ARCHS; do \
			echo Building release binary for $$OS/$$ARCH...; \
			test -d release/$$OS/$$ARCH|| mkdir -p release/$$OS/$$ARCH; \
			env GOOS=$$OS GOARCH=$$ARCH $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
				-ldflags "$(GO_BUILD_LDFLAGS)" \
				-o release/$$OS/$$ARCH/$(TARGET)$$EXT ./cmd/cilium; \
			if [ $$OS = "windows" ]; \
			then \
				zip -j release/$(TARGET)-$$OS-$$ARCH.zip release/$$OS/$$ARCH/$(TARGET)$$EXT; \
				(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.zip > $(TARGET)-$$OS-$$ARCH.zip.sha256sum); \
			else \
				tar -czf release/$(TARGET)-$$OS-$$ARCH.tar.gz -C release/$$OS/$$ARCH $(TARGET)$$EXT; \
				(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.tar.gz > $(TARGET)-$$OS-$$ARCH.tar.gz.sha256sum); \
			fi; \
		done; \
		rm -rf release/$$OS; \
	done; \

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

clean-tags:
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $$($(GO) list ./...)
	@ctags $<
	cscope -R -b -q

ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION:v%=%),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	docker run --rm -v `pwd`:/app -w /app docker.io/golangci/golangci-lint:$(GOLANGCILINT_WANT_VERSION) golangci-lint run
endif

.PHONY: $(TARGET) release local-release install clean test bench check clean-tags tags

-include Makefile.override
