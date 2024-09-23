# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO := go
GO_BUILD = CGO_ENABLED=0 $(GO) build
GO_TAGS ?=
TARGET=cilium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CLI_VERSION=$(shell git describe --tags --always)
THIS_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CILIUM_VERSION=$(shell cat $(THIS_DIR)/../stable.txt)
CLI_MAIN_DIR?=./cmd/cilium
STRIP_DEBUG=-w -s
ifdef DEBUG
	STRIP_DEBUG=
endif
GO_BUILD_LDFLAGS ?= $(STRIP_DEBUG) \
	-X 'github.com/cilium/cilium/cilium-cli/defaults.CLIVersion=$(CLI_VERSION)' \
	-X 'github.com/cilium/cilium/cilium-cli/defaults.Version=$(CILIUM_VERSION)'

TEST_TIMEOUT ?= 5s

$(TARGET):
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "$(GO_BUILD_LDFLAGS)" \
		-o $(TARGET) \
		$(CLI_MAIN_DIR)

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
				-o release/$$OS/$$ARCH/$(TARGET)$$EXT $(CLI_MAIN_DIR); \
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

.PHONY: $(TARGET) local-release install clean test bench check clean-tags tags

-include Makefile.override
