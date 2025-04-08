# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET=cilium

all: $(TARGET)

.PHONY: all $(TARGET) local-release install clean test bench clean-tags tags


PREFIX=/usr/local
CLI_VERSION=$(shell git describe --tags --always)
CLI_MAIN_DIR?=./cmd/cilium
GO_BUILD_LDFLAGS += -X "github.com/cilium/cilium/cilium-cli/defaults.CLIVersion=$(CLI_VERSION)"

# Kept for bakwards compatibility with previous usage of GO_TAGS
GO_TAGS_FLAGS += $(GO_TAGS)

TEST_TIMEOUT ?= 5s

$(TARGET):
	$(GO_BUILD) \
		-o $(@) \
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
			env GOOS=$$OS GOARCH=$$ARCH $(GO_BUILD) \
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
	$(GO_TEST) -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

bench:
	$(GO_TEST) -timeout=30s -bench=. $$($(GO) list ./...)

clean-tags:
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $$($(GO) list ./...)
	@ctags $<
	cscope -R -b -q


-include Makefile.override
