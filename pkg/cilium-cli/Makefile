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

$(TARGET):
	$(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "$(GO_BUILD_LDFLAGS)" \
		-o $(TARGET) \
		./cmd/cilium

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)

test:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -cover $$($(GO) list ./...)

bench:
	$(GO) test -timeout=30s -bench=. $$($(GO) list ./...)

clean-tags:
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $$($(GO) list ./...)
	@ctags $<
	cscope -R -b -q

.PHONY: $(TARGET) install clean test bench clean-tags tags

-include Makefile.override
