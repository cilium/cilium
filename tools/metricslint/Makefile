# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := metricslint

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(wildcard *.go */*.go */*/*.go)
	@$(ECHO_GO)
	$(QUIET)CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $@

test:
	@$(ECHO_TEST)
	$(GO_TEST) ./pkg/analyzer/ | $(GOTEST_FORMATTER)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)

install: all
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
