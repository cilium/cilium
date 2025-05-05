# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

CURR_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")

include $(CURR_DIR)/../Makefile.defs

TARGET := cilium-bugtool

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f .cilium-bugtool.config $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:
