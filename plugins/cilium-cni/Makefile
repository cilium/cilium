# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")

include $(ROOT_DIR)/../../Makefile.defs

TARGET := cilium-cni

.PHONY: all
all: $(TARGET)

.PHONY: $(TARGET)
$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

.PHONY: install
install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNIBINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(CNIBINDIR)

.PHONY: install-binary
install-binary: install

.PHONY: install-bash-completion
install-bash-completion:
