# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := cilium-cni

.PHONY: all
all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

.PHONY: install
install: install-binary
	$(QUIET)$(INSTALL) -m 0644 05-cilium-cni.conf $(DESTDIR)$(CNICONFDIR)

.PHONY: install-binary
install-binary:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNIBINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(CNIBINDIR)

.PHONY: install-bash-completion
install-bash-completion:
