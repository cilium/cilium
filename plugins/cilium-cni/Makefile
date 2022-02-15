# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := cilium-cni

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0644 05-cilium-cni.conf $(DESTDIR)$(CNICONFDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CNIBINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(CNIBINDIR)

install-binary: install

install-bash-completion:
