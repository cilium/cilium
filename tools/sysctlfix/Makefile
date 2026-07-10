# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := cilium-sysctlfix

.PHONY: all $(TARGET) $(SUBDIRS) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:
