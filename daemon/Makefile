# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := cilium-agent

all: $(TARGET)

.PHONY: all $(TARGET)

$(TARGET): ../Makefile ../Makefile.defs Makefile
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

ifeq ("$(PKG_BUILD)","")

install:
	groupadd -f cilium
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:

else

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:

endif
