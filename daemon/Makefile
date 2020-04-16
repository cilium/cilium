# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := cilium-agent
LINKS := cilium-node-monitor

all: $(TARGET) links

.PHONY: all $(TARGET) links

$(TARGET): ../Dockerfile ../Makefile ../Makefile.defs Makefile
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)

links:
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(link) || cp $(TARGET) $(link);)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)
	$(foreach link,$(LINKS), $(QUIET)rm -f $(link);)

ifeq ("$(PKG_BUILD)","")

install:
	groupadd -f cilium
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link) || cp $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

else

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link) || cp $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

endif
