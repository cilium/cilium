# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all

ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")

include ${ROOT_DIR}/../Makefile.defs

# Add the ability to override variables
# ROOT_DIR changes to repo root after including Makefile.defs
-include ${ROOT_DIR}/Makefile.override

TARGET := cilium-agent
DBGTARGET := cilium-dbg
DBGTARGET_OLD := cilium

all: $(TARGET)

.PHONY: all $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)
	$(QUIET)ln -frs $(TARGET) $(DBGTARGET)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET) $(DBGTARGET)
	$(QUIET)$(GO_CLEAN)


ifeq ("$(PKG_BUILD)","")
install:
	groupadd -f cilium
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
else
install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
endif

install-binary: install install-dbg

install-bash-completion: $(TARGET) 
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(DBGTARGET) completion bash > $(DBGTARGET)_bash_completion
	$(QUIET)$(INSTALL) -m 0644 -T $(DBGTARGET)_bash_completion $(DESTDIR)$(CONFDIR)/bash_completion.d/$(DBGTARGET)

install-dbg: install
	$(QUIET)ln -frs $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(DBGTARGET)
	$(QUIET)ln -frs $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(DBGTARGET_OLD)

