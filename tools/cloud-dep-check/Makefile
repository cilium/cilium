# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := cilium-cloud-dep-check

.PHONY: all $(TARGET) clean install check

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

# `make check` builds the linter and runs it against the cilium repository
# root, verifying that each cilium-operator-* binary variant only contains
# its own cloud-provider SDK dependencies.
check: $(TARGET)
	$(QUIET)./$(TARGET) -root ../..

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

