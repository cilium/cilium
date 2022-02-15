# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := clustermesh-apiserver

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install: install-binary install-bash-completion-only

install-binary:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-bash-completion: $(TARGET) install-bash-completion-only

install-bash-completion-only:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > $(TARGET)_bash_completion
	$(QUIET)$(INSTALL) -m 0644 -T $(TARGET)_bash_completion $(DESTDIR)$(CONFDIR)/bash_completion.d/$(TARGET)
