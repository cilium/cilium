# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := cilium-api-flaggen

.PHONY: all $(TARGET) $(SUBDIRS) clean

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)
