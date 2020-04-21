# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

# Build all ipam managers in development environments
ifeq ($(PKG_BUILD),)
	EXTRA_GO_BUILD_FLAGS += -tags operator_aws,operator_azure,ipam_provider_operator
endif

TARGET := cilium-operator

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
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
