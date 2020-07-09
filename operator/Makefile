# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGETS := cilium-operator cilium-operator-generic cilium-operator-aws cilium-operator-azure

.PHONY: all $(TARGETS) clean install

all: $(TARGETS)

cilium-operator: OPERATOR_TAGS=ipam_provider_aws,ipam_provider_azure,ipam_provider_operator
cilium-operator-generic: OPERATOR_TAGS=ipam_provider_operator
cilium-operator-aws: OPERATOR_TAGS=ipam_provider_aws
cilium-operator-azure: OPERATOR_TAGS=ipam_provider_azure

$(TARGETS):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -tags $(OPERATOR_TAGS) -o $(@)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGETS)
	$(GO) clean $(GOCLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(foreach target,$(TARGETS), $(QUIET)$(INSTALL) -m 0755 $(target) $(DESTDIR)$(BINDIR);)
