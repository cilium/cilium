# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGETS := cilium-operator cilium-operator-generic cilium-operator-aws cilium-operator-azure cilium-operator-alibabacloud

.PHONY: all $(TARGETS) clean install

all: $(TARGETS)

cilium-operator: GO_TAGS_FLAGS+=ipam_provider_aws,ipam_provider_azure,ipam_provider_operator,ipam_provider_alibabacloud
cilium-operator-generic: GO_TAGS_FLAGS+=ipam_provider_operator
cilium-operator-aws: GO_TAGS_FLAGS+=ipam_provider_aws
cilium-operator-azure: GO_TAGS_FLAGS+=ipam_provider_azure
cilium-operator-alibabacloud: GO_TAGS_FLAGS+=ipam_provider_alibabacloud

$(TARGETS):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(@)

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
