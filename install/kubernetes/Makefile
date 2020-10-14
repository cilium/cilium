# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

# Workaround until we branch for v1.9
VERSION := 1.8.90

MANAGED_ETCD_VERSION := "v2.0.7"

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
EXPERIMENTAL_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/experimental-install.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_TAG_REGEX := '\(tag:\) \(v'$(VERSION_REGEX)'\|latest\)'
CILIUM_PULLPOLICY_REGEX := '\([pP]ullPolicy:\) .*'
EXPERIMENTAL_OPTIONS := \
    --set hubble.enabled=true \
    --set hubble.listenAddress=":4244" \
    --set hubble.tls.enabled=false \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --set bandwidthManager=true

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

$(QUICK_INSTALL) quick-install: $(shell find cilium/ -type f)
	$(QUIET)helm template cilium cilium --namespace=kube-system > $(QUICK_INSTALL)

$(EXPERIMENTAL_INSTALL) experimental-install: $(shell find cilium/ -type f)
	$(QUIET)helm template cilium cilium --namespace=kube-system $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g'
	@# Fix up the cilium tag
	$(QUIET)$(shell											\
		if echo $(VERSION) | grep -q $(LATEST_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 latest/' $$chart;				\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $$chart;			\
		elif echo $(VERSION) | grep -q $(DEV_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(subst -dev,,$(VERSION))/' $$chart;	\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $$chart;			\
		else											\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(VERSION)/' $$chart;			\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 IfNotPresent/' $$chart;		\
		fi;											\
	)

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

.PHONY: all clean update-versions lint quick-install experimental-install
