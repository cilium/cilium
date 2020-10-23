# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

HUBBLE_PROXY_VERSION := "v1.14.5"
HUBBLE_UI_VERSION := "v0.7.2"
MANAGED_ETCD_VERSION := "v2.0.7"
NODEINIT_VERSION := "62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
CERTGEN_VERSION := "v0.1.2@sha256:c56e1cd89e6f49a9fa442ad129974e2addfc687ef6ac524ee26849162425c489"

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
EXPERIMENTAL_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/experimental-install.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_PULLPOLICY_REGEX := '\([pP]ullPolicy:\) .*'
QUICK_OPTIONS := \
    --set hubble.tls.enabled=false
EXPERIMENTAL_OPTIONS := \
    --set hubble.enabled=true \
    --set hubble.listenAddress=":4244" \
    --set hubble.tls.auto.enabled=true \
    --set hubble.tls.auto.method="cronJob" \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --set localRedirectPolicy=true \
    --set bandwidthManager=true \
    --set externalWorkloads.enabled=true \
    --set clustermesh.apiserver.tls.auto.method="cronJob"

DOCKER_RUN := $(CONTAINER_ENGINE) container run --rm \
	--workdir /src/install/kubernetes \
	--volume $(CURDIR)/../..:/src \
	--user "$(shell id -u):$(shell id -g)"

HELM_DOCS_VERSION := "v1.3.0"
HELM_DOCS_SHA := "12f065115654c9a1d6819b938487d327f1fdb5c32bdc2a5c74afef22ed68f5ca"
HELM_DOCS_IMAGE := "docker.io/jnorwood/helm-docs:$(HELM_DOCS_VERSION)@sha256:$(HELM_DOCS_SHA)"
HELM_DOCS := $(DOCKER_RUN) $(HELM_DOCS_IMAGE)

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

$(QUICK_INSTALL) quick-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(QUICK_OPTIONS) > $(QUICK_INSTALL)

$(EXPERIMENTAL_INSTALL) experimental-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g'
	@# Fix up the container image tags
	$(QUIET)$(shell														\
		cilium_version="v$(VERSION)";											\
		hubble_version=$(HUBBLE_UI_VERSION);										\
		pull_policy="IfNotPresent";											\
		if echo "$(VERSION)" | grep -q $(LATEST_VERSION_REGEX); then							\
			cilium_version="latest";										\
			hubble_version="latest";										\
			pull_policy="Always";											\
		elif echo "$(VERSION)" | grep -q $(DEV_VERSION_REGEX); then							\
			cilium_version="v$(subst -dev,,$(VERSION))";								\
			hubble_version="$(HUBBLE_UI_VERSION)";									\
			pull_policy="Always";											\
		fi;														\
		# image.tag operator.image.tag preflight.image.tag hubble.relay.image.tag;					\
		sed -i 's/tag: .*/tag: '$$cilium_version'/g' $(CILIUM_VALUES);							\
		# hubble.ui.frontend.image.tag hubble.ui.backend.image.tag;							\
		sed -i '/repository.*hubble-ui.*/{!b;n;s/tag.*/tag: '$$hubble_version'/}' $(CILIUM_VALUES);			\
		# etcd.image.tag												\
		sed -i '/repository.*etcd-operator.*/{!b;n;s/tag.*/tag: '$(MANAGED_ETCD_VERSION)'/}' $(CILIUM_VALUES)		\
		# hubble.ui.proxy.image.tag											\
		sed -i '/repository.*envoy.*/{!b;n;s/tag.*/tag: '$(HUBBLE_PROXY_VERSION)'/}' $(CILIUM_VALUES)			\
		# nodeinit.image.tag												\
		sed -i '/repository.*cilium\/startup-script.*/{!b;n;s/tag.*/tag: '$(NODEINIT_VERSION)'/}' $(CILIUM_VALUES)	\
		# certgen.image.tag										\
		sed -i '/repository.*certgen.*/{!b;n;s/tag.*/tag: '$(CERTGEN_VERSION)'/}' $(CILIUM_VALUES);			\
		sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 '$$pull_policy'/' $$chart;						\
	)

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

docs:
	$(QUIET)$(HELM_DOCS)

.PHONY: all clean update-versions lint quick-install experimental-install docs
