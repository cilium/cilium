# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

HUBBLE_PROXY_VERSION := "v1.14.5"
HUBBLE_UI_VERSION := "v0.7.3"
MANAGED_ETCD_VERSION := "v2.0.7"
ETCD_VERSION := "v3.4.13"
NODEINIT_VERSION := "62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
CERTGEN_VERSION := "v0.1.3"

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
QUICK_HUBBLE_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-hubble-install.yaml"
EXPERIMENTAL_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/experimental-install.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"
CHART_FILE := "$(CILIUM_CHARTS)/Chart.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_PULLPOLICY_REGEX := '\([pP]ullPolicy:\) .*'
QUICK_OPTIONS := \
    --set hubble.tls.auto.enabled=false \
    --set operator.replicas=1
QUICK_HUBBLE_OPTIONS := \
    --set agent=false \
    --set operator.enabled=false \
    --set hubble.tls.auto.enabled=true \
    --set hubble.tls.auto.method="cronJob" \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true
EXPERIMENTAL_OPTIONS := \
    --set hubble.tls.auto.enabled=true \
    --set hubble.tls.auto.method="cronJob" \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --set localRedirectPolicy=true \
    --set operator.replicas=1

DOCKER_RUN := $(CONTAINER_ENGINE) container run --rm \
	--workdir /src/install/kubernetes \
	--volume $(CURDIR)/../..:/src \
	--user "$(shell id -u):$(shell id -g)"

HELM_DOCS_VERSION := "v1.3.0"
HELM_DOCS_SHA := "12f065115654c9a1d6819b938487d327f1fdb5c32bdc2a5c74afef22ed68f5ca"
HELM_DOCS_IMAGE := "docker.io/jnorwood/helm-docs:$(HELM_DOCS_VERSION)@sha256:$(HELM_DOCS_SHA)"
HELM_DOCS := $(DOCKER_RUN) $(HELM_DOCS_IMAGE)

LOGO_BASE_URL := https://cdn.jsdelivr.net/gh/cilium
LOGO_PATH := Documentation/images/logo-solo.svg

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL) $(QUICK_HUBBLE_INSTALL) docs

$(QUICK_INSTALL) quick-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(QUICK_OPTIONS) > $(QUICK_INSTALL)

$(QUICK_HUBBLE_INSTALL) quick-hubble-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(QUICK_HUBBLE_OPTIONS) > $(QUICK_HUBBLE_INSTALL)

$(EXPERIMENTAL_INSTALL) experimental-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g';						\
		# Fix up the container image tags										\
		cilium_version="v$(VERSION)";											\
		branch="$$cilium_version";											\
		hubble_version=$(HUBBLE_UI_VERSION);										\
		pull_policy="IfNotPresent";											\
		if echo "$(VERSION)" | grep -q $(LATEST_VERSION_REGEX); then							\
			cilium_version="latest";										\
			branch="master";											\
			hubble_version="latest";										\
			pull_policy="Always";											\
		elif echo "$(VERSION)" | grep -q $(DEV_VERSION_REGEX); then							\
			cilium_version="v$(subst -dev,,$(VERSION))";								\
			branch="$$cilium_version";										\
			hubble_version="$(HUBBLE_UI_VERSION)";									\
			pull_policy="Always";											\
		fi;														\
		sed -i 's;icon:.*;icon: $(LOGO_BASE_URL)/cilium@'$$branch'/$(LOGO_PATH);' $(CHART_FILE);			\
		# image.tag operator.image.tag preflight.image.tag hubble.relay.image.tag;					\
		sed -i 's/tag: .*/tag: '$$cilium_version'/g' $(CILIUM_VALUES);							\
		# hubble.ui.frontend.image.tag hubble.ui.backend.image.tag;							\
		sed -i '/repository.*hubble-ui.*/{!b;n;s/tag.*/tag: '$$hubble_version'/}' $(CILIUM_VALUES);			\
		# etcd.image.tag												\
		sed -i '/repository.*etcd-operator.*/{!b;n;s/tag.*/tag: '$(MANAGED_ETCD_VERSION)'/}' $(CILIUM_VALUES)		\
		# clustermesh.apiserver.etcd.image.tag										\
		sed -i '/repository.*etcd$$/{!b;n;s/tag.*/tag: '$(ETCD_VERSION)'/}' $(CILIUM_VALUES)			\
		# hubble.ui.proxy.image.tag											\
		sed -i '/repository.*envoy.*/{!b;n;s/tag.*/tag: '$(HUBBLE_PROXY_VERSION)'/}' $(CILIUM_VALUES)			\
		# nodeinit.image.tag												\
		sed -i '/repository.*cilium\/startup-script.*/{!b;n;s/tag.*/tag: '$(NODEINIT_VERSION)'/}' $(CILIUM_VALUES)	\
		# certgen.image.tag												\
		sed -i '/repository.*certgen.*/{!b;n;s/tag.*/tag: '$(CERTGEN_VERSION)'/}' $(CILIUM_VALUES);			\
		sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 '$$pull_policy'/' $(CILIUM_VALUES);

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

docs:
	$(QUIET)$(HELM_DOCS)

check-docker-images:
	$(QUIET)\
         HUBBLE_PROXY_VERSION=$(HUBBLE_PROXY_VERSION) \
         HUBBLE_UI_VERSION=$(HUBBLE_UI_VERSION) \
         MANAGED_ETCD_VERSION=$(MANAGED_ETCD_VERSION) \
         ETCD_VERSION=$(ETCD_VERSION) \
         NODEINIT_VERSION=$(NODEINIT_VERSION) \
         CERTGEN_VERSION=$(CERTGEN_VERSION) \
         ../../contrib/release/check-docker-images.sh "v$(VERSION)"

.PHONY: all check-docker-images clean docs experimental-install lint quick-install update-versions
