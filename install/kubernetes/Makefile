# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.digests ../../Makefile.defs

HUBBLE_UI_VERSION := "v0.9.0@sha256:0ef04e9a29212925da6bdfd0ba5b581765e41a01f1cc30563cef9b30b457fea0"
HUBBLE_UI_BACKEND_VERSION := "v0.9.0@sha256:000df6b76719f607a9edefb9af94dfd1811a6f1b6a8a9c537cba90bf12df474b"
MANAGED_ETCD_VERSION := "v2.0.7"
ETCD_VERSION := "v3.4.13"
NODEINIT_VERSION := "62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
CERTGEN_VERSION := "v0.1.5"

MIN_K8S_MAJOR := 1
MIN_K8S_MINOR := 16
MIN_K8S_VERSION := "v$(MIN_K8S_MAJOR).$(MIN_K8S_MINOR).0"

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
    --set bandwidthManager=true \
    --set operator.replicas=1

USE_DIGESTS ?= $(shell if grep -q '""' Makefile.digests; then echo "false"; else echo "true"; fi)
ifeq ($(USE_DIGESTS),false)
DIGEST_OPTS :=
else
DIGEST_OPTS := --set image.useDigest=true \
	--set operator.image.useDigest=true \
	--set preflight.image.useDigest=true \
	--set hubble.relay.image.useDigest=true \
	--set clustermesh.apiserver.image.useDigest=true
endif

DOCKER_RUN := $(CONTAINER_ENGINE) container run --rm \
	--workdir /src/install/kubernetes \
	--volume $(CURDIR)/../..:/src \
	--user "$(shell id -u):$(shell id -g)"
HELM_DOCS := $(DOCKER_RUN) $(HELM_DOCS_IMAGE)

LOGO_BASE_URL := https://cdn.jsdelivr.net/gh/cilium
LOGO_PATH := Documentation/images/logo-solo.svg

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL) $(QUICK_HUBBLE_INSTALL) docs

$(QUICK_INSTALL) quick-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system \
	$(DIGEST_OPTS) $(QUICK_OPTIONS) > $(QUICK_INSTALL)

$(QUICK_HUBBLE_INSTALL) quick-hubble-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system \
	$(DIGEST_OPTS) $(QUICK_HUBBLE_OPTIONS) > $(QUICK_HUBBLE_INSTALL)

$(EXPERIMENTAL_INSTALL) experimental-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system \
	$(DIGEST_OPTS) $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g';						\
		# Fix up the container image tags										\
		cilium_version="v$(VERSION)";											\
		branch="$$cilium_version";											\
		hubble_version_frontend=$(HUBBLE_UI_VERSION);									\
		hubble_version_backend=$(HUBBLE_UI_BACKEND_VERSION);								\
		pull_policy="IfNotPresent";											\
		use_digest="false";												\
		if echo "$(VERSION)" | grep -q $(LATEST_VERSION_REGEX); then							\
			cilium_version="latest";										\
			branch="master";											\
			hubble_version_frontend="latest";									\
			hubble_version_backend="latest";									\
			pull_policy="Always";											\
			use_digest="false";											\
		elif echo "$(VERSION)" | grep -q $(DEV_VERSION_REGEX); then							\
			cilium_version="v$(subst -dev,,$(VERSION))";								\
			branch="$$cilium_version";										\
			hubble_version_frontend="$(HUBBLE_UI_VERSION)";								\
			hubble_version_backend="$(HUBBLE_UI_BACKEND_VERSION)";							\
			pull_policy="Always";											\
			use_digest="false";											\
		fi;														\
		sed -i 's;icon:.*;icon: $(LOGO_BASE_URL)/cilium@'$$branch'/$(LOGO_PATH);' $(CHART_FILE);			\
		# image.tag operator.image.tag preflight.image.tag hubble.relay.image.tag;					\
		sed -i 's/tag: .*/tag: '$$cilium_version'/g' $(CILIUM_VALUES);							\
		# hubble.ui.frontend.image.tag;											\
		sed -i '/repository.*hubble-ui.*/{!b;n;s/tag.*/tag: '$$hubble_version_frontend'/}' $(CILIUM_VALUES);	\
		# hubble.ui.backend.image.tag;							\
		sed -i '/repository.*hubble-ui-backend.*/{!b;n;s/tag.*/tag: '$$hubble_version_backend'/}' $(CILIUM_VALUES);	\
		# etcd.image.tag												\
		sed -i '/repository.*etcd-operator.*/{!b;n;s/tag.*/tag: '$(MANAGED_ETCD_VERSION)'/}' $(CILIUM_VALUES)		\
		# clustermesh.apiserver.etcd.image.tag										\
		sed -i '/repository.*etcd$$/{!b;n;s/tag.*/tag: '$(ETCD_VERSION)'/}' $(CILIUM_VALUES)				\
		# nodeinit.image.tag												\
		sed -i '/repository.*cilium\/startup-script.*/{!b;n;s/tag.*/tag: '$(NODEINIT_VERSION)'/}' $(CILIUM_VALUES)	\
		# certgen.image.tag												\
		sed -i '/repository.*certgen.*/{!b;n;s/tag.*/tag: '$(CERTGEN_VERSION)'/}' $(CILIUM_VALUES);			\
		sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 '$$pull_policy'/' $(CILIUM_VALUES);  					\
		sed -i 's/useDigest:.*/useDigest: '$$use_digest'/' $(CILIUM_VALUES);  							\
		# image digests;													\
		sed -i '/# cilium-digest.*/{!b;n;s/digest.*/digest: "'$(CILIUM_DIGEST)'"/}' $(CILIUM_VALUES); 				\
		sed -i '/# hubble-relay-digest.*/{!b;n;s/digest.*/digest: "'$(HUBBLE_RELAY_DIGEST)'"/}' $(CILIUM_VALUES);			\
		sed -i '/# operator-aws-digest.*/{!b;n;s/awsDigest.*/awsDigest: "'$(OPERATOR_AWS_DIGEST)'"/}' $(CILIUM_VALUES);                 \
		sed -i '/# operator-azure-digest.*/{!b;n;s/azureDigest.*/azureDigest: "'$(OPERATOR_AZURE_DIGEST)'"/}' $(CILIUM_VALUES);         \
		sed -i '/# operator-generic-digest.*/{!b;n;s/genericDigest.*/genericDigest: "'$(OPERATOR_GENERIC_DIGEST)'"/}' $(CILIUM_VALUES); \
		sed -i '/# clustermesh-apiserver-digest.*/{!b;n;s/digest.*/digest: "'$(CLUSTERMESH_APISERVER_DIGEST)'"/}' $(CILIUM_VALUES)

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

docs:
	$(QUIET)$(HELM_DOCS)

check-docker-images:
	$(QUIET)\
         HUBBLE_UI_VERSION=$(HUBBLE_UI_VERSION) \
         MANAGED_ETCD_VERSION=$(MANAGED_ETCD_VERSION) \
         ETCD_VERSION=$(ETCD_VERSION) \
         NODEINIT_VERSION=$(NODEINIT_VERSION) \
         CERTGEN_VERSION=$(CERTGEN_VERSION) \
         ../../contrib/release/check-docker-images.sh "v$(VERSION)"

.PHONY: all check-docker-images clean docs experimental-install lint quick-install update-versions
