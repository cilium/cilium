# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.digests ../../Makefile.defs

HUBBLE_PROXY_VERSION := "v1.18.4@sha256:e5c2bb2870d0e59ce917a5100311813b4ede96ce4eb0c6bfa879e3fbe3e83935"
HUBBLE_UI_VERSION := "v0.8.5@sha256:4eaca1ec1741043cfba6066a165b3bf251590cf4ac66371c4f63fbed2224ebb4"
HUBBLE_UI_BACKEND_VERSION := "v0.8.5@sha256:2bce50cf6c32719d072706f7ceccad654bfa907b2745a496da99610776fe31ed"
MANAGED_ETCD_VERSION := "v2.0.7"
ETCD_VERSION := "v3.4.13"
NODEINIT_VERSION := "62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
CERTGEN_VERSION := "v0.1.5"

MIN_K8S_MAJOR := 1
MIN_K8S_MINOR := 16
MIN_K8S_VERSION := "v$(MIN_K8S_MAJOR).$(MIN_K8S_MINOR).0"

CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"
CHART_FILE := "$(CILIUM_CHARTS)/Chart.yaml"
USE_DIGESTS ?= $(shell if grep -q '""' Makefile.digests; then echo "false"; else echo "true"; fi)

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_PULLPOLICY_REGEX := '\([pP]ullPolicy:\) .*'

DOCKER_RUN := $(CONTAINER_ENGINE) container run --rm \
	--workdir /src/install/kubernetes \
	--volume $(CURDIR)/../..:/src \
	--user "$(shell id -u):$(shell id -g)"
HELM_DOCS := $(DOCKER_RUN) $(HELM_DOCS_IMAGE)

LOGO_BASE_URL := https://cdn.jsdelivr.net/gh/cilium
LOGO_PATH := Documentation/images/logo-solo.svg

all: update-versions docs

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g';						\
		# Fix up the container image tags										\
		cilium_version="v$(VERSION)";											\
		branch="$$cilium_version";											\
		hubble_version=$(HUBBLE_UI_VERSION);										\
		hubble_backend_version=$(HUBBLE_UI_BACKEND_VERSION);								\
		pull_policy="IfNotPresent";											\
		use_digest="$(USE_DIGESTS)";													\
		if echo "$(VERSION)" | grep -q $(LATEST_VERSION_REGEX); then							\
			cilium_version="latest";										\
			branch="master";											\
			hubble_version="latest";										\
			hubble_backend_version="latest";									\
			pull_policy="Always";											\
			use_digest="false";												\
		elif echo "$(VERSION)" | grep -q $(DEV_VERSION_REGEX); then							\
			cilium_version="v$(subst -dev,,$(VERSION))";								\
			branch="$$cilium_version";										\
			hubble_version="$(HUBBLE_UI_VERSION)";									\
			hubble_backend_version="$(HUBBLE_UI_BACKEND_VERSION)";							\
			pull_policy="Always";											\
			use_digest="false";												\
		fi;														\
		sed -i 's;icon:.*;icon: $(LOGO_BASE_URL)/cilium@'$$branch'/$(LOGO_PATH);' $(CHART_FILE);			\
		# image.tag operator.image.tag preflight.image.tag hubble.relay.image.tag;					\
		sed -i 's/tag: .*/tag: '$$cilium_version'/g' $(CILIUM_VALUES);							\
		# hubble.ui.frontend.image.tag;											\
		sed -i '/repository.*hubble-ui$$/{!b;n;s/tag.*/tag: '$$hubble_version'/}' $(CILIUM_VALUES);			\
		# hubble.ui.backend.image.tag;											\
		sed -i '/repository.*hubble-ui-backend.*/{!b;n;s/tag.*/tag: '$$hubble_backend_version'/}' $(CILIUM_VALUES);	\
		# etcd.image.tag												\
		sed -i '/repository.*etcd-operator.*/{!b;n;s/tag.*/tag: '$(MANAGED_ETCD_VERSION)'/}' $(CILIUM_VALUES)		\
		# clustermesh.apiserver.etcd.image.tag										\
		sed -i '/repository.*etcd$$/{!b;n;s/tag.*/tag: '$(ETCD_VERSION)'/}' $(CILIUM_VALUES)				\
		# hubble.ui.proxy.image.tag											\
		sed -i '/repository.*envoy.*/{!b;n;s/tag.*/tag: '$(HUBBLE_PROXY_VERSION)'/}' $(CILIUM_VALUES)			\
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
		sed -i '/# operator-alibabacloud-digest.*/{!b;n;s/alibabacloudDigest.*/alibabacloudDigest: "'$(OPERATOR_ALIBABACLOUD_DIGEST)'"/}' $(CILIUM_VALUES);         \
		sed -i '/# operator-generic-digest.*/{!b;n;s/genericDigest.*/genericDigest: "'$(OPERATOR_GENERIC_DIGEST)'"/}' $(CILIUM_VALUES); \
		sed -i '/# clustermesh-apiserver-digest.*/{!b;n;s/digest.*/digest: "'$(CLUSTERMESH_APISERVER_DIGEST)'"/}' $(CILIUM_VALUES)

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

docs:
	$(QUIET)$(HELM_DOCS)

check-docker-images:
	$(QUIET)\
         HUBBLE_PROXY_VERSION=$(HUBBLE_PROXY_VERSION) \
         HUBBLE_UI_VERSION=$(HUBBLE_UI_VERSION) \
         HUBBLE_UI_BACKEND_VERSION=$(HUBBLE_UI_BACKEND_VERSION) \
         MANAGED_ETCD_VERSION=$(MANAGED_ETCD_VERSION) \
         ETCD_VERSION=$(ETCD_VERSION) \
         NODEINIT_VERSION=$(NODEINIT_VERSION) \
         CERTGEN_VERSION=$(CERTGEN_VERSION) \
         ../../contrib/release/check-docker-images.sh "v$(VERSION)"

.PHONY: all check-docker-images clean docs lint update-versions
