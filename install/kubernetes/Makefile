# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

# Workaround until we branch for v1.9
VERSION := 1.8.90

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
EXPERIMENTAL_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/experimental-install.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
EXPERIMENTAL_OPTIONS := \
    --set hubble.enabled=true \
    --set hubble.listenAddress=":4244" \
    --set hubble.tls.auto.enabled=true \
    --set hubble.tls.auto.method="cronJob" \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --set bandwidthManager=true

DOCKER_RUN := $(CONTAINER_ENGINE) container run --rm \
	--workdir /src/install/kubernetes \
	--volume $(CURDIR)/../..:/src \
	--user "$(shell id -u):$(shell id -g)"

HELM_DOCS_VERSION := "v1.3.0"
HELM_DOCS_SHA := "12f065115654c9a1d6819b938487d327f1fdb5c32bdc2a5c74afef22ed68f5ca"
HELM_DOCS_IMAGE := "docker.io/jnorwood/helm-docs:$(HELM_DOCS_VERSION)@sha256:$(HELM_DOCS_SHA)"
HELM_DOCS := $(DOCKER_RUN) $(HELM_DOCS_IMAGE)

GOMPLATE_VERSION := "v3.8.0-alpine"
GOMPLATE_SHA := "799c798e5489c49527e2b7bb104de66a8c93555165f7c86eea023f98b5d227d5"
GOMPLATE_IMAGE := "docker.io/hairyhenderson/gomplate:$(GOMPLATE_VERSION)@sha256:$(GOMPLATE_SHA)"
GOMPLATE := $(DOCKER_RUN) $(GOMPLATE_IMAGE)

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL) docs

$(QUICK_INSTALL) quick-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system > $(QUICK_INSTALL)

$(EXPERIMENTAL_INSTALL) experimental-install: $(shell find cilium/ -type f) update-versions
	$(QUIET)helm template cilium cilium --namespace=kube-system $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g'
	@# Generate cilium/values.yaml.
	$(QUIET)$(GOMPLATE) -c .=versions.json -f ./cilium/values.yaml.tmpl -o ./cilium/values.yaml

lint:
	$(QUIET)helm lint --with-subcharts --values ./cilium/values.yaml ./cilium

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

docs:
	$(QUIET)$(HELM_DOCS)

.PHONY: all clean update-versions lint quick-install experimental-install docs
