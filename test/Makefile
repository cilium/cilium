# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

PROVISION ?= true
# If you set provision to false the test will run without bootstrapping the
# cluster again.

TEST_ARTIFACTS = ./tmp.yaml ./*_service_manifest.json ./*_manifest.yaml
TEST_ARTIFACTS += ./*_policy.json ./k8s-*.xml ./runtime.xml ./test_results
TEST_ARTIFACTS += ./test.test

GINKGO = $(QUIET) ginkgo

REGISTRY_CREDENTIALS ?= "${DOCKER_LOGIN}:${DOCKER_PASSWORD}"

all: build

build:
	@$(ECHO_GINKGO)$@
	$(GINKGO) build
	$(QUIET)$(MAKE) -C bpf/

test: run k8s

run:
	ginkgo --focus "Runtime" -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

k8s:
	ginkgo --focus "K8s" -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

nightly:
	ginkgo --focus "Nightly" -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET) rm -rf $(TEST_ARTIFACTS)
	-$(QUIET) rm -f .vagrant/*.box
