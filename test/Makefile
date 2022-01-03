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
	$(GINKGO) build -tags=integration_tests
	$(QUIET)$(MAKE) -C bpf/

test: run k8s

run:
	KERNEL=net-next ginkgo --focus "Runtime" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

k8s:
	ginkgo --focus "K8s" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

nightly:
	ginkgo --focus "Nightly" -v --tags integration_tests -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET) rm -rf $(TEST_ARTIFACTS)
	-$(QUIET) rm -f .vagrant/*.box
