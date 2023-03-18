# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

PROVISION ?= true
# If you set provision to false the test will run without bootstrapping the
# cluster again.
HOLD_ENVIRONMENT ?= true

TEST_ARTIFACTS = ./tmp.yaml ./*_service_manifest.json ./*_manifest.yaml
TEST_ARTIFACTS += ./*_policy.json ./k8s-*.xml ./runtime.xml ./test_results
TEST_ARTIFACTS += ./test.test

NETNEXT ?= false
KUBEPROXY ?= 1
NO_CILIUM_ON_NODES ?= ""

GINKGO = $(QUIET) ginkgo

REGISTRY_CREDENTIALS ?= "${DOCKER_LOGIN}:${DOCKER_PASSWORD}"

.PHONY = all build test run k8s-test k8s-kind clean run_bpf_tests

all: build

build:
	@$(ECHO_GINKGO)$@
	$(GINKGO) build -tags=integration_tests
	$(QUIET)$(MAKE) -C bpf/

build-darwin:
	@$(ECHO_GINKGO)$@
	GOOS=darwin $(GINKGO) build -tags=integration_tests

test: run k8s-test

run:
	KERNEL=net-next ginkgo --focus "Runtime" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

k8s-test:
	ginkgo --focus "K8s" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

# Match kind-image target in parent directory
k8s-kind: export DOCKER_REGISTRY=localhost:5000
k8s-kind:
	@if [ -z $(FOCUS) ]; then \
		>&2 echo "usage: FOCUS=K8sFoo make k8s-kind"; \
		exit 1; \
	fi
	@CNI_INTEGRATION=kind \
		K8S_VERSION="$$(kubectl version -o json | jq -r '.serverVersion | "\(.major).\(.minor)"')" \
		NETNEXT="$(NETNEXT)" \
		KUBEPROXY="$(KUBEPROXY)" \
		NO_CILIUM_ON_NODES="$(NO_CILIUM_ON_NODES)" \
		ginkgo --focus "$(FOCUS)" --tags integration_tests -v -- \
			-cilium.testScope=k8s \
			-cilium.provision=false \
			-cilium.kubeconfig=$$(echo ~/.kube/config) \
			-cilium.passCLIEnvironment=true \
			-cilium.image="$(DOCKER_REGISTRY)/cilium/cilium-dev" \
			-cilium.tag="local" \
			-cilium.operator-image="quay.io/cilium/operator" \
			-cilium.operator-suffix="-ci" \
			-cilium.holdEnvironment=$(HOLD_ENVIRONMENT)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET) rm -rf $(TEST_ARTIFACTS)
	-$(QUIET) rm -f .vagrant/*.box
	-$(QUIET)$(MAKE) -C bpf/ clean

BPF_TEST_FLAGS:=
ifeq ($(V),1)
    BPF_TEST_FLAGS += -test.v
endif
ifeq ($(COVER),1)
	ifndef COVERFORMAT
		COVERFORMAT:=html
	endif
    BPF_TEST_FLAGS += -coverage-report $(ROOT_DIR)/bpf-coverage.$(COVERFORMAT) -coverage-format $(COVERFORMAT)
ifdef NOCOVER
    BPF_TEST_FLAGS += -no-test-coverage "$(NOCOVER)"
endif
endif
ifeq ($(INSTRLOG),1)
    BPF_TEST_FLAGS += -instrumentation-log $(ROOT_DIR)/test/bpf-instrumentation.log
endif
ifdef RUN
    BPF_TEST_FLAGS += -run $(RUN)
endif

run_bpf_tests:
	$(QUIET)$(MAKE) -C ../bpf/tests all
	$(QUIET)$(GO) test ./bpf_tests -exec sudo -bpf-test-path $(ROOT_DIR)/bpf/tests $(BPF_TEST_FLAGS)
