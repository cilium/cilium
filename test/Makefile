include ../Makefile.defs

provision = true
# If you set provision to false the test will run without compile the code
# again.

TEST_ARTIFACTS = ./tmp.yaml ./*_service_manifest.json ./*_manifest.yaml
TEST_ARTIFACTS += ./*_policy.json ./k8s-*.xml ./runtime.xml ./test_results
TEST_ARTIFACTS += ./test.test

GINKGO := $(QUIET) $(GO) run -v ../vendor/github.com/onsi/ginkgo/ginkgo/*.go

all: build

build:
	# This should print a message if ginkgo is missing, but allow the
	# bash-based test VM to run CI without needing to add Ginkgo to it.
	# Once the bash-based tests are migrated, the "|| true" can be removed.
	# GH #1839
	@$(ECHO_GINKGO)$@
	$(GINKGO) build || true
	$(QUIET)$(MAKE) -C bpf/

test: run k8s

run:
	$(GINKGO) --focus " Runtime*" -v -- --cilium.provision=$(provision)

k8s:
	$(GINKGO) --focus " K8s*" -v -- --cilium.provision=$(provision)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -rf $(TEST_ARTIFACTS)
