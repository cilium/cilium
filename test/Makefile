provision = true
# If you set provision to false the test will run without compile the code
# again.

TEST_ARTIFACTS = ./tmp.yaml ./*_service_manifest.json ./*_manifest.yaml
TEST_ARTIFACTS += ./*_policy.json ./k8s-*.xml ./runtime.xml ./test_results
TEST_ARTIFACTS += ./test.test

all: build

build:
	# This should print a message if ginkgo is missing, but allow the
	# bash-based test VM to run CI without needing to add Ginkgo to it.
	# Once the bash-based tests are migrated, the "|| true" can be removed.
	# GH #1839
	ginkgo build || true

test: run k8s

run:
	ginkgo --focus " Runtime*" -v -- --cilium.provision=$(provision)

k8s:
	ginkgo --focus " K8s*" -v -- --cilium.provision=$(provision)

k8s16:
	K8S_VERSION=1.6 ginkgo --focus " K8s*" -v -- --cilium.provision=$(provision)

clean:
	-rm -rf $(TEST_ARTIFACTS)
