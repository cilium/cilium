# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

##@ Default
all: precheck build postcheck ## Default make target that perform precheck -> build -> postcheck
	@echo "Build finished."

##@ Build, Install and Test
debug: export NOOPT=1 ## Builds Cilium by disabling inlining, compiler optimizations and without stripping debug symbols, useful for debugging.
debug: export NOSTRIP=1
debug: all

include Makefile.defs

SUBDIRS_CILIUM_CONTAINER := proxylib envoy bpf cilium daemon cilium-health bugtool tools/mount tools/sysctlfix
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) operator plugins tools hubble-relay

SUBDIRS_CILIUM_CONTAINER += plugins/cilium-cni
ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif

# Space-separated list of Go packages to test, equivalent to 'go test' package patterns.
# Because is treated as a Go package pattern, the special '...' sequence is supported,
# meaning 'all subpackages of the given package'.
TESTPKGS ?= ./...

SWAGGER_VERSION := v0.30.3
SWAGGER := $(CONTAINER_ENGINE) run -u $(shell id -u):$(shell id -g) --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) --entrypoint swagger quay.io/goswagger/swagger:$(SWAGGER_VERSION)

GOTEST_BASE := -test.v -timeout 600s
GOTEST_COVER_OPTS += -coverprofile=coverage.out
BENCH_EVAL := "."
BENCH ?= $(BENCH_EVAL)
BENCHFLAGS_EVAL := -bench=$(BENCH) -run=^$ -benchtime=10s
BENCHFLAGS ?= $(BENCHFLAGS_EVAL)
SKIP_VET ?= "false"
SKIP_KVSTORES ?= "false"
SKIP_K8S_CODE_GEN_CHECK ?= "true"
SKIP_CUSTOMVET_CHECK ?= "false"

JOB_BASE_NAME ?= cilium_test

GO_MAJOR_AND_MINOR_VERSION := $(shell awk '/^go/ { print $$2 }' go.mod)
GO_INSTALLED_MAJOR_AND_MINOR_VERSION := $(shell $(GO) version | sed 's/go version go\([0-9]\+\).\([0-9]\+\)\(.[0-9]\+\)\?.*/\1.\2/')

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002 \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

TEST_UNITTEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

build: check-sources $(SUBDIRS) ## Builds all the components for Cilium by executing make in the respective sub directories.

build-container: check-sources ## Builds components required for cilium-agent container.
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i all; done

$(SUBDIRS): force ## Execute default make target(make all) for the provided subdirectory.
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

tests-privileged: ## Run Go tests including ones that require elevated privileges.
	@$(ECHO_CHECK) running privileged tests...
	PRIVILEGED_TESTS=true PATH=$(PATH):$(ROOT_DIR)/bpf $(GO_TEST) $(TEST_LDFLAGS) \
		$(TESTPKGS) $(GOTEST_BASE) $(GOTEST_COVER_OPTS) | $(GOTEST_FORMATTER)
	$(MAKE) generate-cov

start-kvstores: ## Start running kvstores (etcd and consul containers) for integration tests.
ifeq ($(SKIP_KVSTORES),"false")
	@echo Starting key-value store containers...
	-$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-etcd-test-container" 2> /dev/null
	$(QUIET)$(CONTAINER_ENGINE) run -d \
		-e ETCD_UNSUPPORTED_ARCH=$(GOARCH) \
		--name "cilium-etcd-test-container" \
		-p 4002:4001 \
		$(ETCD_IMAGE) \
		etcd -name etcd0 \
		-advertise-client-urls http://0.0.0.0:4001 \
		-listen-client-urls http://0.0.0.0:4001 \
		-listen-peer-urls http://0.0.0.0:2380 \
		-initial-cluster-token etcd-cluster-1 \
		-initial-cluster-state new
	-$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-consul-test-container" 2> /dev/null
	$(QUIET)rm -rf /tmp/cilium-consul-certs
	$(QUIET)mkdir /tmp/cilium-consul-certs
	$(QUIET)cp $(CURDIR)/test/consul/* /tmp/cilium-consul-certs
	$(QUIET)chmod -R a+rX /tmp/cilium-consul-certs
	$(QUIET)$(CONTAINER_ENGINE) run -d \
		--name "cilium-consul-test-container" \
		-p 8501:8443 \
		-e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true, "disable_update_check": true}' \
		-v /tmp/cilium-consul-certs:/cilium-consul/ \
		$(CONSUL_IMAGE) \
		agent -client=0.0.0.0 -server -bootstrap-expect 1 -config-file=/cilium-consul/consul-config.json
endif

stop-kvstores: ## Forcefully removes running kvstore components (etcd and consul containers) for integration tests.
ifeq ($(SKIP_KVSTORES),"false")
	$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-etcd-test-container"
	$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-consul-test-container"
	$(QUIET)rm -rf /tmp/cilium-consul-certs
endif

generate-cov: ## Generate HTML coverage report at coverage-all.html.
	# Remove generated code from coverage
	$(QUIET) grep -Ev '(^github.com/cilium/cilium/api/v1)|(generated.deepcopy.go)|(^github.com/cilium/cilium/pkg/k8s/client/)' \
		coverage.out > coverage.out.tmp
	$(QUIET)$(GO) tool cover -html=coverage.out.tmp -o=coverage-all.html
	$(QUIET) rm coverage.out.tmp
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true

integration-tests: start-kvstores ## Run Go tests including ones that are marked as integration tests.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C test/bpf/
ifeq ($(SKIP_VET),"false")
	$(MAKE) govet
endif
	@$(ECHO_CHECK) running integration tests...
	INTEGRATION_TESTS=true $(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(TESTPKGS) $(GOTEST_BASE) $(GOTEST_COVER_OPTS) | $(GOTEST_FORMATTER)
	$(MAKE) generate-cov
	$(MAKE) stop-kvstores

bench: start-kvstores ## Run benchmarks for Cilium integration-tests in the repository.
	$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) $(TESTPKGS)
	$(MAKE) stop-kvstores

bench-privileged: ## Run benchmarks for privileged tests.
	PRIVILEGED_TESTS=true $(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) $(TESTPKGS)

clean-tags: ## Remove all the tags files from the repository.
	@$(ECHO_CLEAN) tags
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

.PHONY: cscope.files
cscope.files: ## Generate cscope.files with the list of all files to generate ctags for.
	@# Argument to -f must be double-quoted since shell removes backslashes that appear
	@# before newlines. Otherwise, backslashes will appear in the output file.
	@go list -f "{{ \$$p := .ImportPath }} \
		{{- range .GoFiles }}{{ printf \"%s/%s\n\" \$$p . }}{{ end }} \
		{{- range .TestGoFiles }}{{ printf \"%s/%s\n\" \$$p . }}{{ end }}" ./... \
		| sed 's#github.com/cilium/cilium/##g' | sort | uniq > cscope.files

	@echo "$(BPF_SRCFILES)" | sed 's/ /\n/g' | sort >> cscope.files

tags: cscope.files ## Generate tags for Go and BPF source files.
	@ctags -L cscope.files
	cscope -R -b -q

clean-container: ## Perform `make clean` for each component required in cilium-agent container.
	-$(QUIET) for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

clean: ## Perform overall cleanup for Cilium.
	-$(QUIET) for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

veryclean: ## Perform complete cleanup for container engine images(including build cache).
	-$(QUIET) $(CONTAINER_ENGINE) image prune -af
	-$(QUIET) $(CONTAINER_ENGINE) builder prune -af

install-bpf: ## Copies over the BPF source files from bpf/ to /var/lib/cilium/bpf/
	$(QUIET)$(INSTALL) -m 0750 -d $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium
	-rm -rf $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium/bpf/*
	$(foreach bpfsrc,$(BPF_SRCFILES), $(INSTALL) -D -m 0644 $(bpfsrc) $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium/$(bpfsrc);)

install: install-bpf ## Performs install for all the Cilium sub components (daemon, operator, relay etc.)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

install-container: install-bpf ## Performs install for all components required for cilium-agent container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

install-container-binary: install-bpf ## Install binaries for all components required for cilium-agent container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i install-binary; done

install-bash-completion: ## Install bash completion for all components required for cilium-agent container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i install-bash-completion; done

# Workaround for not having git in the build environment
# Touch the file only if needed
GIT_VERSION: force
	@if [ "$(GIT_VERSION)" != "`cat 2>/dev/null GIT_VERSION`" ] ; then echo "$(GIT_VERSION)" >GIT_VERSION; fi

-include Makefile.docker

##@ API targets
CRD_OPTIONS ?= "crd:crdVersions=v1"
CRD_PATHS := "$(PWD)/pkg/k8s/apis/cilium.io/v2;\
              $(PWD)/pkg/k8s/apis/cilium.io/v2alpha1;"
CRDS_CILIUM_PATHS := $(PWD)/pkg/k8s/apis/cilium.io/client/crds/v2\
                     $(PWD)/pkg/k8s/apis/cilium.io/client/crds/v2alpha1
CRDS_CILIUM_V2 := ciliumnetworkpolicies \
                  ciliumclusterwidenetworkpolicies \
                  ciliumendpoints \
                  ciliumidentities \
                  ciliumnodes \
                  ciliumexternalworkloads \
                  ciliumlocalredirectpolicies \
                  ciliumegressgatewaypolicies \
                  ciliumenvoyconfigs \
                  ciliumclusterwideenvoyconfigs
CRDS_CILIUM_V2ALPHA1 := ciliumendpointslices \
                        ciliumbgppeeringpolicies \
                        ciliumloadbalancerippools \
                        ciliumnodeconfigs \
                        ciliumcidrgroups
manifests: ## Generate K8s manifests e.g. CRD, RBAC etc.
	$(eval TMPDIR := $(shell mktemp -d -t cilium.tmpXXXXXXXX))
	$(QUIET)$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen $(CRD_OPTIONS) paths=$(CRD_PATHS) output:crd:artifacts:config="$(TMPDIR)"
	$(QUIET)$(GO) run ./tools/crdcheck "$(TMPDIR)"

	# Clean up old CRD state and start with a blank state.
	for path in $(CRDS_CILIUM_PATHS); do rm -rf $${path} && mkdir $${path}; done

	for file in $(CRDS_CILIUM_V2); do mv ${TMPDIR}/cilium.io_$${file}.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/$${file}.yaml; done
	for file in $(CRDS_CILIUM_V2ALPHA1); do mv ${TMPDIR}/cilium.io_$${file}.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2alpha1/$${file}.yaml; done
	rm -rf $(TMPDIR)

generate-api: api/v1/openapi.yaml ## Generate cilium-agent client, model and server code from openapi spec.
	@$(ECHO_GEN)api/v1/openapi.yaml
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 \
		-f api/v1/openapi.yaml \
		--default-scheme=unix \
		-C api/v1/cilium-server.yml \
		-r hack/spdx-copyright-header.txt
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 \
		-f api/v1/openapi.yaml \
		-r hack/spdx-copyright-header.txt
	@# sort goimports automatically
	-$(QUIET)$(GO) run golang.org/x/tools/cmd/goimports -w ./api/v1/client ./api/v1/models ./api/v1/server

generate-health-api: api/v1/health/openapi.yaml ## Generate cilium-health client, model and server code from openapi spec.
	@$(ECHO_GEN)api/v1/health/openapi.yaml
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 \
		-t api/v1/health/ \
		-f api/v1/health/openapi.yaml \
		--default-scheme=unix \
		-C api/v1/cilium-server.yml \
		-r hack/spdx-copyright-header.txt
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 \
		-t api/v1/health/ \
		-f api/v1/health/openapi.yaml \
		-r hack/spdx-copyright-header.txt
	@# sort goimports automatically
	-$(QUIET)$(GO) run golang.org/x/tools/cmd/goimports -w ./api/v1/health

generate-operator-api: api/v1/operator/openapi.yaml ## Generate cilium-operator client, model and server code from openapi spec.
	@$(ECHO_GEN)api/v1/operator/openapi.yaml
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 \
		-t api/v1/operator/ \
		-f api/v1/operator/openapi.yaml \
		--default-scheme=http \
		-C api/v1/cilium-server.yml \
		-r hack/spdx-copyright-header.txt
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 \
		-t api/v1/operator/ \
		-f api/v1/operator/openapi.yaml \
		-r hack/spdx-copyright-header.txt
	@# sort goimports automatically
	-$(QUIET)$(GO) run golang.org/x/tools/cmd/goimports -w ./api/v1/operator

generate-hubble-api: api/v1/flow/flow.proto api/v1/peer/peer.proto api/v1/observer/observer.proto api/v1/relay/relay.proto ## Generate hubble proto Go sources.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C api/v1

define generate_k8s_api
	$(QUIET) cd "./vendor/k8s.io/code-generator" && \
	bash ./generate-groups.sh $(1) \
	    $(2) \
	    $(3) \
	    $(4) \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt" \
	    --output-base $(5)
endef

define generate_deepequal
	$(GO) run github.com/cilium/deepequal-gen \
	--input-dirs $(subst $(space),$(comma),$(1)) \
	--go-header-file "$(PWD)/hack/custom-boilerplate.go.txt" \
	--output-file-base zz_generated.deepequal \
	--output-base $(2)
endef

define generate_deepcopy
	$(GO) run k8s.io/code-generator/cmd/deepcopy-gen \
	--input-dirs $(subst $(space),$(comma),$(1)) \
	--go-header-file "$(PWD)/hack/custom-boilerplate.go.txt" \
	--output-file-base zz_generated.deepcopy \
	--output-base $(2)
endef

define generate_k8s_protobuf
	$(GO) install k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo && \
	$(GO) install golang.org/x/tools/cmd/goimports && \
	$(GO) run k8s.io/code-generator/cmd/go-to-protobuf \
		--apimachinery-packages='-k8s.io/apimachinery/pkg/util/intstr,$\
                                -k8s.io/apimachinery/pkg/api/resource,$\
                                -k8s.io/apimachinery/pkg/runtime/schema,$\
                                -k8s.io/apimachinery/pkg/runtime,$\
                                -k8s.io/apimachinery/pkg/apis/meta/v1,$\
                                -k8s.io/apimachinery/pkg/apis/meta/v1beta1'\
		--drop-embedded-fields="github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1.TypeMeta" \
		--proto-import="$(PWD)" \
		--proto-import="$(PWD)/vendor" \
		--proto-import="$(PWD)/tools/protobuf" \
		--packages=$(subst $(newline),$(comma),$(1)) \
		--go-header-file "$(PWD)/hack/custom-boilerplate.go.txt" \
		--output-base=$(2)
endef

define K8S_PROTO_PACKAGES
github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1
github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1
github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1
github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1
github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/apiextensions/v1
github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1
github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1beta1
github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr
endef

GEN_CRD_GROUPS := "cilium.io:v2\
                   cilium.io:v2alpha1"
generate-k8s-api: ## Generate Cilium k8s API client, deepcopy and deepequal Go sources.
	$(ASSERT_CILIUM_MODULE)

	$(eval TMPDIR := $(shell mktemp -d -t cilium.tmpXXXXXXXX))

	$(QUIET) $(call generate_k8s_protobuf,${K8S_PROTO_PACKAGES},"$(TMPDIR)")

	$(eval DEEPEQUAL_PACKAGES := $(shell grep "\+deepequal-gen" -l -r --include \*.go --exclude-dir 'vendor' . | xargs dirname {} | sort | uniq | grep -x -v '.' | sed 's|\.\/|github.com/cilium/cilium\/|g'))
	$(QUIET) $(call generate_deepequal,${DEEPEQUAL_PACKAGES},"$(TMPDIR)")

	$(eval DEEPCOPY_PACKAGES := $(shell grep "\+k8s:deepcopy-gen" -l -r --include \*.go --exclude-dir 'vendor' . | xargs dirname {} | sort | uniq | grep -x -v '.' | sed 's|\.\/|github.com/cilium/cilium\/|g'))
	$(QUIET) $(call generate_deepcopy,${DEEPCOPY_PACKAGES},"$(TMPDIR)")

	$(QUIET) $(call generate_k8s_api,client,github.com/cilium/cilium/pkg/k8s/slim/k8s/client,github.com/cilium/cilium/pkg/k8s/slim/k8s/api,"discovery:v1beta1 discovery:v1 networking:v1 core:v1","$(TMPDIR)")
	$(QUIET) $(call generate_k8s_api,client,github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"apiextensions:v1","$(TMPDIR)")
	$(QUIET) $(call generate_k8s_api,client$(comma)lister$(comma)informer,github.com/cilium/cilium/pkg/k8s/client,github.com/cilium/cilium/pkg/k8s/apis,$(GEN_CRD_GROUPS),"$(TMPDIR)")

	$(QUIET) cp -r "$(TMPDIR)/github.com/cilium/cilium/." ./
	$(QUIET) rm -rf "$(TMPDIR)"

check-k8s-clusterrole: ## Ensures there is no diff between preflight's clusterrole and runtime's clusterrole.
	./contrib/scripts/check-preflight-clusterrole.sh

##@ Development
vps: ## List all the running vagrant VMs.
	VBoxManage list runningvms

reload: ## Reload cilium-agent and cilium-docker systemd service after installing built binaries.
	sudo systemctl stop cilium cilium-docker
	sudo $(MAKE) install
	sudo systemctl start cilium cilium-docker
	sleep 6
	cilium status

release: ## Perform a Git release for Cilium.
	$(eval TAG_VERSION := $(shell git tag | grep v$(VERSION) > /dev/null; echo $$?))
	$(eval BRANCH := $(shell git rev-parse --abbrev-ref HEAD))
	$(info Checking if tag $(VERSION) is created '$(TAG_VERSION)' $(BRANCH))

	@if [ "$(TAG_VERSION)" -eq "0" ];then { echo Git tag v$(VERSION) is already created; exit 1; } fi
	git commit -m "Version $(VERSION)"
	git tag v$(VERSION)
	git archive --format tar $(BRANCH) | gzip > ../cilium_$(VERSION).orig.tar.gz

gofmt: ## Run gofmt on Go source files in the repository.
	$(QUIET)$(GO) fmt ./...

govet: ## Run govet on Go source files in the repository.
	@$(ECHO_CHECK) vetting all packages...
	$(QUIET) $(GO_VET) ./...

golangci-lint: ## Run golangci-lint
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
	@$(ECHO_CHECK) golangci-lint $(GOLANGCI_LINT_ARGS)
	$(QUIET) golangci-lint run $(GOLANGCI_LINT_ARGS)
else
	$(QUIET) $(CONTAINER_ENGINE) run --rm -v `pwd`:/app -w /app docker.io/golangci/golangci-lint:$(GOLANGCILINT_WANT_VERSION)@$(GOLANGCILINT_IMAGE_SHA) golangci-lint run $(GOLANGCI_LINT_ARGS)
endif

golangci-lint-fix: ## Run golangci-lint to automatically fix warnings
	$(QUIET)$(MAKE) golangci-lint GOLANGCI_LINT_ARGS="--fix"

lint: golangci-lint

lint-fix: golangci-lint-fix

logging-subsys-field: ## Validate logrus subsystem field for logs in Go source code.
	@$(ECHO_CHECK) contrib/scripts/check-logging-subsys-field.sh
	$(QUIET) contrib/scripts/check-logging-subsys-field.sh

check-microk8s: ## Validate if microk8s is ready to install cilium.
	@$(ECHO_CHECK) microk8s is ready...
	$(QUIET)microk8s.status >/dev/null \
		|| (echo "Error: Microk8s is not running" && exit 1)

LOCAL_IMAGE_TAG=local
microk8s: export DOCKER_REGISTRY=localhost:32000
microk8s: export LOCAL_AGENT_IMAGE=$(DOCKER_REGISTRY)/$(DOCKER_DEV_ACCOUNT)/cilium-dev:$(LOCAL_IMAGE_TAG)
microk8s: export LOCAL_OPERATOR_IMAGE=$(DOCKER_REGISTRY)/$(DOCKER_DEV_ACCOUNT)/operator:$(LOCAL_IMAGE_TAG)
microk8s: check-microk8s ## Build cilium-dev docker image and import to microk8s
	$(QUIET)$(MAKE) dev-docker-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)
	@echo "  DEPLOY image to microk8s ($(LOCAL_AGENT_IMAGE))"
	$(QUIET)./contrib/scripts/microk8s-import.sh $(LOCAL_AGENT_IMAGE)
	$(QUIET)$(MAKE) dev-docker-operator-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)
	@echo "  DEPLOY image to microk8s ($(LOCAL_OPERATOR_IMAGE))"
	$(QUIET)./contrib/scripts/microk8s-import.sh $(LOCAL_OPERATOR_IMAGE)

kind: ## Create a kind cluster for Cilium development.
	SED=$(SED) $(QUIET)./contrib/scripts/kind.sh

kind-down: ## Destroy a kind cluster for Cilium development.
	$(QUIET)./contrib/scripts/kind-down.sh

.PHONY: kind-clustermesh
kind-clustermesh: ## Create two kind clusters for clustermesh development.
	@echo " If you have problems with too many open file, check https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files"
	$(QUIET) CLUSTER_NAME=clustermesh1 IPFAMILY=ipv4 PODSUBNET=10.1.0.0/16 SERVICESUBNET=172.20.1.0/24 ./contrib/scripts/kind.sh
	$(QUIET) CLUSTER_NAME=clustermesh2 AGENTPORTPREFIX=236 OPERATORPORTPREFIX=237 IPFAMILY=ipv4 PODSUBNET=10.2.0.0/16 SERVICESUBNET=172.20.2.0/24 ./contrib/scripts/kind.sh

.PHONY: kind-clustermesh-down
kind-clustermesh-down: ## Destroy kind clusters for clustermesh development.
	$(QUIET)./contrib/scripts/kind-down.sh clustermesh1 clustermesh2

.PHONY: kind-clustermesh-ready
kind-clustermesh-ready: ## Check if both kind clustermesh clusters exist
	@$(ECHO_CHECK) clustermesh kind is ready...
	@kind get clusters 2>&1 | grep "clustermesh1" \
		&& exit 0 || exit 1
	@kind get clusters 2>&1 | grep "clustermesh2" \
		&& exit 0 || exit 1

# Template for kind environment for a target. Parameters are:
# $(1) Makefile target name
define KIND_ENV
.PHONY: $(1)
$(1): export DOCKER_REGISTRY=localhost:5000
$(1): export LOCAL_AGENT_IMAGE=$$(DOCKER_REGISTRY)/$$(DOCKER_DEV_ACCOUNT)/cilium-dev:$$(LOCAL_IMAGE_TAG)
$(1): export LOCAL_OPERATOR_IMAGE=$$(DOCKER_REGISTRY)/$$(DOCKER_DEV_ACCOUNT)/operator-generic:$$(LOCAL_IMAGE_TAG)
$(1): export LOCAL_CLUSTERMESH_IMAGE=$$(DOCKER_REGISTRY)/$$(DOCKER_DEV_ACCOUNT)/clustermesh-apiserver:$$(LOCAL_IMAGE_TAG)
endef

$(eval $(call KIND_ENV,kind-clustermesh-images))
kind-clustermesh-images: kind-clustermesh-ready kind-build-clustermesh-apiserver kind-build-image-agent kind-build-image-operator ## Builds images and imports them into clustermesh clusters
	$(QUIET)kind load docker-image $(LOCAL_CLUSTERMESH_IMAGE) --name clustermesh1
	$(QUIET)kind load docker-image $(LOCAL_CLUSTERMESH_IMAGE) --name clustermesh2
	$(QUIET)kind load docker-image $(LOCAL_AGENT_IMAGE) --name clustermesh1
	$(QUIET)kind load docker-image $(LOCAL_AGENT_IMAGE) --name clustermesh2
	$(QUIET)kind load docker-image $(LOCAL_OPERATOR_IMAGE) --name clustermesh1
	$(QUIET)kind load docker-image $(LOCAL_OPERATOR_IMAGE) --name clustermesh2

$(eval $(call KIND_ENV,kind-install-cilium-clustermesh))
kind-install-cilium-clustermesh: kind-clustermesh-ready ## Install a local Cilium version into the clustermesh clusters and enable clustermesh.
	@echo "  INSTALL cilium on clustermesh1 cluster"
	kubectl config use kind-clustermesh1
	-$(CILIUM_CLI) uninstall >/dev/null
	$(CILIUM_CLI) install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-clustermesh1.yaml \
		--version=
	@echo "  INSTALL cilium on clustermesh2 cluster"
	kubectl config use kind-clustermesh2
	-$(CILIUM_CLI) uninstall >/dev/null
	$(CILIUM_CLI) install \
		--inherit-ca kind-clustermesh1 \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-clustermesh2.yaml \
		--version=
	@echo "  Enabling clustermesh"
	$(CILIUM_CLI) clustermesh enable --context kind-clustermesh1 --service-type NodePort --apiserver-image $(LOCAL_CLUSTERMESH_IMAGE)
	$(CILIUM_CLI) clustermesh enable --context kind-clustermesh2 --service-type NodePort --apiserver-image $(LOCAL_CLUSTERMESH_IMAGE)
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh1 --wait
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh2 --wait
	$(CILIUM_CLI) clustermesh connect --context kind-clustermesh1 --destination-context kind-clustermesh2
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh1 --wait
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh2 --wait


.PHONY: kind-ready
kind-ready:
	@$(ECHO_CHECK) kind is ready...
	@kind get clusters 2>&1 | grep "No kind clusters found." \
		&& exit 1 || exit 0

$(eval $(call KIND_ENV,kind-build-image-agent))
kind-build-image-agent: ## Build cilium-dev docker image
	$(QUIET)$(MAKE) dev-docker-image$(DEBUGGER_SUFFIX) DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

$(eval $(call KIND_ENV,kind-image-agent))
kind-image-agent: kind-ready kind-build-image-agent ## Build cilium-dev docker image and import it into kind.
	$(QUIET)kind load docker-image $(LOCAL_AGENT_IMAGE)

$(eval $(call KIND_ENV,kind-build-image-operator))
kind-build-image-operator: ## Build cilium-operator-dev docker image
	$(QUIET)$(MAKE) dev-docker-operator-generic-image$(DEBUGGER_SUFFIX) DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

$(eval $(call KIND_ENV,kind-image-operator))
kind-image-operator: kind-ready kind-build-image-operator ## Build cilium-operator-dev docker image and import it into kind.
	$(QUIET)kind load docker-image $(LOCAL_OPERATOR_IMAGE)

$(eval $(call KIND_ENV,kind-build-clustermesh-apiserver))
kind-build-clustermesh-apiserver: ## Build cilium-clustermesh-apiserver docker image
	$(QUIET)$(MAKE) docker-clustermesh-apiserver-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

.PHONY: kind-image
kind-image: ## Build cilium and operator images and import them into kind.
	$(MAKE) kind-image-agent
	$(MAKE) kind-image-operator

.PHONY: kind-install-cilium
kind-install-cilium: kind-ready ## Install a local Cilium version into the cluster.
	@echo "  INSTALL cilium"
	# cilium-cli doesn't support idempotent installs, so we uninstall and
	# reinstall here. https://github.com/cilium/cilium-cli/issues/205
	-$(CILIUM_CLI) uninstall >/dev/null
	# cilium-cli's --wait flag doesn't work, so we just force it to run
	# in the background instead and wait for the resources to be available.
	# https://github.com/cilium/cilium-cli/issues/1070
	$(CILIUM_CLI) install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-values.yaml \
		--version= \
		>/dev/null 2>&1 &

.PHONY: kind-uninstall-cilium
kind-uninstall-cilium: ## Uninstall Cilium from the cluster.
	@echo "  UNINSTALL cilium"
	-$(CILIUM_CLI) uninstall

.PHONY: kind-check-cilium
kind-check-cilium:
	@echo "  CHECK  cilium is ready..."
	$(CILIUM_CLI) status --wait --wait-duration 1s >/dev/null 2>/dev/null

# Template for kind debug targets. Parameters are:
# $(1) agent target
define DEBUG_KIND_TEMPLATE
.PHONY: kind-image$(1)-debug
kind-image$(1)-debug: export DEBUGGER_SUFFIX=-debug
kind-image$(1)-debug: export NOSTRIP=1
kind-image$(1)-debug: export NOOPT=1
kind-image$(1)-debug: ## Build cilium$(1) docker image with a dlv debugger wrapper and import it into kind.
	$(MAKE) kind-image$(1)
endef

# kind-image-agent-debug
$(eval $(call DEBUG_KIND_TEMPLATE,-agent))

# kind-image-operator-debug
$(eval $(call DEBUG_KIND_TEMPLATE,-operator))

$(eval $(call KIND_ENV,kind-debug-agent))
kind-debug-agent: ## Create a local kind development environment with cilium-agent attached to a debugger.
	$(QUIET)$(MAKE) kind-ready 2>/dev/null \
		|| $(MAKE) kind
	$(MAKE) kind-image-agent-debug
	# Not debugging cilium-operator here; any image is good enough.
	kind load docker-image $(LOCAL_OPERATOR_IMAGE) \
		|| $(MAKE) kind-image-operator
	$(MAKE) kind-check-cilium 2>/dev/null \
		|| $(MAKE) kind-install-cilium
	@echo "Attach delve to localhost on these ports to continue:"
	@echo " - 23401: cilium-agent (kind-control-plane)"
	@echo " - 23411: cilium-agent (kind-worker)"

$(eval $(call KIND_ENV,kind-debug))
kind-debug: ## Create a local kind development environment with cilium-agent & cilium-operator attached to a debugger.
	$(QUIET)$(MAKE) kind-ready 2>/dev/null \
		|| $(MAKE) kind
	$(MAKE) kind-image-agent-debug
	$(MAKE) kind-image-operator-debug
	$(MAKE) kind-check-cilium 2>/dev/null \
		|| $(MAKE) kind-install-cilium
	@echo "Attach delve to localhost on these ports to continue:"
	@echo " - 23401: cilium-agent    (kind-control-plane)"
	@echo " - 23411: cilium-agent    (kind-worker)"
	@echo " - 23511: cilium-operator (kind-worker)"

precheck: check-go-version logging-subsys-field ## Peform build precheck for the source code.
ifeq ($(SKIP_K8S_CODE_GEN_CHECK),"false")
	@$(ECHO_CHECK) contrib/scripts/check-k8s-code-gen.sh
	$(QUIET) contrib/scripts/check-k8s-code-gen.sh
endif
	@$(ECHO_CHECK) contrib/scripts/check-fmt.sh
	$(QUIET) contrib/scripts/check-fmt.sh
	@$(ECHO_CHECK) contrib/scripts/check-log-newlines.sh
	$(QUIET) contrib/scripts/check-log-newlines.sh
	@$(ECHO_CHECK) contrib/scripts/check-test-tags.sh
	$(QUIET) contrib/scripts/check-test-tags.sh
	@$(ECHO_CHECK) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) contrib/scripts/check-assert-deep-equals.sh
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	@$(ECHO_CHECK) contrib/scripts/check-viper.sh
	$(QUIET) contrib/scripts/check-viper.sh
ifeq ($(SKIP_CUSTOMVET_CHECK),"false")
	@$(ECHO_CHECK) contrib/scripts/custom-vet-check.sh
	$(QUIET) contrib/scripts/custom-vet-check.sh
endif
	@$(ECHO_CHECK) contrib/scripts/rand-check.sh
	$(QUIET) contrib/scripts/rand-check.sh

check-sources:
	@$(ECHO_CHECK) pkg/datapath/loader/check-sources.sh
	$(QUIET) pkg/datapath/loader/check-sources.sh

pprof-heap: ## Get Go pprof heap profile.
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/heap

pprof-profile: ## Get Go pprof profile.
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/profile

pprof-block: ## Get Go pprof block profile.
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/block

pprof-trace-5s: ## Get Go pprof trace for a duration of 5 seconds.
	curl http://localhost:6060/debug/pprof/trace?seconds=5

pprof-mutex: ## Get Go pprof mutex profile.
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/mutex

update-authors: ## Update AUTHORS file for Cilium repository.
	@echo "Updating AUTHORS file..."
	@echo "The following people, in alphabetical order, have either authored or signed" > AUTHORS
	@echo "off on commits in the Cilium repository:" >> AUTHORS
	@echo "" >> AUTHORS
	@contrib/scripts/extract_authors.sh >> AUTHORS
	@cat .authors.aux >> AUTHORS

test-docs: ## Build HTML documentation.
	$(MAKE) -C Documentation html

render-docs: ## Run server with live preview to render documentation.
	$(MAKE) -C Documentation live-preview

manpages: ## Generate manpage for Cilium CLI.
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages: ## Install manpages the Cilium CLI.
	cp man/* /usr/local/share/man/man1/
	mandb

postcheck: build ## Run Cilium build postcheck (update-cmdref, build documentation etc.).
	$(QUIET) SKIP_BUILD=true $(MAKE) $(SUBMAKEOPTS) -C Documentation check

licenses-all: ## Generate file with all the License from dependencies.
	@$(GO) run ./tools/licensegen > LICENSE.all || ( rm -f LICENSE.all ; false )

check-go-version: ## Check locally install Go version against required Go version.
ifneq ($(GO_MAJOR_AND_MINOR_VERSION),$(GO_INSTALLED_MAJOR_AND_MINOR_VERSION))
	@echo "Installed Go version $(GO_INSTALLED_MAJOR_AND_MINOR_VERSION) does not match requested Go version $(GO_MAJOR_AND_MINOR_VERSION)"
	@exit 1
else
	@$(ECHO_CHECK) "Installed Go version $(GO_INSTALLED_MAJOR_AND_MINOR_VERSION) matches required version $(GO_MAJOR_AND_MINOR_VERSION)"
endif

dev-doctor: ## Run Cilium dev-doctor to validate local development environment.
	$(QUIET)$(GO) version 2>/dev/null || ( echo "go not found, see https://golang.org/doc/install" ; false )
	$(QUIET)$(GO) run ./tools/dev-doctor

help: ## Display help for the Makefile, from https://www.thapaliya.com/en/writings/well-documented-makefiles/.
	$(call print_help_from_makefile)
	@# There is also a list of target we have to manually put the information about.
	@# These are templated targets.
	$(call print_help_line,"docker-cilium-image","Build cilium-agent docker image")
	$(call print_help_line,"dev-docker-image","Build cilium-agent development docker image")
	$(call print_help_line,"docker-plugin-image","Build cilium-docker plugin image")
	$(call print_help_line,"docker-hubble-relay-image","Build hubble-relay docker image")
	$(call print_help_line,"docker-clustermesh-apiserver-image","Build docker image for Cilium clustermesh APIServer")
	$(call print_help_line,"docker-operator-image","Build cilium-operator docker image")
	$(call print_help_line,"docker-operator-*-image","Build platform specific cilium-operator images(alibabacloud, aws, azure, generic)")
	$(call print_help_line,"docker-*-image-unstripped","Build unstripped version of above docker images(cilium, hubble-relay, operator etc.)")

.PHONY: help clean clean-container dev-doctor force generate-api generate-health-api generate-operator-api generate-hubble-api install licenses-all veryclean check-sources
force :;

# this top level run_bpf_tests target will run the bpf unit tests inside the Cilium Builder container.
# it exists here so the entire source code repo can be mounted into the container.
CILIUM_BUILDER_IMAGE=$(shell cat images/cilium/Dockerfile | grep "ARG CILIUM_BUILDER_IMAGE=" | cut -d"=" -f2)
run_bpf_tests:
	docker run -v $$(pwd):/src --privileged -w /src -e RUN_WITH_SUDO=false $(CILIUM_BUILDER_IMAGE) "make" "-C" "test/" "run_bpf_tests"