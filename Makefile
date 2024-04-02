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

SUBDIRS_CILIUM_CONTAINER := cilium-dbg daemon cilium-health bugtool tools/mount tools/sysctlfix plugins/cilium-cni
SUBDIR_OPERATOR_CONTAINER := operator

ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif

# Add the ability to override variables
-include Makefile.override

# List of subdirectories used for global "make build", "make clean", etc
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) $(SUBDIR_OPERATOR_CONTAINER) plugins tools hubble-relay bpf

# Filter out any directories where the parent directory is also present, to avoid
# building or cleaning a subdirectory twice.
# For example: The directory "tools" is transformed into a match pattern "tools/%",
# which is then used to filter out items such as "tools/mount" and "tools/sysctlfx"
SUBDIRS := $(filter-out $(foreach dir,$(SUBDIRS),$(dir)/%),$(SUBDIRS))

# Space-separated list of Go packages to test, equivalent to 'go test' package patterns.
# Because is treated as a Go package pattern, the special '...' sequence is supported,
# meaning 'all subpackages of the given package'.
TESTPKGS ?= ./...

GOTEST_BASE := -timeout 600s
GOTEST_COVER_OPTS += -coverprofile=coverage.out
BENCH_EVAL := "."
BENCH ?= $(BENCH_EVAL)
BENCHFLAGS_EVAL := -bench=$(BENCH) -run=^$ -benchtime=10s
BENCHFLAGS ?= $(BENCHFLAGS_EVAL)
SKIP_KVSTORES ?= "false"
SKIP_K8S_CODE_GEN_CHECK ?= "true"
SKIP_CUSTOMVET_CHECK ?= "false"

JOB_BASE_NAME ?= cilium_test

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002 \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

TEST_UNITTEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

build: check-sources $(SUBDIRS) ## Builds all the components for Cilium by executing make in the respective sub directories.

build-container: check-sources ## Builds components required for cilium-agent container.
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i all; done

build-container-operator: ## Builds components required for cilium-operator container.
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) all

build-container-operator-generic: ## Builds components required for a cilium-operator generic variant container.
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) cilium-operator-generic

build-container-operator-aws: ## Builds components required for a cilium-operator aws variant container.
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) cilium-operator-aws

build-container-operator-azure: ## Builds components required for a cilium-operator azure variant container.
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) cilium-operator-azure

build-container-operator-alibabacloud: ## Builds components required for a cilium-operator alibabacloud variant container.
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) cilium-operator-alibabacloud

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

install-container-binary-operator: ## Install binaries for all components required for cilium-operator container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) install

install-container-binary-operator-generic: ## Install binaries for all components required for cilium-operator generic variant container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) install-generic

install-container-binary-operator-aws: ## Install binaries for all components required for cilium-operator aws variant container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) install-aws

install-container-binary-operator-azure: ## Install binaries for all components required for cilium-operator azure variant container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) install-azure

install-container-binary-operator-alibabacloud: ## Install binaries for all components required for cilium-operator alibabacloud variant container.
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_OPERATOR_CONTAINER) install-alibabacloud

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
                        ciliumbgpclusterconfigs \
                        ciliumbgppeerconfigs \
                        ciliumbgpadvertisements \
                        ciliumbgpnodeconfigs \
                        ciliumbgpnodeconfigoverrides \
                        ciliumloadbalancerippools \
                        ciliumnodeconfigs \
                        ciliumcidrgroups \
                        ciliuml2announcementpolicies \
                        ciliumpodippools

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
	bash ./generate-internal-groups.sh $(1) \
	    $(2) \
	    "" \
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
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION:v%=%),$(GOLANGCILINT_VERSION)))
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
	$(QUIET)SED=$(SED) ./contrib/scripts/kind.sh

kind-egressgw: ## Create a kind cluster for egress gateway Cilium development.
	$(QUIET)SED=$(SED) WORKERS=3 ./contrib/scripts/kind.sh
	kubectl patch node kind-worker3 --type=json -p='[{"op":"add","path":"/metadata/labels/cilium.io~1no-schedule","value":"true"}]'

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

.PHONY: kind-bgp-v4
kind-bgp-v4:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v4 deploy

.PHONY: kind-bgp-v4-down
kind-bgp-v4-down:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v4 destroy

.PHONY: kind-bgp-v4-apply-policy
kind-bgp-v4-apply-policy:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v4 apply-policy

.PHONY: kind-bgp-v6
kind-bgp-v6:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v6 deploy

.PHONY: kind-bgp-v6-down
kind-bgp-v6-down:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v6 destroy

.PHONY: kind-bgp-v6-apply-policy
kind-bgp-v6-apply-policy:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-v6 apply-policy

.PHONY: kind-bgp-dual
kind-bgp-dual:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-dual deploy

.PHONY: kind-bgp-dual-down
kind-bgp-dual-down:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-dual destroy

.PHONY: kind-bgp-dual-apply-policy
kind-bgp-dual-apply-policy:
	$(QUIET) $(MAKE) -C contrib/containerlab/bgp-cplane-dev-dual apply-policy

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

ENABLE_KVSTOREMESH ?= false
$(eval $(call KIND_ENV,kind-install-cilium-clustermesh))
kind-install-cilium-clustermesh: kind-clustermesh-ready ## Install a local Cilium version into the clustermesh clusters and enable clustermesh.
	@echo "  INSTALL cilium on clustermesh1 cluster"
	-$(CILIUM_CLI) --context=kind-clustermesh1 uninstall >/dev/null
	$(CILIUM_CLI) --context=kind-clustermesh1 install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--values=$(ROOT_DIR)/contrib/testing/kind-clustermesh1.yaml \
		--set=image.override=$(LOCAL_AGENT_IMAGE) \
		--set=operator.image.override=$(LOCAL_OPERATOR_IMAGE) \
		--set=clustermesh.apiserver.image.override=$(LOCAL_CLUSTERMESH_IMAGE) \
		--set=clustermesh.apiserver.kvstoremesh.enabled=$(ENABLE_KVSTOREMESH)

	@echo "  INSTALL cilium on clustermesh2 cluster"
	-$(CILIUM_CLI) --context=kind-clustermesh2 uninstall >/dev/null
	$(KUBECTL) --context=kind-clustermesh1 get secret -n kube-system cilium-ca -o yaml | \
		$(KUBECTL) --context=kind-clustermesh2 replace --force -f -
	$(CILIUM_CLI) --context=kind-clustermesh2 install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--values=$(ROOT_DIR)/contrib/testing/kind-clustermesh2.yaml \
		--set=image.override=$(LOCAL_AGENT_IMAGE) \
		--set=operator.image.override=$(LOCAL_OPERATOR_IMAGE) \
		--set=clustermesh.apiserver.image.override=$(LOCAL_CLUSTERMESH_IMAGE) \
		--set=clustermesh.apiserver.kvstoremesh.enabled=$(ENABLE_KVSTOREMESH)

	@echo "  CONNECT the two clusters"
	$(CILIUM_CLI) clustermesh connect --context kind-clustermesh1 --destination-context kind-clustermesh2
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh1 --wait
	$(CILIUM_CLI) clustermesh status --context kind-clustermesh2 --wait

KIND_CLUSTER_NAME ?= $(shell kind get clusters -q | head -n1)

.PHONY: kind-ready
kind-ready:
	@$(ECHO_CHECK) kind-ready
	@if [ -n "$(shell kind get clusters -q)" ]; then echo "kind is ready"; else echo "kind not ready"; exit 1; fi

$(eval $(call KIND_ENV,kind-build-image-agent))
kind-build-image-agent: ## Build cilium-dev docker image
	$(QUIET)$(MAKE) dev-docker-image$(DEBUGGER_SUFFIX) DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

$(eval $(call KIND_ENV,kind-image-agent))
kind-image-agent: kind-ready kind-build-image-agent ## Build cilium-dev docker image and import it into kind.
	$(QUIET)kind load docker-image $(LOCAL_AGENT_IMAGE) -n $(KIND_CLUSTER_NAME)

$(eval $(call KIND_ENV,kind-build-image-operator))
kind-build-image-operator: ## Build cilium-operator-dev docker image
	$(QUIET)$(MAKE) dev-docker-operator-generic-image$(DEBUGGER_SUFFIX) DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

$(eval $(call KIND_ENV,kind-image-operator))
kind-image-operator: kind-ready kind-build-image-operator ## Build cilium-operator-dev docker image and import it into kind.
	$(QUIET)kind load docker-image $(LOCAL_OPERATOR_IMAGE) -n $(KIND_CLUSTER_NAME)

$(eval $(call KIND_ENV,kind-build-clustermesh-apiserver))
kind-build-clustermesh-apiserver: ## Build cilium-clustermesh-apiserver docker image
	$(QUIET)$(MAKE) docker-clustermesh-apiserver-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)

.PHONY: kind-image
kind-image: ## Build cilium and operator images and import them into kind.
	$(MAKE) kind-image-agent
	$(MAKE) kind-image-operator

define KIND_VALUES_FAST_FILES
--helm-values=$(ROOT_DIR)/contrib/testing/kind-common.yaml \
--helm-values=$(ROOT_DIR)/contrib/testing/kind-fast.yaml
endef

ifneq ("$(wildcard $(ROOT_DIR)/contrib/testing/kind-custom.yaml)","")
	KIND_VALUES_FAST_FILES := $(KIND_VALUES_FAST_FILES) --helm-values=$(ROOT_DIR)/contrib/testing/kind-custom.yaml
endif

.PHONY: kind-install-cilium-fast
kind-install-cilium-fast: kind-ready ## Install a local Cilium version into the cluster.
	@echo "  INSTALL cilium"
	docker pull quay.io/cilium/cilium-ci:latest
	for cluster_name in $${KIND_CLUSTERS:-$(shell kind get clusters)}; do \
		kind load docker-image --name $$cluster_name quay.io/cilium/cilium-ci:latest; \
		$(CILIUM_CLI) --context=kind-$$cluster_name uninstall >/dev/null 2>&1 || true; \
		$(CILIUM_CLI) install --context=kind-$$cluster_name \
			--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
			$(KIND_VALUES_FAST_FILES) \
			--version= >/dev/null 2>&1 & \
	done

.PHONY: build-cli
build-cli: ## Build cilium cli binary
	$(QUIET)$(MAKE) -C cilium-dbg GOOS=linux

.PHONY: build-agent
build-agent: ## Build cilium daemon binary
	$(QUIET)$(MAKE) -C daemon GOOS=linux

.PHONY: build-operator
build-operator: ## Build cilium operator binary
	$(QUIET)$(MAKE) -C operator cilium-operator-generic GOOS=linux

.PHONY: build-clustermesh-apiserver
build-clustermesh-apiserver: ## Build cilium clustermesh-apiserver binary
	$(QUIET)$(MAKE) -C clustermesh-apiserver  GOOS=linux

.PHONY: kind-image-fast-agent
kind-image-fast-agent: kind-ready build-cli build-agent ## Build cilium cli and daemon binaries. Copy the bins and bpf files to kind nodes.
	$(eval dst:=/cilium-binaries)
	for cluster_name in $${KIND_CLUSTERS:-$(shell kind get clusters)}; do \
		for node_name in $$(kind get nodes -n "$$cluster_name"); do \
			docker exec -ti $${node_name} mkdir -p "${dst}"; \
			\
			docker exec -ti $${node_name} rm -rf "${dst}/var/lib/cilium"; \
			docker exec -ti $${node_name} mkdir -p "${dst}/var/lib/cilium"; \
			docker cp "./bpf/" $${node_name}:"${dst}/var/lib/cilium/bpf"; \
			docker exec -ti $${node_name} find "${dst}/var/lib/cilium/bpf" -type f -exec chmod 0644 {} + ;\
			\
			docker exec -ti $${node_name} rm -f "${dst}/cilium-dbg"; \
			docker cp "./cilium-dbg/cilium-dbg" $${node_name}:"${dst}"; \
			docker exec -ti $${node_name} chmod +x "${dst}/cilium-dbg"; \
			\
			docker exec -ti $${node_name} rm -f "${dst}/cilium-agent"; \
			docker cp "./daemon/cilium-agent" $${node_name}:"${dst}"; \
			docker exec -ti $${node_name} chmod +x "${dst}/cilium-agent"; \
		done; \
		kubectl --context=kind-$${cluster_name} delete pods -n kube-system -l k8s-app=cilium --force; \
	done

.PHONY: kind-image-fast-operator
kind-image-fast-operator: kind-ready build-operator ## Build cilium operator binary and copy it to all kind nodes.
	$(eval dst:=/cilium-binaries)
	for cluster_name in $${KIND_CLUSTERS:-$(shell kind get clusters)}; do \
		for node_name in $$(kind get nodes -n "$$cluster_name"); do \
			docker exec -ti $${node_name} mkdir -p "${dst}"; \
			\
			docker exec -ti $${node_name} rm -f "${dst}/cilium-operator-generic"; \
			docker cp "./operator/cilium-operator-generic" $${node_name}:"${dst}"; \
			docker exec -ti $${node_name} chmod +x "${dst}/cilium-operator-generic"; \
		done; \
	kubectl --context=kind-$${cluster_name} delete pods -n kube-system -l name=cilium-operator --force; \
	done

.PHONY: kind-image-fast-clustermesh-apiserver
kind-image-fast-clustermesh-apiserver: kind-ready build-clustermesh-apiserver ## Build clustermesh-apiserver binary and copy it to all kind nodes.
	$(eval dst:=/cilium-binaries)
	for cluster_name in $${KIND_CLUSTERS:-$(shell kind get clusters)}; do \
		for node_name in $$(kind get nodes -n "$$cluster_name"); do \
			docker exec -ti $${node_name} mkdir -p "${dst}"; \
			\
			docker exec -ti $${node_name} rm -f "${dst}/clustermesh-apiserver"; \
			docker cp "./clustermesh-apiserver/clustermesh-apiserver" $${node_name}:"${dst}"; \
			docker exec -ti $${node_name} chmod +x "${dst}/clustermesh-apiserver"; \
		done; \
	kubectl --context=kind-$${cluster_name} delete pods -n kube-system -l k8s-app=clustermesh-apiserver --force; \
	done

.PHONY: kind-image-fast
kind-image-fast: kind-image-fast-agent kind-image-fast-operator kind-image-fast-clustermesh-apiserver ## Build all binaries and copy them to kind nodes.

define KIND_VALUES_FILES
--helm-values=$(ROOT_DIR)/contrib/testing/kind-common.yaml \
--helm-values=$(ROOT_DIR)/contrib/testing/kind-values.yaml
endef

ifneq ("$(wildcard $(ROOT_DIR)/contrib/testing/kind-custom.yaml)","")
	KIND_VALUES_FILES := $(KIND_VALUES_FILES) --helm-values=$(ROOT_DIR)/contrib/testing/kind-custom.yaml
endif

.PHONY: kind-install-cilium
kind-install-cilium: kind-ready ## Install a local Cilium version into the cluster.
	@echo "  INSTALL cilium"
	# cilium-cli doesn't support idempotent installs, so we uninstall and
	# reinstall here. https://github.com/cilium/cilium-cli/issues/205
	-@$(CILIUM_CLI) uninstall >/dev/null 2>&1 || true

	# cilium-cli's --wait flag doesn't work, so we just force it to run
	# in the background instead and wait for the resources to be available.
	# https://github.com/cilium/cilium-cli/issues/1070
	$(CILIUM_CLI) install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		$(KIND_VALUES_FILES) \
		--version= \
		>/dev/null 2>&1 &


.PHONY: kind-egressgw-install-cilium
kind-egressgw-install-cilium: kind-ready ## Install a local Cilium version into the cluster.
	@echo "  INSTALL cilium"
	# cilium-cli doesn't support idempotent installs, so we uninstall and
	# reinstall here. https://github.com/cilium/cilium-cli/issues/205
	-@$(CILIUM_CLI) uninstall >/dev/null 2>&1 || true

	# cilium-cli's --wait flag doesn't work, so we just force it to run
	# in the background instead and wait for the resources to be available.
	# https://github.com/cilium/cilium-cli/issues/1070
	$(CILIUM_CLI) install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		$(KIND_VALUES_FILES) \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-egressgw-values.yaml \
		--nodes-without-cilium \
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

precheck: logging-subsys-field ## Peform build precheck for the source code.
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
	@$(ECHO_CHECK) contrib/scripts/check-time.sh
	$(QUIET) contrib/scripts/check-time.sh
	@$(ECHO_CHECK) contrib/scripts/check-go-testdata.sh
	$(QUIET) contrib/scripts/check-go-testdata.sh

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

generate-crd-docs: ## Generate CRD List for documentation
	$(QUIET)$(GO) run ./tools/crdlistgen

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
	docker run --rm --privileged \
		-v $$(pwd):/src -w /src \
		$(CILIUM_BUILDER_IMAGE) \
		"make" "-j$(shell nproc)" "-C" "bpf/tests/" "all" "run"

run-builder:
	docker run -it --rm -v $$(pwd):/go/src/github.com/cilium/cilium $(CILIUM_BUILDER_IMAGE) bash
