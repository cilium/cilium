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
SUBDIR_RELAY_CONTAINER := hubble-relay

ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif

# Add the ability to override variables
-include Makefile.override

# List of subdirectories used for global "make build", "make clean", etc
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) $(SUBDIR_OPERATOR_CONTAINER) plugins tools $(SUBDIR_RELAY_CONTAINER) bpf

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
BENCHFLAGS_EVAL := -bench=$(BENCH) -run=^$$ -benchtime=10s
BENCHFLAGS ?= $(BENCHFLAGS_EVAL)
SKIP_KVSTORES ?= "false"
SKIP_K8S_CODE_GEN_CHECK ?= "true"
SKIP_CUSTOMVET_CHECK ?= "false"

JOB_BASE_NAME ?= cilium_test

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002"

TEST_UNITTEST_LDFLAGS=

build: $(SUBDIRS) ## Builds all the components for Cilium by executing make in the respective sub directories.

build-container: ## Builds components required for cilium-agent container.
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

build-container-hubble-relay:
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_RELAY_CONTAINER) all

$(SUBDIRS): force ## Execute default make target(make all) for the provided subdirectory.
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

tests-privileged: ## Run Go tests including ones that require elevated privileges.
	@$(ECHO_CHECK) running privileged tests...
	PRIVILEGED_TESTS=true PATH=$(PATH):$(ROOT_DIR)/bpf $(GO_TEST) -p 1 $(TEST_LDFLAGS) \
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
	-@# Remove generated code from coverage
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

install-container-binary-hubble-relay:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(MAKE) $(SUBMAKEOPTS) -C $(SUBDIR_RELAY_CONTAINER) install-binary

# Workaround for not having git in the build environment
# Touch the file only if needed
GIT_VERSION: force
	@if [ "$(GIT_VERSION)" != "`cat 2>/dev/null GIT_VERSION`" ] ; then echo "$(GIT_VERSION)" >GIT_VERSION; fi

check_deps:
	@$(CILIUM_CLI) --help > /dev/null 2>&1 || ( echo "ERROR: '$(CILIUM_CLI)' not found. Please install it." && exit 1)

include Makefile.kind

-include Makefile.docker

manifests: ## Generate K8s manifests e.g. CRD, RBAC etc.
	contrib/scripts/k8s-manifests-gen.sh

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

generate-kvstoremesh-api: api/v1/kvstoremesh/openapi.yaml ## Generate kvstoremesh client, model and server code from openapi spec.
	@$(ECHO_GEN)api/v1/kvstoremesh/openapi.yaml
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 \
		-t api/v1/kvstoremesh/ \
		-f api/v1/kvstoremesh/openapi.yaml \
		--default-scheme=http \
		-C api/v1/cilium-server.yml \
		-r hack/spdx-copyright-header.txt
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 \
		-t api/v1/kvstoremesh/ \
		-f api/v1/kvstoremesh/openapi.yaml \
		-r hack/spdx-copyright-header.txt
	@# sort goimports automatically
	-$(QUIET)$(GO) run golang.org/x/tools/cmd/goimports -w ./api/v1/kvstoremesh

generate-hubble-api: api/v1/flow/flow.proto api/v1/peer/peer.proto api/v1/observer/observer.proto api/v1/relay/relay.proto ## Generate hubble proto Go sources.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C api/v1

define generate_deepequal
	$(GO) run github.com/cilium/deepequal-gen \
	--input-dirs $(subst $(space),$(comma),$(1)) \
	--go-header-file "$$PWD/hack/custom-boilerplate.go.txt" \
	--output-file-base zz_generated.deepequal \
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
		--proto-import="$$PWD" \
		--proto-import="$$PWD/vendor" \
		--proto-import="$$PWD/tools/protobuf" \
		--packages=$(subst $(newline),$(comma),$(1)) \
		--go-header-file "$$PWD/hack/custom-boilerplate.go.txt" \
		--output-dir=$$GOPATH/src
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

.PHONY: generate-k8s-api-local
generate-k8s-api-local:
	$(ASSERT_CILIUM_MODULE)

	$(eval TMPDIR := $(shell mktemp -d -t cilium.tmpXXXXXXXX))

	$(QUIET) $(call generate_k8s_protobuf,${K8S_PROTO_PACKAGES},"$(TMPDIR)")

	$(eval DEEPEQUAL_PACKAGES := $(shell grep "\+deepequal-gen" -l -r --include \*.go --exclude-dir 'vendor' . | xargs dirname {} | sort | uniq | grep -x -v '.' | sed 's|\.\/|github.com/cilium/cilium\/|g'))
	$(QUIET) $(call generate_deepequal,${DEEPEQUAL_PACKAGES},"$(TMPDIR)")

	$(QUIET) contrib/scripts/k8s-code-gen.sh "$(TMPDIR)"

	$(QUIET) rm -rf "$(TMPDIR)"

.PHONY: generate-k8s-api
generate-k8s-api: ## Generate Cilium k8s API client, deepcopy and deepequal Go sources.
	RUN_AS_NONROOT=1 contrib/scripts/builder.sh \
		$(MAKE) -C /go/src/github.com/cilium/cilium/ generate-k8s-api-local

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
	@echo "Visit https://github.com/cilium/release/issues/new/choose to initiate the release process."

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
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	@$(ECHO_CHECK) contrib/scripts/check-viper.sh
	$(QUIET) contrib/scripts/check-viper.sh
ifeq ($(SKIP_CUSTOMVET_CHECK),"false")
	@$(ECHO_CHECK) contrib/scripts/custom-vet-check.sh
	$(QUIET) contrib/scripts/custom-vet-check.sh
endif
	@$(ECHO_CHECK) contrib/scripts/check-time.sh
	$(QUIET) contrib/scripts/check-time.sh
	@$(ECHO_CHECK) contrib/scripts/check-go-testdata.sh
	$(QUIET) contrib/scripts/check-go-testdata.sh
	@$(ECHO_CHECK) contrib/scripts/check-source-info.sh
	$(QUIET) contrib/scripts/check-source-info.sh
	@$(ECHO_CHECK) contrib/scripts/check-xfrmstate.sh
	$(QUIET) contrib/scripts/check-xfrmstate.sh
	@$(ECHO_CHECK) contrib/scripts/check-legacy-header-guard.sh
	$(QUIET) contrib/scripts/check-legacy-header-guard.sh
	@$(ECHO_CHECK) contrib/scripts/check-logrus.sh
	$(QUIET) contrib/scripts/check-logrus.sh

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

.PHONY: help clean clean-container dev-doctor force generate-api generate-health-api generate-operator-api generate-kvstoremesh-api generate-hubble-api install licenses-all veryclean run_bpf_tests run-builder
force :;

BPF_TEST_FILE ?= ""

run_bpf_tests: ## Build and run the BPF unit tests using the cilium-builder container image.
	DOCKER_ARGS=--privileged contrib/scripts/builder.sh \
		"make" "-j$(shell nproc)" "-C" "bpf/tests/" "run" "BPF_TEST_FILE=$(BPF_TEST_FILE)"

run-builder: ## Drop into a shell inside a container running the cilium-builder image.
	DOCKER_ARGS=-it contrib/scripts/builder.sh bash
