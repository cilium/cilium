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

GO_VERSION := $(shell cat GO_VERSION)
GO_MAJOR_AND_MINOR_VERSION := $(shell sed 's/\([0-9]\+\).\([0-9]\+\)\(.[0-9]\+\)\?/\1.\2/' GO_VERSION)
GO_IMAGE_VERSION := $(shell awk -F. '{ z=$$3; if (z == "") z=0; print $$1 "." $$2 "." z}' GO_VERSION)
GO_INSTALLED_MAJOR_AND_MINOR_VERSION := $(shell $(GO) version | sed 's/go version go\([0-9]\+\).\([0-9]\+\)\(.[0-9]\+\)\?.*/\1.\2/')

GO_CONTAINER := $(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) golang:$(GO_VERSION)
GOIMPORTS_VERSION ?= v0.1.12

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002 \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

TEST_UNITTEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

define generate_k8s_api
	cd "./vendor/k8s.io/code-generator" && \
	GO111MODULE=off bash ./generate-groups.sh $(1) \
	    $(2) \
	    $(3) \
	    $(4) \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

define generate_deepequal
	go run github.com/cilium/deepequal-gen \
	--input-dirs $(1) \
	-O zz_generated.deepequal \
	--go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

define generate_k8s_api_all
	$(call generate_k8s_api,all,github.com/cilium/cilium/pkg/k8s/client,$(1),$(2))
	$(call generate_deepequal,"$(call join-with-comma,$(foreach pkg,$(2),$(1)/$(subst ",,$(subst :,/,$(pkg)))))")
endef

define generate_k8s_api_deepcopy_deepequal
	$(call generate_k8s_api,deepcopy,github.com/cilium/cilium/pkg/k8s/client,$(1),$(2))
	@# Explanation for the 'subst' below:
	@#   $(subst ",,$(subst :,/,$(pkg))) - replace all ':' with '/' and replace
	@#    all '"' with '' from $pkg
	@#   $(foreach pkg,$(2),$(1)/$(subst ",,$(subst :,/,$(pkg)))) - for each
	@#    "$pkg", with the characters replaced, create a new string with the
	@#    prefix $(1)
	@#   Finally replace all spaces with commas from the generated strings.
	$(call generate_deepequal,"$(call join-with-comma,$(foreach pkg,$(2),$(1)/$(subst ",,$(subst :,/,$(pkg)))))")
endef

define generate_k8s_api_deepcopy_deepequal_client
	$(call generate_k8s_api,deepcopy$(comma)client,github.com/cilium/cilium/pkg/k8s/slim/k8s/$(1),$(2),$(3))
	$(call generate_deepequal,"$(call join-with-comma,$(foreach pkg,$(3),$(2)/$(subst ",,$(subst :,/,$(pkg)))))")
endef

define generate_k8s_protobuf
	go install k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo
	go install golang.org/x/tools/cmd/goimports

	go run k8s.io/code-generator/cmd/go-to-protobuf \
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
		--packages=$(1) \
		--go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

build: check-sources $(SUBDIRS) ## Builds all the components for Cilium by executing make in the respective sub directories.

build-container: check-sources ## Builds components required for cilium-agent container.
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i all; done

$(SUBDIRS): force ## Execute default make target(make all) for the provided subdirectory.
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

tests-privileged: ## Run Go tests including ones that require elevated privileges.
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

integration-tests: GO_TAGS_FLAGS+=integration_tests
integration-tests: start-kvstores ## Runs all integration tests.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C test/bpf/
ifeq ($(SKIP_VET),"false")
	$(MAKE) govet
endif
	$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(TESTPKGS) $(GOTEST_BASE) $(GOTEST_COVER_OPTS) | $(GOTEST_FORMATTER)
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
manifests: ## Generate K8s manifests e.g. CRD, RBAC etc.
	$(eval TMPDIR := $(shell mktemp -d))
	$(QUIET)$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen $(CRD_OPTIONS) paths="$(PWD)/pkg/k8s/apis/cilium.io/v2;$(PWD)/pkg/k8s/apis/cilium.io/v2alpha1" output:crd:artifacts:config="$(TMPDIR)"
	$(QUIET)$(GO) run ./tools/crdcheck "$(TMPDIR)"
	mv ${TMPDIR}/cilium.io_ciliumnetworkpolicies.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumclusterwidenetworkpolicies.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumclusterwidenetworkpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumendpoints.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumendpoints.yaml
	mv ${TMPDIR}/cilium.io_ciliumidentities.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumidentities.yaml
	mv ${TMPDIR}/cilium.io_ciliumnodes.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnodes.yaml
	mv ${TMPDIR}/cilium.io_ciliumexternalworkloads.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumexternalworkloads.yaml
	mv ${TMPDIR}/cilium.io_ciliumlocalredirectpolicies.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumlocalredirectpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumegressgatewaypolicies.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumegressgatewaypolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumendpointslices.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumendpointslices.yaml
	mv ${TMPDIR}/cilium.io_ciliumclusterwideenvoyconfigs.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumclusterwideenvoyconfigs.yaml
	mv ${TMPDIR}/cilium.io_ciliumenvoyconfigs.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2/ciliumenvoyconfigs.yaml
	mv ${TMPDIR}/cilium.io_ciliumbgppeeringpolicies.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumbgppeeringpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumloadbalancerippools.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumloadbalancerippools.yaml
	mv ${TMPDIR}/cilium.io_ciliumnodeconfigs.yaml ./pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumnodeconfigs.yaml
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
	-$(QUIET)$(GO_CONTAINER) bash -c "go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) && ./contrib/scripts/format-api.sh api/v1/client/ api/v1/models/ api/v1/server/"

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
	-$(QUIET)$(GO_CONTAINER) bash -c "go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) && ./contrib/scripts/format-api.sh api/v1/health/"

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
	-$(QUIET)$(GO_CONTAINER) bash -c "go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) && ./contrib/scripts/format-api.sh api/v1/operator/"

generate-hubble-api: api/v1/flow/flow.proto api/v1/peer/peer.proto api/v1/observer/observer.proto api/v1/relay/relay.proto ## Generate hubble proto Go sources.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C api/v1

generate-k8s-api: ## Generate Cilium k8s API client, deepcopy and deepequal Go sources.
	$(ASSERT_CILIUM_MODULE)

	$(call generate_k8s_protobuf,$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1beta1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/apiextensions/v1)
	$(call generate_k8s_api_deepcopy_deepequal_client,client,github.com/cilium/cilium/pkg/k8s/slim/k8s/api,"$\
	discovery:v1beta1\
	discovery:v1\
	networking:v1\
	core:v1")
	$(call generate_k8s_api_deepcopy_deepequal_client,apiextensions-client,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"$\
	apiextensions:v1")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"$\
	util:intstr\
	meta:v1\
	meta:v1beta1")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/k8s/slim/k8s,"$\
	apis:labels")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg,"$\
	aws:types\
	azure:types\
	ipam:types\
	alibabacloud:types\
	k8s:types\
	k8s:utils\
	maps:auth\
	maps:ctmap\
	maps:encrypt\
	maps:eppolicymap\
	maps:eventsmap\
	maps:fragmap\
	maps:ipcache\
	maps:ipmasq\
	maps:lbmap\
	maps:lxcmap\
	maps:metricsmap\
	maps:nat\
	maps:neighborsmap\
	maps:policymap\
	maps:signalmap\
	maps:sockmap\
	maps:srv6map\
	maps:tunnel\
	maps:vtep\
	node:types\
	policy:api\
	service:store")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/policy,"api:kafka")
	$(call generate_k8s_api_all,github.com/cilium/cilium/pkg/k8s/apis,"cilium.io:v2 cilium.io:v2alpha1")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/aws,"eni:types")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/alibabacloud,"eni:types")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/api,"v1:models")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium,"$\
	pkg:bpf\
	pkg:k8s\
	pkg:labels\
	pkg:loadbalancer\
	pkg:tuple\
	pkg:recorder")

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
	$(QUIET)./contrib/scripts/kind.sh

kind-down: ## Destroy a kind cluster for Cilium development.
	$(QUIET)./contrib/scripts/kind-down.sh

.PHONY: kind-clustermesh
kind-clustermesh: ## Create two kind clusters for clustermesh development.
	@echo " If you have problems with too many open file, check https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files"
	$(QUIET) CLUSTER_NAME=clustermesh1 IPFAMILY=ipv4 PODSUBNET=10.1.0.0/16 SERVICESUBNET=172.20.1.0/24 ./contrib/scripts/kind.sh
	$(QUIET) CLUSTER_NAME=clustermesh2 AGENTPORTPREFIX=236 OPERATORPORTPREFIX=237 IPFAMILY=ipv4 PODSUBNET=10.2.0.0/16 SERVICESUBNET=172.20.2.0/24 ./contrib/scripts/kind.sh

.PHONY: kind-clustermesh-down
kind-clustermesh-down: ## Destroy kind clusters for clustermesh development.
	kind delete clusters clustermesh1
	kind delete clusters clustermesh2

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

.PHONY: kind-install-cilium-clustermesh
kind-install-cilium-clustermesh: kind-clustermesh-ready ## Install a local Cilium version into the clustermesh clusters and enable clustermesh.
	@echo "  INSTALL cilium on clustermesh1 cluster"
	kubectl config use kind-clustermesh1
	-cilium uninstall >/dev/null
	cilium install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-clustermesh1.yaml \
		--version=
	@echo "  INSTALL cilium on clustermesh2 cluster"
	kubectl config use kind-clustermesh2
	-cilium uninstall >/dev/null
	cilium install \
		--inherit-ca kind-clustermesh1 \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-clustermesh2.yaml \
		--version=
	@echo "  Enabling clustermesh"
	cilium clustermesh enable --context kind-clustermesh1 --service-type NodePort --apiserver-image $(LOCAL_CLUSTERMESH_IMAGE)
	cilium clustermesh enable --context kind-clustermesh2 --service-type NodePort --apiserver-image $(LOCAL_CLUSTERMESH_IMAGE)
	cilium clustermesh status --context kind-clustermesh1 --wait
	cilium clustermesh status --context kind-clustermesh2 --wait
	cilium clustermesh connect --context kind-clustermesh1 --destination-context kind-clustermesh2
	cilium clustermesh status --context kind-clustermesh1 --wait
	cilium clustermesh status --context kind-clustermesh2 --wait


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
	-cilium uninstall >/dev/null
	# cilium-cli's --wait flag doesn't work, so we just force it to run
	# in the background instead and wait for the resources to be available.
	# https://github.com/cilium/cilium-cli/issues/1070
	cilium install \
		--chart-directory=$(ROOT_DIR)/install/kubernetes/cilium \
		--helm-values=$(ROOT_DIR)/contrib/testing/kind-values.yaml \
		--version= \
		>/dev/null 2>&1 &

.PHONY: kind-check-cilium
kind-check-cilium:
	@echo "  CHECK  cilium is ready..."
	cilium status --wait --wait-duration 1s >/dev/null 2>/dev/null

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
	@$(ECHO_CHECK) contrib/scripts/check-privileged-tests-tags.sh
	$(QUIET) contrib/scripts/check-privileged-tests-tags.sh
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

update-go-version: ## Update Go version for all the components (images, CI, dev-doctor etc.).
	# Update dev-doctor Go version.
	$(QUIET) sed -i 's/^const minGoVersionStr = ".*"/const minGoVersionStr = "$(GO_MAJOR_AND_MINOR_VERSION)"/' tools/dev-doctor/config.go
	@echo "Updated go version in tools/dev-doctor to $(GO_MAJOR_AND_MINOR_VERSION)"
	# Update Go version in GitHub action config.
	$(QUIET) for fl in $(shell find .github/workflows -name "*.yaml" -print) ; do sed -i 's/go-version: .*/go-version: $(GO_IMAGE_VERSION)/g' $$fl ; done
	@echo "Updated go version in GitHub Actions to $(GO_IMAGE_VERSION)"
	# Update Go version in main.go.
	$(QUIET) for fl in $(shell find .  -name main.go -not -path "./vendor/*" -print); do \
		sed -i \
			-e 's|^//go:build go.*|//go:build go$(GO_MAJOR_AND_MINOR_VERSION)|g' \
			$$fl ; \
	done
	# Update Go version in Travis CI config.
	$(QUIET) sed -i 's/go: ".*/go: "$(GO_VERSION)"/g' .travis.yml
	@echo "Updated go version in .travis.yml to $(GO_VERSION)"
	# Update Go version in test scripts.
	$(QUIET) sed -i 's/GO_VERSION=.*/GO_VERSION="$(GO_VERSION)"/g' test/kubernetes-test.sh
	$(QUIET) sed -i 's/GOLANG_VERSION=.*/GOLANG_VERSION="$(GO_VERSION)"/g' test/packet/scripts/install.sh
	@echo "Updated go version in test scripts to $(GO_VERSION)"
	# Update Go version in Dockerfiles.
	$(QUIET) sed -i 's/GOLANG_VERSION=.*/GOLANG_VERSION=$(GO_VERSION)/g' contrib/backporting/Dockerfile

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
