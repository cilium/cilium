# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

all: precheck build postcheck
	@echo "Build finished."

debug: export NOOPT=1
debug: export NOSTRIP=1
debug: all

include Makefile.defs

# This is a no-op unless DOCKER_BUILDKIT is defined
# Provides buildkit specific defaults BUILD_DIR and DOCKER_BUILD_DIR
include Makefile.buildkit

# Use the main repo as the build-context by default.
DOCKER_BUILD_DIR ?= .
BUILD_DIR ?= .

SUBDIRS_CILIUM_CONTAINER := proxylib envoy bpf cilium daemon cilium-health bugtool
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) operator plugins tools hubble-relay

SUBDIRS_CILIUM_CONTAINER += plugins/cilium-cni
ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif

GOFILES_EVAL := $(subst _$(ROOT_DIR)/,,$(shell $(GO_LIST) -find -e ./...))
GOFILES ?= $(GOFILES_EVAL)
TESTPKGS_EVAL := $(subst github.com/cilium/cilium/,,$(shell echo $(GOFILES) | \
	sed 's/ /\n/g' | \
	grep -v '/api/v1\|/vendor\|/contrib\|/$(BUILD_DIR)/' | \
	grep -v '/test'))
TESTPKGS_EVAL += "test/helpers/logutils"
TESTPKGS ?= $(TESTPKGS_EVAL)
GOLANG_SRCFILES := $(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v vendor | sort | uniq)
K8S_CRD_EVAL := $(addprefix $(ROOT_DIR)/,$(shell git ls-files $(ROOT_DIR)/examples/crds | grep -v .gitignore | tr "\n" ' '))
K8S_CRD_FILES ?= $(K8S_CRD_EVAL)

SWAGGER_VERSION := v0.25.0
SWAGGER := $(CONTAINER_ENGINE) run -u $(shell id -u):$(shell id -g) --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) --entrypoint swagger quay.io/goswagger/swagger:$(SWAGGER_VERSION)

COVERPKG_EVAL := $(shell if [ $$(echo "$(TESTPKGS)" | wc -w) -gt 1 ]; then echo "./..."; else echo "github.com/cilium/cilium/$(TESTPKGS)"; fi)
COVERPKG ?= $(COVERPKG_EVAL)
GOTEST_BASE := -test.v -timeout 360s
GOTEST_UNIT_BASE := $(GOTEST_BASE) -check.vv
GOTEST_COVER_OPTS += -coverprofile=coverage.out -coverpkg $(COVERPKG)
BENCH_EVAL := "."
BENCH ?= $(BENCH_EVAL)
BENCHFLAGS_EVAL := -bench=$(BENCH) -run=^$ -benchtime=10s
BENCHFLAGS ?= $(BENCHFLAGS_EVAL)
# Level of logs emitted to console during unit test runs
LOGLEVEL ?= "error"
SKIP_VET ?= "false"
SKIP_KVSTORES ?= "false"
SKIP_K8S_CODE_GEN_CHECK ?= "true"

JOB_BASE_NAME ?= cilium_test

GO_VERSION := $(shell cat GO_VERSION)
GO_MAJOR_AND_MINOR_VERSION := $(shell sed 's/\([0-9]\+\).\([0-9]\+\).\([0-9]\+\)/\1.\2/' GO_VERSION)
GOARCH := $(shell $(GO) env GOARCH)

DOCKER_FLAGS ?=

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002 \
	-X github.com/cilium/cilium/pkg/testutils.CiliumRootDir=$(ROOT_DIR) \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

TEST_UNITTEST_LDFLAGS= -ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyConfigFile=/tmp/cilium-consul-certs/cilium-consul.yaml \
	-X github.com/cilium/cilium/pkg/testutils.CiliumRootDir=$(ROOT_DIR) \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
	-X github.com/cilium/cilium/pkg/logging.DefaultLogLevelStr=$(LOGLEVEL)"

define generate_k8s_api
	cd "./vendor/k8s.io/code-generator" && \
	GO111MODULE=off bash ./generate-groups.sh $(1) \
	    $(2) \
	    $(3) \
	    $(4) \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

define generate_deepequal
	cd "./vendor/github.com/cilium/deepequal-gen" && \
	GO111MODULE=off go run main.go \
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
	PATH="$(PWD)/tools:$(PATH)" ./tools/go-to-protobuf \
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

build: $(SUBDIRS)

build-container:
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i all; done

$(SUBDIRS): force
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

jenkins-precheck:
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER run --rm precheck

clean-jenkins-precheck:
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER rm
	# remove the networks
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER down

PRIV_TEST_PKGS_EVAL := $(shell for pkg in $(TESTPKGS); do echo $$pkg; done | xargs grep --include='*.go' -ril '+build [^!]*privileged_tests' | xargs dirname | sort | uniq)
PRIV_TEST_PKGS ?= $(PRIV_TEST_PKGS_EVAL)
tests-privileged: GO_TAGS_FLAGS+=privileged_tests
tests-privileged:
	# cilium-map-migrate is a dependency of some unit tests.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C bpf cilium-map-migrate
	$(MAKE) init-coverage
	for pkg in $(patsubst %,github.com/cilium/cilium/%,$(PRIV_TEST_PKGS)); do \
		PATH=$(PATH):$(ROOT_DIR)/bpf $(GO_TEST) $(TEST_LDFLAGS) $$pkg $(GOTEST_UNIT_BASE) $(GOTEST_COVER_OPTS) \
		|| exit 1; \
		tail -n +2 coverage.out >> coverage-all-tmp.out; \
	done
	$(MAKE) generate-cov

start-kvstores:
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

stop-kvstores:
ifeq ($(SKIP_KVSTORES),"false")
	$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-etcd-test-container"
	$(QUIET)$(CONTAINER_ENGINE) rm -f "cilium-consul-test-container"
	$(QUIET)rm -rf /tmp/cilium-consul-certs
endif

tests: force
	$(MAKE) unit-tests

generate-cov:
	# Remove generated code from coverage
	$(QUIET) grep -Ev '(^github.com/cilium/cilium/api/v1)|(generated.deepcopy.go)|(^github.com/cilium/cilium/pkg/k8s/client/)' \
		coverage-all-tmp.out > coverage-all.out
	$(QUIET)$(GO) tool cover -html=coverage-all.out -o=coverage-all.html
	$(QUIET) rm coverage.out coverage-all-tmp.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true

init-coverage:
	$(QUIET) echo "mode: count" > coverage-all-tmp.out
	$(QUIET) echo "mode: count" > coverage.out

unit-tests: start-kvstores
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C tools/maptool/
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C test/bpf/
	test/bpf/unit-test
ifeq ($(SKIP_VET),"false")
	$(MAKE) govet
endif
	$(MAKE) init-coverage
	# It seems that in some env if the path is large enough for the full list
	# of files, the full bash command in that target gets too big for bash and
	# hence will trigger an error of too many arguments. As a workaround, we
	# have to process these packages in different subshells.
	for pkg in $(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)); do \
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $$pkg $(GOTEST_BASE) $(GOTEST_COVER_OPTS) \
		|| exit 1; \
		tail -n +2 coverage.out >> coverage-all-tmp.out; \
	done
	$(MAKE) generate-cov
	$(MAKE) stop-kvstores

bench: start-kvstores
	# Process the packages in different subshells. See comment in the
	# "unit-tests" target above for an explanation.
	$(QUIET)for pkg in $(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)); do \
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) \
			$$pkg \
		|| exit 1; \
	done
	$(MAKE) stop-kvstores

bench-privileged: GO_TAGS_FLAGS+=privileged_tests
bench-privileged:
	# Process the packages in different subshells. See comment in the
	# "unit-tests" target above for an explanation.
	$(QUIET)for pkg in $(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)); do \
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) $$pkg \
		|| exit 1; \
	done

clean-tags:
	@$(ECHO_CLEAN) tags
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

cscope.files: $(GOLANG_SRCFILES) $(BPF_SRCFILES)
	@echo $(GOLANG_SRCFILES) $(BPF_SRCFILES) | sed 's/ /\n/g' | sort > cscope.files

tags: $(GOLANG_SRCFILES) $(BPF_SRCFILES) cscope.files
	@ctags $(GOLANG_SRCFILES) $(BPF_SRCFILES)
	cscope -R -b -q

clean-container:
	-$(QUIET) for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

clean: clean-container clean-build
	-$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/deb clean
	-$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/rpm clean

veryclean:
	-$(QUIET) $(CONTAINER_ENGINE) image prune -af
	-$(QUIET) $(CONTAINER_ENGINE) builder prune -af

install-bpf:
	$(QUIET)$(INSTALL) -m 0750 -d $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium
	-rm -rf $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium/bpf/*
	$(foreach bpfsrc,$(BPF_SRCFILES), $(INSTALL) -D -m 0644 $(bpfsrc) $(DESTDIR)$(LOCALSTATEDIR)/lib/cilium/$(bpfsrc);)

install: install-bpf
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

install-container: install-bpf
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

# Workaround for not having git in the build environment
# Touch the file only if needed
GIT_VERSION: force
	@if [ "$(GIT_VERSION)" != "`cat 2>/dev/null GIT_VERSION`" ] ; then echo "$(GIT_VERSION)" >GIT_VERSION; fi

include Makefile.docker

CRD_OPTIONS ?= "crd:crdVersions=v1"
# Generate manifests e.g. CRD, RBAC etc.
manifests:
	$(eval TMPDIR := $(shell mktemp -d))
	cd "./vendor/sigs.k8s.io/controller-tools/cmd/controller-gen" && \
	go run ./... $(CRD_OPTIONS) paths="$(PWD)/pkg/k8s/apis/cilium.io/v2" output:crd:artifacts:config="$(TMPDIR)";
	mv ${TMPDIR}/cilium.io_ciliumnetworkpolicies.yaml ./examples/crds/ciliumnetworkpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumclusterwidenetworkpolicies.yaml ./examples/crds/ciliumclusterwidenetworkpolicies.yaml
	mv ${TMPDIR}/cilium.io_ciliumendpoints.yaml ./examples/crds/ciliumendpoints.yaml
	mv ${TMPDIR}/cilium.io_ciliumidentities.yaml ./examples/crds/ciliumidentities.yaml
	mv ${TMPDIR}/cilium.io_ciliumnodes.yaml ./examples/crds/ciliumnodes.yaml
	mv ${TMPDIR}/cilium.io_ciliumexternalworkloads.yaml ./examples/crds/ciliumexternalworkloads.yaml
	mv ${TMPDIR}/cilium.io_ciliumlocalredirectpolicies.yaml ./examples/crds/ciliumlocalredirectpolicies.yaml
	rm -rf $(TMPDIR)

build-deb:
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/deb

build-rpm:
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/rpm

runtime-tests:
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C tests runtime-tests

k8s-tests:
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C tests k8s-tests

generate-api: api/v1/openapi.yaml
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
	-$(QUIET) find api/v1/client/ -type f -name "*.go" -print | PATH="$(PWD)/tools:$(PATH)" xargs goimports -w
	-$(QUIET) find api/v1/models/ -type f -name "*.go" -print | PATH="$(PWD)/tools:$(PATH)" xargs goimports -w
	-$(QUIET) find api/v1/server/ -type f -name "*.go" -print | PATH="$(PWD)/tools:$(PATH)" xargs goimports -w

generate-health-api: api/v1/health/openapi.yaml
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
	-$(QUIET) find api/v1/health/ -type f -name "*.go" -print | PATH="$(PWD)/tools:$(PATH)" xargs goimports -w

generate-hubble-api: api/v1/flow/flow.proto api/v1/peer/peer.proto api/v1/observer/observer.proto api/v1/relay/relay.proto
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C api/v1

generate-k8s-api:
	$(call generate_k8s_protobuf,$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1beta1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/apiextensions/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/apiextensions/v1beta1)
	$(call generate_k8s_api_deepcopy_deepequal_client,client,github.com/cilium/cilium/pkg/k8s/slim/k8s/api,"$\
	discovery:v1beta1\
	networking:v1\
	core:v1")
	$(call generate_k8s_api_deepcopy_deepequal_client,apiextensions-client,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"$\
	apiextensions:v1beta1\
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
	k8s:types\
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
	maps:tunnel\
	node:types\
	policy:api\
	service:store")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/policy,"api:kafka")
	$(call generate_k8s_api_all,github.com/cilium/cilium/pkg/k8s/apis,"cilium.io:v2")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/pkg/aws,"eni:types")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium/api,"v1:models")
	$(call generate_k8s_api_deepcopy_deepequal,github.com/cilium/cilium,"$\
	pkg:bpf\
	pkg:k8s\
	pkg:labels\
	pkg:loadbalancer\
	pkg:tuple")

# Explanation for the arguments to `go-bindata`:
# - prefix:   Strip off the ROOT_DIR from the CRD YAML paths
# - pkg:      CRD YAMLs live in the client package
# - mode:     Hardcode the file permissions
# - modetime: Hardcode the modification time so that the generated files don't
#             change on every invocation
GO_BINDATA := $(QUIET) go run ./... -prefix $(ROOT_DIR) -pkg client -mode 0640 -modtime 1450269211

go-bindata: $(K8S_CRD_FILES)
	@$(ECHO_GEN) $@
	cd "./vendor/github.com/go-bindata/go-bindata/v3/go-bindata" && \
		$(GO_BINDATA) -o $(ROOT_DIR)/pkg/k8s/apis/cilium.io/v2/client/bindata.go \
		$(K8S_CRD_FILES)

vps:
	VBoxManage list runningvms

reload:
	sudo systemctl stop cilium cilium-docker
	sudo $(MAKE) install
	sudo systemctl start cilium cilium-docker
	sleep 6
	cilium status

release:
	$(eval TAG_VERSION := $(shell git tag | grep v$(VERSION) > /dev/null; echo $$?))
	$(eval BRANCH := $(shell git rev-parse --abbrev-ref HEAD))
	$(info Checking if tag $(VERSION) is created '$(TAG_VERSION)' $(BRANCH))

	@if [ "$(TAG_VERSION)" -eq "0" ];then { echo Git tag v$(VERSION) is already created; exit 1; } fi
	$(MAKE) -C ./contrib/packaging/deb release
	git commit -m "Version $(VERSION)"
	git tag v$(VERSION)
	git archive --format tar $(BRANCH) | gzip > ../cilium_$(VERSION).orig.tar.gz

gofmt:
	$(QUIET)for pkg in $(GOFILES); do $(GO) fmt $$pkg; done

govet:
	@$(ECHO_CHECK) vetting all GOFILES...
	$(QUIET) $(GO_VET) \
    ./api/... \
    ./bugtool/... \
    ./cilium/... \
    ./cilium-health/... \
    ./daemon/... \
    ./hubble-relay/... \
    ./operator/... \
    ./pkg/... \
    ./plugins/... \
    ./proxylib/... \
    ./test/. \
    ./test/config/... \
    ./test/ginkgo-ext/... \
    ./test/helpers/... \
    ./test/runtime/... \
    ./test/k8sT/... \
    ./tools/...

lint:
	@$(ECHO_CHECK) golangci-lint
	$(QUIET) golangci-lint run

logging-subsys-field:
	@$(ECHO_CHECK) contrib/scripts/check-logging-subsys-field.sh
	$(QUIET) contrib/scripts/check-logging-subsys-field.sh

check-microk8s:
	@$(ECHO_CHECK) microk8s is ready...
	$(QUIET)microk8s.status >/dev/null \
		|| (echo "Error: Microk8s is not running" && exit 1)
	$(QUIET)microk8s.status --yaml | grep -q "registry.*enabled" \
		|| (echo "Error: Microk8s registry must be enabled" && exit 1)

LOCAL_IMAGE_TAG=local
LOCAL_IMAGE=localhost:32000/cilium/cilium:$(LOCAL_IMAGE_TAG)
microk8s: check-microk8s
	$(QUIET)$(MAKE) dev-docker-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)
	@echo "  DEPLOY image to microk8s ($(LOCAL_IMAGE))"
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/cilium-dev:$(LOCAL_IMAGE_TAG) $(LOCAL_IMAGE)
	$(QUIET)./contrib/scripts/microk8s-import.sh $(LOCAL_IMAGE)

ci-precheck: precheck
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C bpf build_all

precheck: logging-subsys-field
ifeq ($(SKIP_K8S_CODE_GEN_CHECK),"false")
	@$(ECHO_CHECK) contrib/scripts/check-k8s-code-gen.sh
	$(QUIET) contrib/scripts/check-k8s-code-gen.sh
endif
	@$(ECHO_CHECK) contrib/scripts/check-fmt.sh
	$(QUIET) contrib/scripts/check-fmt.sh
	@$(ECHO_CHECK) contrib/scripts/check-log-newlines.sh
	$(QUIET) contrib/scripts/check-log-newlines.sh
	@$(ECHO_CHECK) contrib/scripts/check-missing-tags-in-tests.sh
	$(QUIET) contrib/scripts/check-missing-tags-in-tests.sh
	@$(ECHO_CHECK) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) contrib/scripts/check-assert-deep-equals.sh
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	@$(ECHO_CHECK) contrib/scripts/rand-check.sh
	$(QUIET) contrib/scripts/rand-check.sh

pprof-help:
	@echo "Available pprof targets:"
	@echo "  pprof-heap"
	@echo "  pprof-profile"
	@echo "  pprof-block"
	@echo "  pprof-trace-5s"
	@echo "  pprof-mutex"

pprof-heap:
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/heap

pprof-profile:
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/profile


pprof-block:
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/block

pprof-trace-5s:
	curl http://localhost:6060/debug/pprof/trace?seconds=5

pprof-mutex:
	$(QUIET)$(GO) tool pprof http://localhost:6060/debug/pprof/mutex

update-authors:
	@echo "Updating AUTHORS file..."
	@echo "The following people, in alphabetical order, have either authored or signed" > AUTHORS
	@echo "off on commits in the Cilium repository:" >> AUTHORS
	@echo "" >> AUTHORS
	@contrib/scripts/extract_authors.sh >> AUTHORS
	@cat .authors.aux >> AUTHORS

test-docs:
	$(MAKE) -C Documentation html

render-docs: test-docs
	$(MAKE) -C Documentation run-server

render-docs-live-preview:
	$(MAKE) -C Documentation live-preview

manpages:
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages:
	cp man/* /usr/local/share/man/man1/
	mandb

postcheck: build
	$(QUIET)$(MAKE) $(SUBMAKEOPTS) -C Documentation update-cmdref check

minikube:
	$(QUIET) contrib/scripts/minikube.sh

licenses-all:
	@go run ./tools/licensegen > LICENSE.all || ( rm -f LICENSE.all ; false )

update-golang: update-golang-dev-doctor update-golang-dockerfiles update-gh-actions-go-version update-travis-go-version update-test-go-version update-images-go-version

update-golang-dev-doctor:
	$(QUIET) sed -i 's/^const minGoVersionStr = ".*"/const minGoVersionStr = "$(GO_MAJOR_AND_MINOR_VERSION)"/' tools/dev-doctor/config.go
	@echo "Updated go version in tools/dev-doctor to $(GO_MAJOR_AND_MINOR_VERSION)"

update-golang-dockerfiles:
	$(QUIET) sed -i 's/GO_VERSION .*/GO_VERSION $(GO_VERSION)/g' Dockerfile.builder
	$(QUIET) for fl in $(shell find . \( -path ./vendor -prune -o -path ./images -prune \) -o -name "*Dockerfile*" -print) ; do sed -i 's/golang:.* /golang:$(GO_VERSION) as /g' $$fl ; done
	@echo "Updated go version in Dockerfiles to $(GO_VERSION)"

update-gh-actions-go-version:
	$(QUIET) for fl in $(shell find .github/workflows -name "*.yaml" -print) ; do sed -i 's/go-version: .*/go-version: $(GO_VERSION)/g' $$fl ; done
	@echo "Updated go version in GitHub Actions to $(GO_VERSION)"

update-travis-go-version:
	$(QUIET) sed -i 's/go: ".*/go: "$(GO_VERSION)"/g' .travis.yml
	@echo "Updated go version in .travis.yml to $(GO_VERSION)"

update-test-go-version:
	$(QUIET) sed -i 's/GO_VERSION=.*/GO_VERSION="$(GO_VERSION)"/g' test/kubernetes-test.sh
	$(QUIET) sed -i 's/GOLANG_VERSION=.*/GOLANG_VERSION="$(GO_VERSION)"/g' test/packet/scripts/install.sh
	@echo "Updated go version in test scripts to $(GO_VERSION)"

update-images-go-version:
	$(QUIET) sed -i 's/^go_version=.*/go_version=$(GO_VERSION)/g' images/scripts/update-golang-image.sh
	$(QUIET) $(MAKE) -C images update-golang-image
	@echo "Updated go version in image Dockerfiles to $(GO_VERSION)"

dev-doctor:
	$(QUIET)$(GO) version 2>/dev/null || ( echo "go not found, see https://golang.org/doc/install" ; false )
	$(QUIET)$(GO) run ./tools/dev-doctor

.PHONY: build-context-update clean-build clean clean-container dev-doctor force generate-api generate-health-api generate-hubble-api install licenses-all veryclean
force :;
