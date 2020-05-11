# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.defs

SUBDIRS_CILIUM_CONTAINER := proxylib envoy bpf cilium daemon cilium-health bugtool
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) operator plugins tools hubble-relay

SUBDIRS_CILIUM_CONTAINER += plugins/cilium-cni
ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif

GOFILES_EVAL := $(subst _$(ROOT_DIR)/,,$(shell $(GO_LIST) -e ./...))
GOFILES ?= $(GOFILES_EVAL)
TESTPKGS_EVAL := $(subst github.com/cilium/cilium/,,$(shell echo $(GOFILES) | \
	sed 's/ /\n/g' | \
	grep -v '/api/v1\|/vendor\|/contrib' | \
	grep -v -P 'test(?!/helpers/logutils)'))
TESTPKGS ?= $(TESTPKGS_EVAL)
GOLANGVERSION := $(shell $(GO) version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')
GOLANG_SRCFILES := $(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v vendor | sort | uniq)

SWAGGER_VERSION := v0.20.1
SWAGGER := $(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) --entrypoint swagger quay.io/goswagger/swagger:$(SWAGGER_VERSION)

COVERPKG_EVAL := $(shell if [ $$(echo "$(TESTPKGS)" | wc -w) -gt 1 ]; then echo "./..."; else echo "github.com/cilium/cilium/$(TESTPKGS)"; fi)
COVERPKG ?= $(COVERPKG_EVAL)
GOTEST_BASE := -test.v -timeout 360s
GOTEST_UNIT_BASE := $(GOTEST_BASE) -check.vv
GOTEST_PRIV_OPTS := $(GOTEST_UNIT_BASE) -tags=privileged_tests
GOTEST_COVER_OPTS := -coverprofile=coverage.out -covermode=count -coverpkg $(COVERPKG)
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

UTC_DATE=$(shell date -u "+%Y-%m-%d")

GO_VERSION := $(shell cat GO_VERSION)
GOARCH := $(shell $(GO) env GOARCH)

comma:= ,

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=https://consul:8443 \
	-X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002 \
	-X github.com/cilium/cilium/pkg/testutils.CiliumRootDir=$(ROOT_DIR) \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA=1234567890abcdef7890"

TEST_UNITTEST_LDFLAGS= -ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyConfigFile=/tmp/cilium-consul-certs/cilium-consul.yaml \
	-X github.com/cilium/cilium/pkg/testutils.CiliumRootDir=$(ROOT_DIR) \
	-X github.com/cilium/cilium/pkg/datapath.DatapathSHA=1234567890abcdef7890 \
	-X github.com/cilium/cilium/pkg/logging.DefaultLogLevelStr=$(LOGLEVEL)"

define generate_k8s_api
	cd "./vendor/k8s.io/code-generator" && \
	GO111MODULE=off bash ./generate-groups.sh $(1) \
	    $(2) \
	    $(3) \
	    $(4) \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

define generate_k8s_api_all
	$(call generate_k8s_api,all,github.com/cilium/cilium/pkg/k8s/client,$(1),$(2))
endef

define generate_k8s_api_deepcopy
	$(call generate_k8s_api,deepcopy,github.com/cilium/cilium/pkg/k8s/client,$(1),$(2))
endef

define generate_k8s_api_deepcopy_client
	$(call generate_k8s_api,deepcopy$(comma)client,github.com/cilium/cilium/pkg/k8s/slim/k8s/client,$(1),$(2))
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

all: precheck build postcheck
	@echo "Build finished."

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
tests-privileged:
	# cilium-map-migrate is a dependency of some unit tests.
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C bpf cilium-map-migrate
	$(MAKE) init-coverage
	for pkg in $(patsubst %,github.com/cilium/cilium/%,$(PRIV_TEST_PKGS)); do \
		$(GO_TEST) $(TEST_LDFLAGS) $$pkg $(GOTEST_PRIV_OPTS) $(GOTEST_COVER_OPTS) \
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
	$(QUIET)$(foreach pkg,$(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)),\
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) \
			$(pkg) \
		|| exit 1;)
	$(MAKE) stop-kvstores

bench-privileged:
	$(QUIET)$(foreach pkg,$(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)),\
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) \
			-tags=privileged_tests $(pkg) \
		|| exit 1;)

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
	-$(QUIET) rm -f GIT_VERSION
	-$(QUIET) docker builder prune --filter type=exec.cachemount -f

clean-build:
	-$(QUIET) rm -rf _build

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
GIT_VERSION: .git
	echo "$(GIT_VERSION)" >GIT_VERSION

docker-cilium-image-for-developers:
	# DOCKER_BUILDKIT allows for faster build as well as the ability to use
	# a dedicated dockerignore file per Dockerfile.
	$(QUIET)DOCKER_BUILDKIT=1 $(CONTAINER_ENGINE) build \
	     --build-arg LOCKDEBUG=\
	     --build-arg V=\
	     --build-arg LIBNETWORK_PLUGIN=\
	     -t "$(DOCKER_DEV_ACCOUNT)/cilium-dev:latest" . -f ./cilium-dev.Dockerfile

docker-image: clean docker-image-no-clean docker-operator-image docker-plugin-image docker-hubble-relay-image

docker-image-no-clean: GIT_VERSION
	$(QUIET)$(CONTAINER_ENGINE) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		--build-arg CILIUM_SHA=$(firstword $(GIT_VERSION)) \
		-t "cilium/cilium:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/cilium:$(DOCKER_IMAGE_TAG) cilium/cilium:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/cilium:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-cilium-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh cilium $(DOCKER_IMAGE_TAG)

DOCKER_BUILDKIT =
DEV_DOCKERFILE_FILTER =
ifeq ($(DOCKER_DEV_NOCACHE),)
	DOCKER_BUILDKIT := DOCKER_BUILDKIT=1
	DEV_DOCKERFILE_FILTER := | sed -e "1s|^\#.*|\# syntax = docker/dockerfile:experimental|" -e "s|^RUN\(.*\)make|RUN --mount=type=cache,target=/root/.cache/go-build\1make|"
endif
DEV_BUILD_DIR := _build/cilium-dev
DEV_DOCKERFILE := $(DEV_BUILD_DIR).Dockerfile

$(DEV_DOCKERFILE): Dockerfile Makefile
	-mkdir -p $(dir $@)
	cat $< $(DEV_DOCKERFILE_FILTER) > $@

check-status:
ifneq ($(shell git status --porcelain),)
	git status
	echo These changes will not be included in build, aborting. Define IGNORE_GIT_STATUS to build anyway.
	test $(IGNORE_GIT_STATUS)
endif

dev-docker-image: check-status clean-build $(DEV_DOCKERFILE) GIT_VERSION
	git clone --no-checkout --no-local --depth 1 . $(DEV_BUILD_DIR)
	$(QUIET)$(DOCKER_BUILDKIT) $(CONTAINER_ENGINE) build -f $(DEV_DOCKERFILE) \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg CILIUM_SHA=$(firstword $(GIT_VERSION)) \
		--build-arg GIT_CHECKOUT=1 \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		-t $(DOCKER_DEV_ACCOUNT)/cilium-dev:$(DOCKER_IMAGE_TAG) $(DEV_BUILD_DIR)
	$(QUIET)$(CONTAINER_ENGINE) tag $(DOCKER_DEV_ACCOUNT)/cilium-dev:$(DOCKER_IMAGE_TAG) $(DOCKER_DEV_ACCOUNT)/cilium-dev:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push $(DOCKER_DEV_ACCOUNT)/cilium-dev:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-cilium-dev-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-dev $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-dev $(DOCKER_IMAGE_TAG)

docker-operator-image: GIT_VERSION
	$(QUIET)$(CONTAINER_ENGINE) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg CILIUM_SHA=$(firstword $(GIT_VERSION)) \
		-f cilium-operator.Dockerfile \
		-t "cilium/operator:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/operator:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-operator-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh operator $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh operator $(DOCKER_IMAGE_TAG)

docker-plugin-image: GIT_VERSION
	$(QUIET)$(CONTAINER_ENGINE) build \
		--build-arg LOCKDEBUG=${LOCKDEUBG} \
		--build-arg CILIUM_SHA=$(firstword $(GIT_VERSION)) \
		-f cilium-docker-plugin.Dockerfile \
		-t "cilium/docker-plugin:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/docker-plugin:$(DOCKER_IMAGE_TAG) cilium/docker-plugin:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/docker-plugin:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-plugin-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh docker-plugin $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh docker-plugin $(DOCKER_IMAGE_TAG)

docker-image-runtime:
	cd contrib/packaging/docker && $(CONTAINER_ENGINE) build --build-arg ARCH=$(GOARCH) -t "cilium/cilium-runtime:$(UTC_DATE)" -f Dockerfile.runtime .
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/cilium-runtime:$(UTC_DATE) cilium/cilium-runtime:$(UTC_DATE)-${GOARCH}

docker-cilium-runtime-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-runtime $(UTC_DATE)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-runtime $(UTC_DATE)

docker-image-builder:
	$(QUIET)$(CONTAINER_ENGINE) build --build-arg ARCH=$(GOARCH) -t "cilium/cilium-builder:$(UTC_DATE)" -f Dockerfile.builder .
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/cilium-builder:$(UTC_DATE) cilium/cilium-builder:$(UTC_DATE)-${GOARCH}

docker-cilium-builder-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-builder $(UTC_DATE)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-builder $(UTC_DATE)

docker-hubble-relay-image:
	$(QUIET)$(CONTAINER_ENGINE) build -f hubble-relay.Dockerfile -t "cilium/hubble-relay:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)$(CONTAINER_ENGINE) tag cilium/hubble-relay:$(DOCKER_IMAGE_TAG) cilium/hubble-relay:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/hubble-relay:$(DOCKER_IMAGE_TAG)-${GOARCH}"

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
		-t api/v1 -f api/v1/openapi.yaml --default-scheme=unix -C api/v1/cilium-server.yml
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 -f api/v1/openapi.yaml

generate-health-api: api/v1/health/openapi.yaml
	@$(ECHO_GEN)api/v1/health/openapi.yaml
	-$(QUIET)$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml --default-scheme=unix -C api/v1/cilium-server.yml
	-$(QUIET)$(SWAGGER) generate client -a restapi \
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml

generate-k8s-api:
	$(call generate_k8s_protobuf,$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/discovery/v1beta1$(comma)$\
	github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/networking/v1)
	$(call generate_k8s_api_deepcopy_client,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"\
	discovery:v1beta1\
	networking:v1\
	core:v1\
	")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg/k8s/slim/k8s/apis,"\
	meta:v1\
	")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"\
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
	service:store\
	")
	$(call generate_k8s_api_all,github.com/cilium/cilium/pkg/k8s/apis,"cilium.io:v2")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg/aws,"eni:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/api,"v1:models")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"\
	pkg:bpf\
	pkg:k8s\
	pkg:loadbalancer\
	pkg:tuple\
	")

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

ineffassign:
	@$(ECHO_CHECK) ineffassign
	$(QUIET) ineffassign .

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
	$(QUIET)$(CONTAINER_ENGINE) push $(LOCAL_IMAGE)
	$(QUIET)microk8s.kubectl apply -f contrib/k8s/microk8s-prepull.yaml
	$(QUIET)microk8s.kubectl -n kube-system delete pod -l name=prepull
	$(QUIET)microk8s.kubectl -n kube-system rollout status ds/prepull
	@echo
	@echo "Update image tag like this when ready:"
	@echo "    microk8s.kubectl -n kube-system set image ds/cilium cilium-agent=$(LOCAL_IMAGE)"
	@echo "Or, redeploy the Cilium pods:"
	@echo "    microk8s.kubectl -n kube-system delete pod -l k8s-app=cilium"

ci-precheck: precheck
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C bpf build_all

precheck: ineffassign logging-subsys-field
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

render-docs:
	$(MAKE) -C Documentation html run-server

manpages:
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages:
	cp man/* /usr/local/share/man/man1/
	mandb

postcheck: build
	$(QUIET)$(MAKE) $(SUBMAKEOPTS) -C Documentation update-cmdref check
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	@$(ECHO_CHECK) contrib/scripts/rand-check.sh
	$(QUIET) contrib/scripts/rand-check.sh

minikube:
	$(QUIET) contrib/scripts/minikube.sh

update-golang: update-golang-dockerfiles update-gh-actions-go-version update-travis-go-version update-test-go-version

update-golang-dockerfiles:
	$(QUIET) sed -i 's/GO_VERSION .*/GO_VERSION $(GO_VERSION)/g' Dockerfile.builder
	$(QUIET) for fl in $(shell find . -path ./vendor -prune -o -name "*Dockerfile*" -print) ; do sed -i 's/golang:.* /golang:$(GO_VERSION) as /g' $$fl ; done
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

.PHONY: force generate-api generate-health-api install check-status dev-docker-image
force :;
