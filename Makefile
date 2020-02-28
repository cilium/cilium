# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.defs

SUBDIRS_CILIUM_CONTAINER := proxylib envoy plugins/cilium-cni bpf cilium daemon cilium-health bugtool
ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) operator plugins tools hubble-relay
GOFILES_EVAL := $(subst _$(ROOT_DIR)/,,$(shell $(GO_LIST) -e ./...))
GOFILES ?= $(GOFILES_EVAL)
TESTPKGS_EVAL := $(subst github.com/cilium/cilium/,,$(shell $(GO_LIST) -e ./... | grep -v '/api/v1\|/vendor\|/contrib' | grep -v -P 'test(?!/helpers/logutils)'))
TESTPKGS ?= $(TESTPKGS_EVAL)
GOLANGVERSION := $(shell $(GO) version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')
GOLANG_SRCFILES := $(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v vendor | sort | uniq)

SWAGGER_VERSION := v0.20.1
SWAGGER := $(CONTAINER_ENGINE_FULL) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) --entrypoint swagger quay.io/goswagger/swagger:$(SWAGGER_VERSION)

COVERPKG_EVAL := $(shell if [ $$(echo "$(TESTPKGS)" | wc -w) -gt 1 ]; then echo "./..."; else echo "$(TESTPKGS)"; fi)
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

JOB_BASE_NAME ?= cilium_test

UTC_DATE=$(shell date -u "+%Y-%m-%d")

GO_VERSION := $(shell cat GO_VERSION)
GOARCH := $(shell $(GO) env GOARCH)

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
	    github.com/cilium/cilium/pkg/k8s/client \
	    $(2) \
	    $(3) \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
endef

define generate_k8s_api_all
	$(call generate_k8s_api,all,$(1),$(2))
endef

define generate_k8s_api_deepcopy
	$(call generate_k8s_api,deepcopy,$(1),$(2))
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
	$(QUIET)$(foreach pkg,$(PRIV_TEST_PKGS),\
		$(GO_TEST) $(TEST_LDFLAGS) github.com/cilium/cilium/$(pkg) $(GOTEST_PRIV_OPTS) || exit 1;)

start-kvstores:
ifeq ($(SKIP_KVSTORES),"false")
	@echo Starting key-value store containers...
	-$(CONTAINER_ENGINE_FULL) rm -f "cilium-etcd-test-container" 2> /dev/null
	$(CONTAINER_ENGINE_FULL) run -d \
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
	-$(CONTAINER_ENGINE_FULL) rm -f "cilium-consul-test-container" 2> /dev/null
	rm -rf /tmp/cilium-consul-certs
	mkdir /tmp/cilium-consul-certs
	cp $(CURDIR)/test/consul/* /tmp/cilium-consul-certs
	chmod -R a+rX /tmp/cilium-consul-certs
	$(CONTAINER_ENGINE_FULL) run -d \
		--name "cilium-consul-test-container" \
		-p 8501:8443 \
		-e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true, "disable_update_check": true}' \
		-v /tmp/cilium-consul-certs:/cilium-consul/ \
		consul:1.1.0 \
		agent -client=0.0.0.0 -server -bootstrap-expect 1 -config-file=/cilium-consul/consul-config.json
endif

stop-kvstores:
ifeq ($(SKIP_KVSTORES),"false")
	$(CONTAINER_ENGINE_FULL) rm -f "cilium-etcd-test-container"
	$(CONTAINER_ENGINE_FULL) rm -f "cilium-consul-test-container"
	rm -rf /tmp/cilium-consul-certs
endif

tests: force
	$(MAKE) unit-tests

generate-cov:
	# Remove generated code from coverage
	$(QUIET) grep -Ev '(^github.com/cilium/cilium/api/v1)|(generated.deepcopy.go)|(^github.com/cilium/cilium/pkg/k8s/client/)' \
		coverage-all-tmp.out > coverage-all.out
	$(QUIET)$(GO) tool cover -html=coverage-all.out -o=coverage-all.html
	$(QUIET) rm coverage.out coverage-all-tmp.out

unit-tests: start-kvstores
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C tools/maptool/
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C test/bpf/
	test/bpf/unit-test
ifeq ($(SKIP_VET),"false")
	$(MAKE) govet
endif
	$(QUIET) echo "mode: count" > coverage-all-tmp.out
	$(QUIET) echo "mode: count" > coverage.out
	# It seems that in some env if the path is large enough for the full list
	# of files, the full bash command in that target gets too big for bash and
	# hence will trigger an error of too many arguments. As a workaround, we
	# have to process these packages in different subshells.
	for pkg in $(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)); do \
		$(GO_TEST) $(TEST_UNITTEST_LDFLAGS) $$pkg $(GOTEST_BASE) $(GOTEST_COVER_OPTS) || exit 1; \
		tail -n +2 coverage.out >> coverage-all-tmp.out; \
	done
	$(MAKE) generate-cov
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
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

clean: clean-container
	-$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/deb clean
	-$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C ./contrib/packaging/rpm clean
	-$(QUIET) rm -f GIT_VERSION

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
	DOCKER_BUILDKIT=1 $(CONTAINER_ENGINE_FULL) build \
	     --build-arg LOCKDEBUG=\
	     --build-arg V=\
	     --build-arg LIBNETWORK_PLUGIN=\
	     -t "cilium/cilium-dev:"latest"" . -f ./cilium-dev.Dockerfile

docker-image: clean docker-image-no-clean docker-operator-image docker-plugin-image

docker-image-no-clean: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		-t "cilium/cilium:$(DOCKER_IMAGE_TAG)" .
	$(CONTAINER_ENGINE_FULL) tag cilium/cilium:$(DOCKER_IMAGE_TAG) cilium/cilium:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/cilium:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-cilium-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh cilium $(DOCKER_IMAGE_TAG)

dev-docker-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		-t "cilium/cilium-dev:$(DOCKER_IMAGE_TAG)" .
	$(CONTAINER_ENGINE_FULL) tag cilium/cilium-dev:$(DOCKER_IMAGE_TAG) cilium/cilium-dev:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/cilium-dev:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-cilium-dev-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-dev $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-dev $(DOCKER_IMAGE_TAG)

docker-operator-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build --build-arg LOCKDEBUG=${LOCKDEBUG} -f cilium-operator.Dockerfile -t "cilium/operator:$(DOCKER_IMAGE_TAG)" .
	$(CONTAINER_ENGINE_FULL) tag cilium/operator:$(DOCKER_IMAGE_TAG) cilium/operator:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/operator:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-operator-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh operator $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh operator $(DOCKER_IMAGE_TAG)

docker-plugin-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build --build-arg LOCKDEBUG=${LOCKDEUBG} -f cilium-docker-plugin.Dockerfile -t "cilium/docker-plugin:$(DOCKER_IMAGE_TAG)" .
	$(CONTAINER_ENGINE_FULL) tag cilium/docker-plugin:$(DOCKER_IMAGE_TAG) cilium/docker-plugin:$(DOCKER_IMAGE_TAG)-${GOARCH}
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/docker-plugin:$(DOCKER_IMAGE_TAG)-${GOARCH}"

docker-plugin-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh docker-plugin $(DOCKER_IMAGE_TAG)
	$(QUIET) contrib/scripts/push_manifest.sh docker-plugin $(DOCKER_IMAGE_TAG)

docker-image-runtime:
	cd contrib/packaging/docker && ${CONTAINER_ENGINE} build --build-arg ARCH=$(GOARCH) -t "cilium/cilium-runtime:$(UTC_DATE)" -f Dockerfile.runtime .
	${CONTAINER_ENGINE} tag cilium/cilium-runtime:$(UTC_DATE) cilium/cilium-runtime:$(UTC_DATE)-${GOARCH}

docker-cilium-runtime-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-runtime $(UTC_DATE)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-runtime $(UTC_DATE)

docker-image-builder:
	${CONTAINER_ENGINE_FULL} build --build-arg ARCH=$(GOARCH) -t "cilium/cilium-builder:$(UTC_DATE)" -f Dockerfile.builder .
	${CONTAINER_ENGINE_FULL} tag cilium/cilium-builder:$(UTC_DATE) cilium/cilium-builder:$(UTC_DATE)-${GOARCH}

docker-cilium-builder-manifest:
	@$(ECHO_CHECK) contrib/scripts/push_manifest.sh cilium-builder $(UTC_DATE)
	$(QUIET) contrib/scripts/push_manifest.sh cilium-builder $(UTC_DATE)

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
	-$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 -f api/v1/openapi.yaml --default-scheme=unix -C api/v1/cilium-server.yml
	-$(SWAGGER) generate client -a restapi \
		-t api/v1 -f api/v1/openapi.yaml

generate-health-api: api/v1/health/openapi.yaml
	@$(ECHO_GEN)api/v1/health/openapi.yaml
	-$(SWAGGER) generate server -s server -a restapi \
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml --default-scheme=unix -C api/v1/cilium-server.yml
	-$(SWAGGER) generate client -a restapi \
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml

generate-k8s-api:
	$(call generate_k8s_api_all,github.com/cilium/cilium/pkg/k8s/apis,"cilium.io:v2")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg/aws,"eni:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"aws:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"azure:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"ipam:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"policy:api")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:loadbalancer")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:k8s")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/api,"v1:models")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"k8s:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:policymap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:ipcache")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:ipmasq")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:lxcmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:tunnel")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:encrypt")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:metricsmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:nat")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:lbmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:eppolicymap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:sockmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:ctmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:eventsmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:signalmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:neighborsmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:fragmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"service:store")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"node:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:tuple")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:bpf")

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
    ./common/... \
    ./daemon/... \
    ./hubble-proxy/... \
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
	$(CONTAINER_ENGINE_FULL) tag cilium/cilium-dev:$(LOCAL_IMAGE_TAG) $(LOCAL_IMAGE)
	$(CONTAINER_ENGINE_FULL) push $(LOCAL_IMAGE)
	$(QUIET)microk8s.kubectl apply -f contrib/k8s/microk8s-prepull.yaml
	$(QUIET)microk8s.kubectl -n kube-system delete pod -l name=prepull
	$(QUIET)microk8s.kubectl -n kube-system rollout status ds/prepull
	@echo
	@echo "Update image tag like this when ready:"
	@echo "    microk8s.kubectl -n kube-system set image ds/cilium cilium-agent=$(LOCAL_IMAGE)"
	@echo "Or, redeploy the Cilium pods:"
	@echo "    microk8s.kubectl -n kube-system delete pod -l k8s-app=cilium"

precheck: ineffassign logging-subsys-field
	@$(ECHO_CHECK) contrib/scripts/check-fmt.sh
	$(QUIET) contrib/scripts/check-fmt.sh
	@$(ECHO_CHECK) contrib/scripts/check-log-newlines.sh
	$(QUIET) contrib/scripts/check-log-newlines.sh
	@$(ECHO_CHECK) contrib/scripts/check-missing-tags-in-tests.sh
	$(QUIET) contrib/scripts/check-missing-tags-in-tests.sh
	@$(ECHO_CHECK) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) -C bpf build_all

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

update-golang: update-golang-dockerfiles update-travis-go-version update-test-go-version

update-golang-dockerfiles:
	$(QUIET) sed -i 's/GO_VERSION .*/GO_VERSION $(GO_VERSION)/g' Dockerfile.builder
	$(QUIET) for fl in $(shell find . -path ./vendor -prune -o -name "*Dockerfile*" -print) ; do sed -i 's/golang:.* /golang:$(GO_VERSION) as /g' $$fl ; done
	@echo "Updated go version in Dockerfiles to $(GO_VERSION)"

update-travis-go-version:
	$(QUIET) sed -e 's/TRAVIS_GO_VERSION/$(GO_VERSION)/g' .travis.yml.tmpl > .travis.yml
	@echo "Updated go version in .travis.yml to $(GO_VERSION)"

update-test-go-version:
	$(QUIET) sed -i 's/GO_VERSION=.*/GO_VERSION="$(GO_VERSION)"/g' test/kubernetes-test.sh
	$(QUIET) sed -i 's/GOLANG_VERSION=.*/GOLANG_VERSION="$(GO_VERSION)"/g' test/packet/scripts/install.sh
	@echo "Updated go version in test scripts to $(GO_VERSION)"

.PHONY: force generate-api generate-health-api install
force :;
