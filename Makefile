include Makefile.defs
include daemon/bpf.sha

SUBDIRS_CILIUM_CONTAINER := proxylib envoy plugins/cilium-cni bpf cilium daemon cilium-health bugtool
ifdef LIBNETWORK_PLUGIN
SUBDIRS_CILIUM_CONTAINER += plugins/cilium-docker
endif
SUBDIRS := $(SUBDIRS_CILIUM_CONTAINER) operator plugins tools
GOFILES_EVAL := $(subst _$(ROOT_DIR)/,,$(shell $(CGO_DISABLED) $(GOLIST) $(GO) list -e ./...))
GOFILES ?= $(GOFILES_EVAL)
TESTPKGS_EVAL := $(subst github.com/cilium/cilium/,,$(shell $(CGO_DISABLED) $(GOLIST) $(GO) list -e ./... | grep -v '/api/v1\|/vendor\|/contrib' | grep -v -P 'test(?!/helpers/logutils)'))
TESTPKGS ?= $(TESTPKGS_EVAL)
GOLANGVERSION := $(shell $(GO) version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')
GOLANG_SRCFILES := $(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v vendor | sort | uniq)
BPF_FILES_EVAL := $(shell git ls-files $(ROOT_DIR)/bpf/ | grep -v .gitignore | tr "\n" ' ')
BPF_FILES ?= $(BPF_FILES_EVAL)
BPF_SRCFILES := $(subst ../,,$(BPF_FILES))

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

GO_VERSION := 1.13.6

# Since there's a bug with NFS or the kernel, the flock syscall hangs the documentation
# build in the developer VM. For this reason the documentation build is skipped if NFS
# is running in the developer VM.
SKIP_DOCS ?= $(shell if mount | grep -q "/home/vagrant/go/src/github.com/cilium/cilium type nfs"; then echo "true"; else echo "false"; fi)

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
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) -C $$i all; done

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

jenkins-precheck:
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER run --rm precheck

clean-jenkins-precheck:
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER rm
	# remove the networks
	docker-compose -f test/docker-compose.yml -p $(JOB_BASE_NAME)-$$BUILD_NUMBER down

PRIV_TEST_PKGS_EVAL := $(shell for pkg in $(TESTPKGS); do echo $(pkg); done | xargs grep --include='*.go' -ril '+build privileged_tests' | xargs dirname | sort | uniq)
PRIV_TEST_PKGS ?= $(PRIV_TEST_PKGS_EVAL)
tests-privileged:
	# cilium-map-migrate is a dependency of some unit tests.
	$(MAKE) -C bpf cilium-map-migrate
	$(QUIET)$(foreach pkg,$(PRIV_TEST_PKGS),\
		$(GO) test $(GOFLAGS) $(TEST_LDFLAGS) github.com/cilium/cilium/$(pkg) $(GOTEST_PRIV_OPTS) || exit 1;)

start-kvstores:
ifeq ($(SKIP_KVSTORES),"false")
	@echo Starting key-value store containers...
	-$(CONTAINER_ENGINE_FULL) rm -f "cilium-etcd-test-container" 2> /dev/null
	$(CONTAINER_ENGINE_FULL) run -d \
		--name "cilium-etcd-test-container" \
		-p 4002:4001 \
		quay.io/coreos/etcd:v3.2.17 \
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
	$(QUIET) $(MAKE) -C tools/maptool/
	$(QUIET) $(MAKE) -C test/bpf/
	test/bpf/unit-test
	$(QUIET) $(MAKE) -C daemon/ check-bindata
ifeq ($(SKIP_VET),"false")
	$(MAKE) govet
endif
	$(QUIET) echo "mode: count" > coverage-all-tmp.out
	$(QUIET) echo "mode: count" > coverage.out
	$(QUIET)$(foreach pkg,$(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)),\
		$(GO) test $(GOFLAGS) $(TEST_UNITTEST_LDFLAGS) $(pkg) $(GOTEST_BASE) $(GOTEST_COVER_OPTS) || exit 1; \
		tail -n +2 coverage.out >> coverage-all-tmp.out;)
	$(MAKE) generate-cov
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	$(MAKE) stop-kvstores

bench: start-kvstores
	$(QUIET)$(foreach pkg,$(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)),\
		$(GO) test $(GOFLAGS) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) \
			$(pkg) \
		|| exit 1;)
	$(MAKE) stop-kvstores

bench-privileged:
	$(QUIET)$(foreach pkg,$(patsubst %,github.com/cilium/cilium/%,$(TESTPKGS)),\
		$(GO) test $(GOFLAGS) $(TEST_UNITTEST_LDFLAGS) $(GOTEST_BASE) $(BENCHFLAGS) \
			-tags=privileged_tests $(pkg) \
		|| exit 1;)

clean-tags:
	@$(ECHO_CLEAN) tags
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $(GOLANG_SRCFILES) $(BPF_SRCFILES) cscope.files
	ctags $(GOLANG_SRCFILES) $(BPF_SRCFILES)
	@ echo $(GOLANG_SRCFILES) $(BPF_SRCFILES) | sed 's/ /\n/g' | sort > cscope.files
	cscope -R -b -q

clean-container:
	-for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done

clean: clean-container
	-$(MAKE) -C ./contrib/packaging/deb clean
	-$(MAKE) -C ./contrib/packaging/rpm clean
	-rm -f GIT_VERSION

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

install-container:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS_CILIUM_CONTAINER); do $(MAKE) -C $$i install; done

# Workaround for not having git in the build environment
GIT_VERSION: .git
	echo "$(GIT_VERSION)" >GIT_VERSION

docker-image: clean docker-image-no-clean docker-operator-image docker-plugin-image

docker-image-no-clean: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		-t "cilium/cilium:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/cilium:$(DOCKER_IMAGE_TAG)"

dev-docker-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build \
		--build-arg LOCKDEBUG=${LOCKDEBUG} \
		--build-arg V=${V} \
		--build-arg LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
		-t "cilium/cilium-dev:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/cilium-dev:$(DOCKER_IMAGE_TAG)"

docker-operator-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build --build-arg LOCKDEBUG=${LOCKDEBUG} -f cilium-operator.Dockerfile -t "cilium/operator:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/operator:$(DOCKER_IMAGE_TAG)"

docker-plugin-image: GIT_VERSION
	$(CONTAINER_ENGINE_FULL) build --build-arg LOCKDEBUG=${LOCKDEUBG} -f cilium-docker-plugin.Dockerfile -t "cilium/docker-plugin:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/docker-plugin:$(DOCKER_IMAGE_TAG)"

docker-image-init:
	$(QUIET)cd contrib/packaging/docker && ${CONTAINER_ENGINE} build -t "cilium/cilium-init:$(UTC_DATE)" -f Dockerfile.init .

docker-image-runtime:
	cd contrib/packaging/docker && ${CONTAINER_ENGINE} build -t "cilium/cilium-runtime:$(UTC_DATE)" -f Dockerfile.runtime .

docker-image-builder:
	${CONTAINER_ENGINE_FULL} build -t "cilium/cilium-builder:$(UTC_DATE)" -f Dockerfile.builder .

build-deb:
	$(MAKE) -C ./contrib/packaging/deb

build-rpm:
	$(MAKE) -C ./contrib/packaging/rpm

runtime-tests:
	$(MAKE) -C tests runtime-tests

k8s-tests:
	$(MAKE) -C tests k8s-tests

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
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"policy:api")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:loadbalancer")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:k8s")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:node")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium,"pkg:service")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/api,"v1:models")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"k8s:types")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:policymap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:ipcache")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:lxcmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:tunnel")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:encrypt")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:metricsmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:nat")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:lbmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:eppolicymap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:sockmap")
	$(call generate_k8s_api_deepcopy,github.com/cilium/cilium/pkg,"maps:ctmap")
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
	$(QUIET) $(GOLIST) $(GO) vet \
    ./api/... \
    ./bugtool/... \
    ./cilium/... \
    ./cilium-health/... \
    ./common/... \
    ./daemon/... \
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
	@$(ECHO_CHECK) $(GOFILES)
	$(QUIET) ineffassign .

logging-subsys-field:
	@$(ECHO_CHECK) contrib/scripts/check-logging-subsys-field.sh
	$(QUIET) contrib/scripts/check-logging-subsys-field.sh

check-microk8s:
	@$(ECHO_CHECK) microk8s is ready...
	$(QUIET)microk8s.status >/dev/null \
		|| (echo "Error: Microk8s is not running" && exit 1)
	$(QUIET)microk8s.status -o yaml | grep -q "registry.*enabled" \
		|| (echo "Error: Microk8s registry must be enabled" && exit 1)

LOCAL_IMAGE_TAG=local
LOCAL_IMAGE=localhost:32000/cilium/cilium:$(LOCAL_IMAGE_TAG)
microk8s: check-microk8s
	$(QUIET)$(MAKE) dev-docker-image DOCKER_IMAGE_TAG=$(LOCAL_IMAGE_TAG)
	@echo "  DEPLOY image to microk8s ($(LOCAL_IMAGE))"
	$(CONTAINER_ENGINE_FULL) tag cilium/cilium-dev:$(LOCAL_IMAGE_TAG) $(LOCAL_IMAGE)
	$(CONTAINER_ENGINE_FULL) push $(LOCAL_IMAGE)
	$(QUIET)kubectl apply -f contrib/k8s/microk8s-prepull.yaml
	$(QUIET)kubectl -n kube-system delete pod -l name=prepull
	$(QUIET)kubectl -n kube-system rollout status ds/prepull
	@echo
	@echo "Update image tag like this when ready:"
	@echo "    kubectl -n kube-system set image ds/cilium cilium-agent=$(LOCAL_IMAGE)"
	@echo "Or, redeploy the Cilium pods:"
	@echo "    kubectl -n kube-system delete pod -l k8s-app=cilium"

precheck: ineffassign logging-subsys-field
	@$(ECHO_CHECK) contrib/scripts/check-fmt.sh
	$(QUIET) contrib/scripts/check-fmt.sh
	@$(ECHO_CHECK) contrib/scripts/check-log-newlines.sh
	$(QUIET) contrib/scripts/check-log-newlines.sh
	@$(ECHO_CHECK) contrib/scripts/check-missing-tags-in-tests.sh
	$(QUIET) contrib/scripts/check-missing-tags-in-tests.sh
	@$(ECHO_CHECK) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) contrib/scripts/check-assert-deep-equals.sh
	$(QUIET) $(MAKE) -C bpf build_all

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

docs-container:
	$(QUIET)cp -r ./api ./Documentation/_api
	$(CONTAINER_ENGINE_FULL) image build -t cilium/docs-builder -f Documentation/Dockerfile ./Documentation; \
	  (ret=$$?; rm -r ./Documentation/_api && exit $$ret)

DOCS_PORT=9081
render-docs: test-docs
	$(CONTAINER_ENGINE_FULL) container run --rm -dit --name docs-cilium -p $(DOCS_PORT):80 -v $$(pwd)/Documentation/_build/html/:/usr/local/apache2/htdocs/ httpd:2.4
	@echo "$$(tput setaf 2)Running at http://localhost:$(DOCS_PORT)$$(tput sgr0)"

test-docs: docs-container
	-$(CONTAINER_ENGINE_FULL) container rm -f docs-cilium >/dev/null 2>&1 || true
	$(CONTAINER_ENGINE_FULL) container run --rm -v $$(pwd):/srv/ cilium/docs-builder /bin/bash -c 'make html'

manpages:
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages:
	cp man/* /usr/local/share/man/man1/
	mandb

# Strip "tabs assets" errors from the dummy target, but fail on target failure.
check-docs:
	$(QUIET)($(MAKE) -C Documentation/ dummy SPHINXOPTS="$(SPHINXOPTS)" 2>&1 && touch $@.ok) \
		| grep -v "tabs assets"
	@rm $@.ok 2>/dev/null

postcheck: build
	@$(ECHO_CHECK) contrib/scripts/check-cmdref.sh
	$(QUIET) MAKE=$(MAKE) contrib/scripts/check-cmdref.sh
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	@$(SKIP_DOCS) || $(MAKE) check-docs

minikube:
	$(QUIET) contrib/scripts/minikube.sh

update-golang: update-golang-dockerfiles update-travis-go-version

update-golang-dockerfiles:
	$(QUIET) sed -i 's/GO_VERSION .*/GO_VERSION $(GO_VERSION)/g' Dockerfile.builder
	$(QUIET) for fl in $(shell find . -name "*Dockerfile*") ; do sed -i 's/golang:.* /golang:$(GO_VERSION) as /g' $$fl ; done
	@echo "Updated go version in Dockerfiles to $(GO_VERSION)"

update-travis-go-version:
	$(QUIET) sed -e 's/TRAVIS_GO_VERSION/$(GO_VERSION)/g' .travis.yml.tmpl > .travis.yml
	@echo "Updated go version in .travis.yml to $(GO_VERSION)"

.PHONY: force generate-api generate-health-api install
force :;
