include Makefile.defs
include daemon/bpf.sha

SUBDIRS = proxylib envoy plugins bpf cilium daemon monitor cilium-health bugtool
GOFILES ?= $(subst _$(ROOT_DIR)/,,$(shell go list ./... | grep -v /vendor/ | grep -v /contrib/ | grep -v envoy/envoy))
TESTPKGS ?= $(subst _$(ROOT_DIR)/,,$(shell go list ./... | grep -v /vendor/ | grep -v /contrib/ | grep -v envoy/envoy | grep -v test))
GOLANGVERSION = $(shell go version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')
GOLANG_SRCFILES=$(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v vendor)
BPF_FILES ?= $(shell git ls-files ../bpf/ | tr "\n" ' ')
BPF_SRCFILES=$(subst ../,,$(BPF_FILES))

DOCKER=$(QUIET)docker

SWAGGER_VERSION = 0.12.0
SWAGGER = $(DOCKER) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) -e GOPATH=$(GOPATH) --entrypoint swagger quay.io/goswagger/swagger:$(SWAGGER_VERSION)

GOTEST_OPTS = -test.v -check.vv

UTC_DATE=$(shell date -u "+%Y-%m-%d")

all: precheck build postcheck
	@echo "Build finished."

build: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

jenkins-precheck:
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER run --rm precheck

# invoked from ginkgo Jenkinsfile
tests-ginkgo: force
	# Make the bindata to run the unittest
	$(MAKE) -C daemon go-bindata
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER run --rm test
	# Remove the networks
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER down

clean-ginkgo-tests:
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER down
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER rm

TEST_LDFLAGS=-ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulDummyAddress=consul:8500 -X github.com/cilium/cilium/pkg/kvstore.etcdDummyAddress=http://etcd:4002"

# invoked from ginkgo compose file after starting kvstore backends
tests-ginkgo-real:
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(TESTPKGS),\
	go test $(TEST_LDFLAGS) \
            -timeout 360s -coverprofile=coverage.out -covermode=count $(pkg) $(GOTEST_OPTS) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	$(GO) tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true

tests-envoy:
	@ $(MAKE) -C envoy tests

start-kvstores:
	@echo Starting key-value store containers...
	-$(DOCKER) rm -f "cilium-etcd-test-container" 2> /dev/null
	$(DOCKER) run -d \
	    --name "cilium-etcd-test-container" \
	    -p 4002:4001 \
        quay.io/coreos/etcd:v3.2.17 \
        etcd -name etcd0 \
        -advertise-client-urls http://0.0.0.0:4001 \
        -listen-client-urls http://0.0.0.0:4001 \
        -listen-peer-urls http://0.0.0.0:2380 \
        -initial-cluster-token etcd-cluster-1 \
        -initial-cluster-state new
	-$(DOCKER) rm -f "cilium-consul-test-container" 2> /dev/null
	$(DOCKER) run -d \
           --name "cilium-consul-test-container" \
           -p 8501:8500 \
           -e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true, "disable_update_check": true}' \
           consul:1.1.0 \
           agent -client=0.0.0.0 -server -bootstrap-expect 1

tests: force
	$(MAKE) unit-tests tests-envoy

unit-tests: start-kvstores
	$(QUIET) $(MAKE) -C daemon/ check-bindata
	$(QUIET) echo "mode: count" > coverage-all.out
	$(QUIET) echo "mode: count" > coverage.out
	$(QUIET)$(foreach pkg,$(TESTPKGS),\
	go test \
            -timeout 360s -coverprofile=coverage.out -covermode=count $(pkg) $(GOTEST_OPTS) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	$(QUIET)$(foreach pkg,$(TESTPKGS),\
	sudo go test -timeout 360s -tags=privileged_tests $(pkg) $(GOTEST_OPTS) || exit 1;)
	$(GO) tool cover -html=coverage-all.out -o=coverage-all.html
	$(QUIET) rm coverage-all.out
	$(QUIET) rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	$(DOCKER) rm -f "cilium-etcd-test-container"
	$(DOCKER) rm -f "cilium-consul-test-container"

clean-tags:
	@$(ECHO_CLEAN) tags
	@-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $(GOLANG_SRCFILES) $(BPF_SRCFILES)
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

# Workaround for not having git in the build environment
GIT_VERSION: .git
	echo "$(GIT_VERSION)" >GIT_VERSION

envoy/SOURCE_VERSION: .git
	git rev-parse HEAD >envoy/SOURCE_VERSION

docker-image: clean GIT_VERSION envoy/SOURCE_VERSION
	$(QUIET)grep -v -E "(SOURCE|GIT)_VERSION" .gitignore >.dockerignore
	$(QUIET)echo ".*" >>.dockerignore # .git pruned out
	$(QUIET)echo "Documentation" >>.dockerignore # Not needed
	@$(ECHO_GEN) docker-image
	$(DOCKER) build --build-arg LOCKDEBUG=${LOCKDEBUG} --build-arg V=${V} -t "cilium/cilium:$(DOCKER_IMAGE_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/cilium:$(DOCKER_IMAGE_TAG)"

docker-image-runtime:
	cd contrib/packaging/docker && docker build -t "cilium/cilium-runtime:$(UTC_DATE)" -f Dockerfile.runtime .

docker-image-builder:
	cd envoy && docker build -t "quay.io/cilium/cilium-builder:$(UTC_DATE)" .

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
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml
	-$(SWAGGER) generate client -a restapi \
		-t api/v1 -t api/v1/health/ -f api/v1/health/openapi.yaml

generate-k8s-api:
	cd "./vendor/k8s.io/code-generator" && \
	./generate-groups.sh all \
	    github.com/cilium/cilium/pkg/k8s/client \
	    github.com/cilium/cilium/pkg/k8s/apis \
	    "cilium.io:v2" \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
	cd "./vendor/k8s.io/code-generator" && \
	./generate-groups.sh deepcopy \
	    github.com/cilium/cilium/pkg/k8s/client \
	    github.com/cilium/cilium/pkg \
	    "policy:api" \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"
	cd "./vendor/k8s.io/code-generator" && \
	./generate-groups.sh deepcopy \
	    github.com/cilium/cilium/pkg/k8s/client \
	    github.com/cilium/cilium \
	    "pkg:labels" \
	    --go-header-file "$(PWD)/hack/custom-boilerplate.go.txt"

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
	for pkg in $(GOFILES); do go fmt $$pkg; done

govet:
	@$(ECHO_CHECK) vetting all GOFILES...
	$(GO) tool vet api pkg $(SUBDIRS)

ineffassign:
	@$(ECHO_CHECK) ineffassign
	$(QUIET) ineffassign .

logging-subsys-field:
	@$(ECHO_CHECK) contrib/scripts/check-logging-subsys-field.sh
	$(QUIET) contrib/scripts/check-logging-subsys-field.sh

precheck: govet ineffassign logging-subsys-field
	@$(ECHO_CHECK) contrib/scripts/check-fmt.sh
	$(QUIET) contrib/scripts/check-fmt.sh
	@$(ECHO_CHECK) contrib/scripts/check-log-newlines.sh
	$(QUIET) contrib/scripts/check-log-newlines.sh

pprof-help:
	@echo "Available pprof targets:"
	@echo "  pprof-heap"
	@echo "  pprof-profile"
	@echo "  pprof-block"
	@echo "  pprof-trace-5s"
	@echo "  pprof-mutex"

pprof-heap:
	$(GO) tool pprof http://localhost:6060/debug/pprof/heap

pprof-profile:
	$(GO) tool pprof http://localhost:6060/debug/pprof/profile


pprof-block:
	$(GO) tool pprof http://localhost:6060/debug/pprof/block

pprof-trace-5s:
	curl http://localhost:6060/debug/pprof/trace?seconds=5

pprof-mutex:
	$(GO) tool pprof http://localhost:6060/debug/pprof/mutex

update-authors:
	@echo "Updating AUTHORS file..."
	@echo "The following people, in alphabetical order, have either authored or signed" > AUTHORS
	@echo "off on commits in the Cilium repository:" >> AUTHORS
	@echo "" >> AUTHORS
	@contrib/scripts/extract_authors.sh >> AUTHORS
	@cat .authors.aux >> AUTHORS

docs-container:
	$(QUIET)grep -v -E "(SOURCE|GIT)_VERSION" .gitignore >.dockerignore
	$(QUIET)echo ".*" >>.dockerignore # .git pruned out
	$(QUIET)cp -r ./api ./Documentation/_api
	$(DOCKER) image build -t cilium/docs-builder -f Documentation/Dockerfile ./Documentation; \
	  (ret=$$?; rm -r ./Documentation/_api && exit $$ret)


render-docs: docs-container
	-$(DOCKER) container rm -f docs-cilium >/dev/null
	$(DOCKER) container run --rm -ti -u $$(id -u):$$(id -g $(USER)) -v $$(pwd):/srv/ cilium/docs-builder /bin/bash -c 'make html'
	$(DOCKER) container run --rm -dit --name docs-cilium -p 8080:80 -v $$(pwd)/Documentation/_build/html/:/usr/local/apache2/htdocs/ httpd:2.4
	@echo "$$(tput setaf 2)Running at http://localhost:8080$$(tput sgr0)"

test-docs: docs-container
	-$(DOCKER) container rm -f docs-cilium >/dev/null
	$(DOCKER) container run --rm -v $$(pwd):/srv/ cilium/docs-builder /bin/bash -c 'make html'

manpages:
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages:
	cp man/* /usr/local/share/man/man1/
	mandb

postcheck: build
	@$(ECHO_CHECK) contrib/scripts/check-cmdref.sh
	$(QUIET) MAKE=$(MAKE) contrib/scripts/check-cmdref.sh
	@$(ECHO_CHECK) contrib/scripts/lock-check.sh
	$(QUIET) contrib/scripts/lock-check.sh
	-$(QUIET) $(MAKE) -C Documentation/ dummy SPHINXOPTS="-q" 2>&1 | grep -v "tabs assets"

.PHONY: force generate-api generate-health-api
force :;
