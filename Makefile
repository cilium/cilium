include Makefile.defs
include daemon/bpf.sha

SUBDIRS = envoy plugins bpf cilium daemon monitor cilium-health bugtool
GOFILES ?= $(shell go list ./... | grep -v /vendor/ | grep -v /contrib/ | grep -v /test | grep -v envoy.*api)
GOLANGVERSION = $(shell go version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')
GOLANG_SRCFILES=$(shell for pkg in $(subst github.com/cilium/cilium/,,$(GOFILES)); do find $$pkg -name *.go -print; done | grep -v /vendor/)
BPF_SRCFILES=$(subst ../,,$(BPF_FILES))

GOTEST_OPTS = -test.v -check.v

UTC_DATE=$(shell date -u "+%Y-%m-%d")

all: precheck-gofmt build cmdref-check lock-check
	@echo "Build finished."

build: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests-ginkgo: force
	tests/00-fmt.sh
	go vet $(GOFILES)
	# Make the bindata to run the unittest
	make -C daemon go-bindata
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER run --rm test
	# Remove the networks
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER down

clean-ginkgo-tests:
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER down
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER rm

tests-envoy:
	@ $(MAKE) -C envoy tests

tests: tests-envoy
	tests/00-fmt.sh
	go vet $(GOFILES)
	@docker rm -f "cilium-etcd-test-container" 2> /dev/null || true
	-docker run -d \
	    --name "cilium-etcd-test-container" \
	    -p 4002:4001 \
        quay.io/coreos/etcd:v3.1.0 \
        etcd -name etcd0 \
        -advertise-client-urls http://0.0.0.0:4001 \
        -listen-client-urls http://0.0.0.0:4001 \
        -initial-cluster-token etcd-cluster-1 \
        -initial-cluster-state new
	@docker rm -f "cilium-consul-test-container" 2> /dev/null || true
	-docker run -d \
           --name "cilium-consul-test-container" \
           -p 8501:8500 \
           -e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true}' \
           consul:0.8.3 \
           agent -client=0.0.0.0 -server -bootstrap-expect 1
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(GOFILES),\
	go test \
            -timeout 30s -coverprofile=coverage.out -covermode=count $(pkg) $(GOTEST_OPTS) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	docker rm -f "cilium-etcd-test-container"
	docker rm -f "cilium-consul-test-container"

tests-ginkgo: tests-common-ginkgo

tests-common-ginkgo: force
	tests/00-fmt.sh
	go vet $(GOFILES)
	# Make the bindata to run the unittest
	make -C daemon go-bindata
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER run --rm test
	# Remove the networks
	docker-compose -f test/docker-compose.yml -p $$JOB_BASE_NAME-$$BUILD_NUMBER down

tests-consul-ginkgo:
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(GOFILES),\
	go test \
            -ldflags "-X github.com/cilium/cilium/pkg/kvstore.consulAddress=consul:8500" \
            -timeout 30s -coverprofile=coverage.out -covermode=count $(pkg) $(GOTEST_OPTS) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true


clean-tags:
	-$(MAKE) -C bpf/ clean-tags
	-rm -f cscope.out cscope.in.out cscope.po.out cscope.files tags

tags: $(GOLANG_SRCFILES) $(BPF_SRCFILES)
	@$(MAKE) -C bpf/ tags
	gotags -R . > tags
	@ echo $(GOLANG_SRCFILES) | sed 's/ /\n/g' > cscope.files
	cscope -R -b -q

clean-container:
	-for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	-for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done

clean: clean-container
	-$(MAKE) -C ./contrib/packaging/deb clean
	-$(MAKE) -C ./contrib/packaging/rpm clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

# Workaround for not having git in the build environment
GIT_VERSION: .git
	echo "$(GIT_VERSION)" >GIT_VERSION

envoy/SOURCE_VERSION: .git
	git rev-parse HEAD >>envoy/SOURCE_VERSION

docker-image: clean GIT_VERSION envoy/SOURCE_VERSION
	grep -v -E "(SOURCE|GIT)_VERSION" .gitignore >.dockerignore
	echo ".*" >>.dockerignore # .git pruned out
	echo "Documentation" >>.dockerignore # Not needed
	docker build -t "cilium/cilium:$(DOCKER_IMAGE_TAG)" .
	echo "Push like this when ready:\ndocker push cilium/cilium:$(DOCKER_IMAGE_TAG)"

docker-image-runtime:
	cd contrib/packaging/docker && docker build -t "cilium/cilium-runtime:$(UTC_DATE)" -f Dockerfile.runtime .
	echo "Update Dockerfile with the new tag and push like this when ready:\ndocker push cilium/cilium-runtime:$(UTC_DATE)"

docker-image-builder:
	cp contrib/packaging/docker/Dockerfile.builder envoy/.
	cd envoy && docker build -t "cilium/cilium-builder:$(UTC_DATE)" -f Dockerfile.builder .
	rm envoy/Dockerfile.builder
	echo "Update Dockerfile with the new tag and push like this when ready:\ndocker push cilium/cilium-builder:$(UTC_DATE)"

build-deb:
	$(MAKE) -C ./contrib/packaging/deb

build-rpm:
	$(MAKE) -C ./contrib/packaging/rpm

runtime-tests:
	$(MAKE) -C tests runtime-tests

k8s-tests:
	$(MAKE) -C tests k8s-tests

generate-api:
	swagger generate server -t api/v1 -f api/v1/openapi.yaml -a restapi \
	    -s server --default-scheme=unix -C api/v1/cilium-server.yml
	swagger generate client -t api/v1 -f api/v1/openapi.yaml -a restapi

generate-health-api:
	swagger generate server -t api/v1 -f api/v1/health/openapi.yaml \
	    -a restapi -t api/v1/health/ -s server
	swagger generate client -t api/v1 -f api/v1/health/openapi.yaml \
	    -a restapi -t api/v1/health/

vps:
	VBoxManage list runningvms

reload:
	cd daemon && make go-bindata
	make
	sudo systemctl stop cilium cilium-docker
	sudo make install
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

precheck-gofmt:
	tests/00-fmt.sh

pprof-help:
	@echo "Available pprof targets:"
	@echo "  pprof-heap"
	@echo "  pprof-profile"
	@echo "  pprof-block"
	@echo "  pprof-trace-5s"
	@echo "  pprof-mutex"

pprof-heap:
	go tool pprof http://localhost:6060/debug/pprof/heap

pprof-profile:
	go tool pprof http://localhost:6060/debug/pprof/profile


pprof-block:
	go tool pprof http://localhost:6060/debug/pprof/block

pprof-trace-5s:
	curl http://localhost:6060/debug/pprof/trace?seconds=5

pprof-mutex:
	go tool pprof http://localhost:6060/debug/pprof/mutex

update-authors:
	@echo "Updating AUTHORS file..."
	@echo "The following people, in alphabetical order, have either authored or signed" > AUTHORS
	@echo "off on commits in the Cilium repository:" >> AUTHORS
	@echo "" >> AUTHORS
	@contrib/scripts/extract_authors.sh >> AUTHORS
	@cat .authors.aux >> AUTHORS

docs-container:
	docker build -t cilium/docs-builder -f Documentation/Dockerfile .

manpages:
	-rm -r man
	mkdir -p man
	cilium cmdman -d man

install-manpages:
	cp man/* /usr/local/share/man/man1/
	mandb

cmdref-check:
	tests/00-check-cmdref.sh

lock-check:
	contrib/scripts/lock-check.sh

.PHONY: force
force :;
