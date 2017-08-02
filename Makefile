include Makefile.defs

SUBDIRS = plugins bpf cilium daemon
GOFILES = $(shell go list ./... | grep -v /vendor/)
GOLANGVERSION = $(shell go version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests: tests-common tests-consul

tests-common: force
	tests/00-fmt.sh
	go vet $(GOFILES)

tests-etcd:
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
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(GOFILES),\
	go test \
            -ldflags "-X "github.com/cilium/cilium/pkg/kvstore".backend=etcd" \
            -timeout 30s -coverprofile=coverage.out -covermode=count $(pkg) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	docker rm -f "cilium-etcd-test-container"

tests-consul:
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
            -ldflags "-X "github.com/cilium/cilium/pkg/kvstore".backend=consul" \
            -timeout 30s -coverprofile=coverage.out -covermode=count $(pkg) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	docker rm -f "cilium-consul-test-container"

clean-container:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done

clean: clean-container
	-$(MAKE) -C ./contrib/packaging/deb clean
	-$(MAKE) -C ./contrib/packaging/rpm clean
	-$(MAKE) -C ./contrib/packaging/docker clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

docker-image-prod:
	$(MAKE) -C ./contrib/packaging/docker docker-image-prod

docker-image-dependencies:
	$(MAKE) -C ./contrib/packaging/docker docker-image-dependencies

docker-image-dev:
	$(MAKE) -C ./contrib/packaging/docker docker-image-dev

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


.PHONY: force
force :;
