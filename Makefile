include Makefile.defs

SUBDIRS = plugins bpf cilium daemon
GOFILES = $(shell go list ./... | grep -v /vendor/)
GOLANGVERSION = $(shell go version 2>/dev/null | grep -Eo '(go[0-9].[0-9])')

all: check-golang $(SUBDIRS)

check-golang:
	if [ "${GOLANGVERSION}" = "go1.8" ]; then \
		echo "golang 1.8 is currently not supported, please downgrade to a lower version"; \
		exit 1; \
	fi

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
        quay.io/coreos/etcd:v3.1.0-rc.0 \
        etcd -name etcd0 \
        -advertise-client-urls http://0.0.0.0:4001 \
        -listen-client-urls http://0.0.0.0:4001 \
        -initial-cluster-token etcd-cluster-1 \
        -initial-cluster-state new
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(GOFILES),\
	go test \
            -ldflags "-X "github.com/cilium/cilium/daemon".kvBackend=etcd" \
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
           consul:v0.6.4 \
           agent -client=0.0.0.0 -server -bootstrap-expect 1
	echo "mode: count" > coverage-all.out
	echo "mode: count" > coverage.out
	$(foreach pkg,$(GOFILES),\
	go test \
            -ldflags "-X "github.com/cilium/cilium/daemon".kvBackend=consul" \
            -timeout 30s -coverprofile=coverage.out -covermode=count $(pkg) || exit 1;\
            tail -n +2 coverage.out >> coverage-all.out;)
	go tool cover -html=coverage-all.out -o=coverage-all.html
	rm coverage-all.out
	rm coverage.out
	@rmdir ./daemon/1 ./daemon/1_backup 2> /dev/null || true
	docker rm -f "cilium-consul-test-container"

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done
	-$(MAKE) -C ./contrib/packaging/deb clean
	-$(MAKE) -C ./contrib/packaging/rpm clean
	-$(MAKE) -C ./contrib/packaging/docker clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

docker-image:
	$(MAKE) -C ./contrib/packaging/docker

build-deb:
	$(MAKE) -C ./contrib/packaging/deb

build-rpm:
	$(MAKE) -C ./contrib/packaging/rpm

runtime-tests:
	$(MAKE) -C tests runtime-tests

generate-api:
	swagger generate server -t api/v1 -f api/v1/openapi.yaml -a restapi \
	    -s server --default-scheme=unix -C api/v1/cilium-server.yml
	swagger generate client -t api/v1 -f api/v1/openapi.yaml -a restapi

.PHONY: force
force :;
