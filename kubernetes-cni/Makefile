all: cilium-kubernetes-cni host-local

tests:
	godep go fmt ./.
	godep go test ./.

clean:
	rm -f cilium-kubernetes-cni host-local

SOURCES := $(shell find . -name '*.go')

cilium-kubernetes-cni: $(SOURCES)
	$(MAKE) tests
	godep go build -o cilium-kubernetes-cni ./kubernetes-cni.go

HOST_SOURCES := $(shell find ../Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local -iname '*.go')

host-local: $(HOST_SOURCES)
	godep go build -o host-local ../Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local 
