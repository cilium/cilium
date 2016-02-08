all: cilium-cni

tests:
	godep go fmt ./.
	godep go test ./.

clean:
	rm -f cilium-cni host-local

SOURCES := $(shell find . -name '*.go')

cilium-cni: $(SOURCES)
	$(MAKE) tests
	godep go build -o cilium-cni ./cilium-cni.go

install:
