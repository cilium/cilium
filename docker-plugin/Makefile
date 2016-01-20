all: cilium-docker

tests:
	godep go fmt ./...
	godep go test ./...

SOURCES := $(shell find . -name '*.go')

cilium-docker: $(SOURCES)
	$(MAKE) tests
	godep go build -o cilium-docker

run:
	./cilium-docker -d -n beef::1:0:0

clean:
	rm -f cilium-docker
