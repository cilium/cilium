all: cilium-docker

tests:
	godep go fmt ./...
	godep go test ./...

SOURCES := $(shell find . -name '*.go')

cilium-docker: $(SOURCES)
	$(MAKE) tests
	godep go build -o cilium-docker

run:
	./run.sh

clean:
	rm -f cilium-docker
