all: cilium-net-daemon

tests:
	godep go fmt ./...
	godep go test ./...

run:
	./run.sh

clean:
	rm -f cilium-net-daemon

SOURCES := $(shell find . -name '*.go')

cilium-net-daemon: $(SOURCES)
	$(MAKE) tests
	godep go build -o cilium-net-daemon ./main.go
