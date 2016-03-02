include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

tests:
	docker run -d \
           --name "cilium-consul-container-test" \
           -p 8500:8500 \
           progrium/consul \
           -server -bootstrap-expect 1
	godep go fmt ./...
	-godep go test ./...
	docker rm -f "cilium-consul-container-test"

runtime-tests:

run:
	./cilium-net-daemon

clean:
	rm -f $(TARGET)

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	$(MAKE) tests
	godep go build -o $(TARGET) ./main.go

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
