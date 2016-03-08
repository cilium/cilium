include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

tests:
	-docker run -d \
           --name "cilium-consul-test-container" \
           -p 8501:8500 \
           progrium/consul \
           -server -bootstrap-expect 1
	godep go fmt ./...
	-godep go test ./...
	docker rm -f "cilium-consul-test-container"

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
