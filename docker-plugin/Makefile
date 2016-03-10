include ../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

tests:
	godep go fmt ./...
	godep go test ./...

runtime-tests:
	./tests.sh

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	godep go build -o $(TARGET)

run:
	./cilium-docker -d

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
