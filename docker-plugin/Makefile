include ../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

tests:
	godep go fmt ./...
	godep go test ./...

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	$(MAKE) tests
	godep go build -o $(TARGET)

run:
	./run.sh

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
