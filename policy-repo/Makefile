include ../Makefile.defs

SUBDIRS = watcher

TARGET=cilium-net-policy

all: $(TARGET)
	$(MAKE) -C watcher

tests:
	godep go fmt ./...
	godep go test ./...

runtime-tests:

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	godep go build -o $(TARGET)

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(MAKE) -C watcher install
