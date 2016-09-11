include ../Makefile.defs

SUBDIRS = watcher

TARGET=cilium-net-policy

all:
	$(MAKE) -C watcher

tests:
	go test ./...

SOURCES := $(shell find . -name '*.go')

$(TARGET):

clean:
	rm -f $(TARGET)

install:
	$(MAKE) -C watcher install
