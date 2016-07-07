include ../../Makefile.defs

all: map_ctrl

tests:
	go fmt ./...
	go test ./...

runtime-tests:

SOURCES := $(shell find . -name '*.go')

map_ctrl: $(SOURCES)
	go build -o map_ctrl

clean:
	go clean
	rm -f map_ctrl

install:
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ map_ctrl
