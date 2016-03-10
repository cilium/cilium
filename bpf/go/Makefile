include ../../Makefile.defs

all: map_ctrl

tests:
	godep go fmt ./...
	godep go test ./...

runtime-tests:

SOURCES := $(shell find . -name '*.go')

map_ctrl: $(SOURCES)
	godep go build -o map_ctrl

clean:
	rm -f map_ctrl

install:
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ map_ctrl
