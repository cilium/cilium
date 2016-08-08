include ../../Makefile.defs

all: lb

tests:
	go fmt ./...
	go test ./...

runtime-tests:

SOURCES := $(shell find . -name '*.go')

lb: $(SOURCES)
	go build -o lb

clean:
	rm -f lb

install:
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/ lb
