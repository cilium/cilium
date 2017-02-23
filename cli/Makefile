include ../Makefile.defs

TARGET=cilium

all: $(TARGET)

run:
	./cilium

clean:
	go clean
	rm -f $(TARGET)

SOURCES := $(shell find ../bpf ../daemon ../common ../pkg . -name '*.go')

$(TARGET): $(SOURCES)
	go build $(GOBUILD) -ldflags "-X "github.com/cilium/cilium/common".Version=$(VERSION)" -o $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	$(INSTALL) -m 0644 -T ../contrib/autocomplete/bash_autocomplete $(DESTDIR)$(CONFDIR)/bash_completion.d/cilium
