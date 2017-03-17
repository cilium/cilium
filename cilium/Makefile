include ../Makefile.defs

TARGET=cilium
SOURCES := $(shell find ../api ../bpf ../daemon ../common ../pkg cmd . -name '*.go')
$(TARGET): $(SOURCES)
	go build $(GOBUILD) -ldflags "-X "github.com/cilium/cilium/common".Version=$(VERSION)" -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
	go clean

install: all
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) generate-bash-completion > bash_autocomplete
	$(INSTALL) -m 0644 -T bash_autocomplete $(DESTDIR)$(CONFDIR)/bash_completion.d/cilium
