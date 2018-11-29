include ../../Makefile.defs

TARGET=cilium-ring-dump
SOURCES := $(shell find ../../pkg/bpf cmd . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)

all: $(TARGET)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
