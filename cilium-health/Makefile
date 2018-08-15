include ../Makefile.defs

TARGET=cilium-health
SOURCES := $(shell find ../api/v1/health ../pkg/health cmd . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(GO) build $(GOBUILD) -o $(TARGET)

all: $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
