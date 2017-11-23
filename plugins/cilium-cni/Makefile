include ../../Makefile.defs

all: cilium-cni

TARGET=cilium-cni

clean:
	@$(ECHO_CLEAN)
	$(QUIET)$(GO) clean $(GOCLEAN)
	-$(QUIET)rm -f $(TARGET)

SOURCES := $(shell find ../../api/v1/models ../../common ../../pkg/client ../../pkg/endpoint . -name '*.go')

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	# Compile without cgo to allow use of cilium-cni on non-glibc platforms - see GH-5055
	$(QUIET) $(GO) build $(GOBUILD) -o $(TARGET)

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(CNICONFDIR)
	$(INSTALL) -m 0644 05-cilium-cni.conf $(DESTDIR)$(CNICONFDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(CNIBINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(CNIBINDIR)
