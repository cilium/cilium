include ../../Makefile.defs

all: cilium-cni

TARGET=cilium-cni

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	$(GO) clean
	-$(QUIET)rm -f $(TARGET)

SOURCES := $(shell find ../../api/v1/models ../../common ../../pkg/client ../../pkg/endpoint . -name '*.go')

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	# Compile without cgo to allow use of cilium-cni on non-glibc platforms - see GH-5055
	CGO_ENABLED=0 $(GO) build $(GOBUILD) -o $(TARGET) ./cilium-cni.go

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)/etc/cni/net.d
	$(INSTALL) -m 0644 05-cilium-cni.conf $(DESTDIR)/etc/cni/net.d
	$(INSTALL) -m 0755 -d $(DESTDIR)/opt/cni/bin
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)/opt/cni/bin
