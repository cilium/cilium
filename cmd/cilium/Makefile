# We keep track of the SHA over bindata.go plus the go version used to
# generate the bindata.go as it affects the generated code. A change
# of version is likely causing a SHA conflict as well.

# GOBUILD relies on the order of makefile list to get VERSION file
include ../../Makefile.defs


TARGET=cilium-agent
LINKS=cilium cilium-node-monitor
SOURCES := $(shell find ../../api ../../common ../../daemon ../../pkg ../../monitor . \( -name '*.go'  ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	$(MAKE) -C ../../daemon go-bindata
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)


all: $(TARGET) links

links:
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(link);)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean
	$(foreach link,$(LINKS), rm -f $(link);)

ifeq ("$(PKG_BUILD)","")

install:
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

else

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

endif
