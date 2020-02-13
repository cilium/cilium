# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs

TARGET=cilium-agent
LINKS=cilium-node-monitor
SOURCES := $(shell find ../api ../common ../daemon ../pkg . \( -name '*.go'  ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET) CGO_ENABLED=0 $(GO) build $(GOBUILD) -o $(TARGET)

all: $(TARGET) links

links:
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(link) || cp $(TARGET) $(link);)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean $(GOCLEAN)
	$(foreach link,$(LINKS), rm -f $(link);)

ifeq ("$(PKG_BUILD)","")

install:
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link) || cp $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

else

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link) || cp $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)

endif
