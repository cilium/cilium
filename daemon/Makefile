# We keep track of the SHA over bindata.go plus the go version used to
# generate the bindata.go as it affects the generated code. A change
# of version is likely causing a SHA conflict as well.
include bpf.sha

# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs


TARGET=cilium-agent
LINKS=cilium-node-monitor
SOURCES := $(shell find ../api ../common ../daemon ../pkg . \( -name '*.go'  ! -name '*_test.go' \))
$(TARGET): $(SOURCES) check-bindata
	@$(ECHO_GO)
	$(QUIET) $(GO) build $(GOBUILD) -o $(TARGET)

GO_BINDATA := $(QUIET) go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore filter_config.h \
	-ignore '.+\.o$$' -ignore '.+\.orig$$' -ignore '.+~$$' \
	-ignore '\.DS_Store'

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

.PHONY: check-bindata
check-bindata: bindata.go
	@echo "  CHECK contrib/scripts/bindata.sh"
	$(QUIET) ../contrib/scripts/bindata.sh $(GO_BINDATA_SHA1SUM)

apply-bindata: go-bindata
	@$(ECHO_GEN)bpf.sha
	$(QUIET) ../contrib/scripts/bindata.sh apply

bindata.go go-bindata: $(BPF_FILES)
	@$(ECHO_GEN) $@
	$(GO_BINDATA) -o ./bindata.go $(BPF_FILES)
