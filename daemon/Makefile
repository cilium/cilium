# We keep track of the SHA over bindata.go plus the go version used to
# generate the bindata.go as it affects the generated code. A change
# of version is likely causing a SHA conflict as well.
include bpf.sha

# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs


TARGET=cilium-agent
SOURCES := $(shell find ../api ../common ../daemon ../pkg ../monitor . -name '*.go')
$(TARGET): $(SOURCES) check-bindata
	$(GO) build -i $(GOBUILD) -o $(TARGET)

GO_BINDATA := go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore filter_config.h \
	-ignore '.+\.o$$' -ignore '.+\.orig$$' -ignore '.+~$$' \
	-ignore '\.DS_Store'

all: $(TARGET)

clean:
	rm -f $(TARGET)
	$(GO) clean

ifeq ("$(PKG_BUILD)","")

install:
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

else

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

endif

.PHONY: check-bindata
check-bindata: go-bindata
	../contrib/scripts/bindata.sh $(GO_BINDATA_SHA1SUM)

apply-bindata: go-bindata
	../contrib/scripts/bindata.sh apply

go-bindata:
	$(GO_BINDATA) -o ./bindata.go `git ls-files ../bpf/`
