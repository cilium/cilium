include ../Makefile.defs

TARGET=cilium-agent
SOURCES := $(shell find ../api ../common ../daemon ../pkg . -name '*.go')
$(TARGET): $(SOURCES) check-bindata
	go build $(GOBUILD) -o $(TARGET)
GO_BINDATA := go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore '.+\.o$$' \
	-ignore '.+\.orig$$' -ignore '.+~$$' -ignore '\.DS_Store'
GO_BINDATA_SHA1SUM=2f41034e602acf3a29ec557d981c39a6a1f44fce
# We keep track of the go version used to update bindata in case of failures.
# Having the version will likely be useful in the cases where someone is using
# a older or newer version than the CI.
#
# The GO_VERSION_USED will be modified by the apply-bindata target:
# $ make -C daemon apply-bindata
# Alternatively you could also run it from this directory:
# $ make apply-bindata
GO_VERSION_USED=go1.8.3

all: $(TARGET)

clean:
	rm -f $(TARGET)
	go clean

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
