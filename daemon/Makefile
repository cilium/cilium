include ../Makefile.defs

TARGET=cilium-agent
SOURCES := $(shell find ../api ../common ../daemon ../pkg . -name '*.go')
$(TARGET): $(SOURCES) check-bindata
	go build $(GOBUILD) -o $(TARGET)
GO_BINDATA := go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore '.+\.o$$' \
	-ignore '.+\.orig$$' -ignore '.+~$$' -ignore '\.DS_Store'
GO_BINDATA_SHA1SUM=4c07b9aaa78073a929aa67dc4bcb862de58d7522

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
	$(GO_BINDATA) -o ./bindata.go ../bpf/...
