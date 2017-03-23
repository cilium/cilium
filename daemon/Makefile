include ../Makefile.defs

TARGET=cilium-agent
SOURCES := $(shell find ../api ../common ../daemon ../pkg . -name '*.go')
$(TARGET): $(SOURCES) check-bindata
	go build $(GOBUILD) -ldflags "-X "github.com/cilium/cilium/common".Version=$(VERSION)" -o $(TARGET)
GO_BINDATA := go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore '.+\.o$$'

all: $(TARGET)

clean:
	rm -f $(TARGET)
	go clean

install:
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

.PHONY: check-bindata
check-bindata:
	@which go-bindata > /dev/null 2> /dev/null || exit 0 && \
	($(GO_BINDATA)  -o ./bindata.tmp ../bpf/...; \
	diff -Nru bindata.go bindata.tmp; FAIL=$$?; rm bindata.tmp; test $$FAIL -eq 1 && (\
	echo "##################################################################"; \
	echo ""; \
	echo "  ERROR: bindata.go is out of date. Run 'make go-bindata' in daemon/"; \
	echo ""; \
	echo "##################################################################" ); \
	exit $$FAIL)

go-bindata: $(shell find ../bpf)
	$(GO_BINDATA) -o ./bindata.go ../bpf/...
