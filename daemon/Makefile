include ../Makefile.defs

all:

TARGET=cilium-agent
SOURCES := $(shell find ../api ../common ../daemon ../pkg . -name '*.go')
$(TARGET): $(SOURCES)
	go build $(GOBUILD) -ldflags "-X "github.com/cilium/cilium/common".Version=$(VERSION)" -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
	go clean

install: all
	groupadd -f cilium
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

go-bindata: $(shell find ../bpf)
	go-bindata -prefix ../ -ignore Makefile -ignore '.+\.o$$' ../bpf/...
