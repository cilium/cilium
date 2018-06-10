include ../../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

SOURCES := $(shell find ../../api/v1 ../../common ../../pkg/client ../../pkg/endpoint driver . -name '*.go')

$(TARGET): $(SOURCES)
	echo "Cilium docker"
	@$(ECHO_GO)
	$(GO) build -i $(GOBUILD) -o $(TARGET) -v -x
	ls -la

run:
	./cilium-docker -d

clean:
	echo "CLEAN!"
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	$(GO) clean
	-$(QUIET) rm -f $(TARGET)

install:
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
