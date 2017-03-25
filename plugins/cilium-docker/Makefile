include ../../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

SOURCES := $(shell find ../../api/v1 ../../common ../../pkg/client ../../pkg/endpoint driver . -name '*.go')

$(TARGET): $(SOURCES)
	go build $(GOBUILD) -o $(TARGET)

run:
	./cilium-docker -d

clean:
	go clean
	rm -f $(TARGET)

install:
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
