include ../../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	go build -ldflags "-X "github.com/cilium/cilium/common".Version=$(VERSION)" -o $(TARGET)

run:
	./cilium-docker -d

clean:
	go clean
	rm -f $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
