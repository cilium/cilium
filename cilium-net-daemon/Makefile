include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

tests:
	godep go fmt ./...
	godep go test ./...

run:
	./run.sh

clean:
	rm -f $(TARGET)

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	$(MAKE) tests
	godep go build -o $(TARGET) ./main.go

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
