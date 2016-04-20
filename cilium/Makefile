include ../Makefile.defs

TARGET=cilium

all: $(TARGET)

tests:
	godep go fmt ./...
	-godep go test ./...

runtime-tests:

run:
	./cilium

clean:
	rm -f $(TARGET)

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	godep go build -o $(TARGET) ./main.go

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
