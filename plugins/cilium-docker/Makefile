include ../../Makefile.defs

TARGET=cilium-docker

all: $(TARGET)

tests:
	go test ./...

SOURCES := $(shell find . -name '*.go')

$(TARGET): $(SOURCES)
	go build -o $(TARGET)

run:
	./cilium-docker -d

clean:
	go clean
	rm -f $(TARGET)

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	cp $(TARGET) ${GOPATH}/bin
