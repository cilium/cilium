include ../Makefile.defs

TARGET=cilium

all: $(TARGET)

tests:
	go fmt ./...
	-go test ./...

runtime-tests:

run:
	./cilium

clean:
	rm -f $(TARGET)

SOURCES := $(shell find monitor/ policy/ endpoint/ ../daemon ../common . -name '*.go')

$(TARGET): $(SOURCES)
	go build -o $(TARGET) ./main.go

install: all
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	cp ../contrib/autocomplete/bash_autocomplete /etc/bash_completion.d/cilium
	chmod 644 /etc/bash_completion.d/cilium
	cp $(TARGET) ${GOPATH}/bin
