include ../Makefile.defs

TARGET=cilium-health
SOURCES := $(shell find ../api/v1/health ../pkg/health cmd . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	$(GO) build -i $(GOBUILD) -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
	$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
