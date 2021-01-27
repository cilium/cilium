GO := CGO_ENABLED=0 go
GO_TAGS ?=
TARGET=cilium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
TEST_TIMEOUT ?= 5s

$(TARGET):
	$(GO) build $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s" \
		-o $(TARGET) \
		./cmd/cilium

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)

test:
	go test -timeout=$(TEST_TIMEOUT) -race -cover $$(go list ./...)

bench:
	go test -timeout=30s -bench=. $$(go list ./...)

.PHONY: $(TARGET) install clean test bench
