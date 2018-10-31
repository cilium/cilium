include ../Makefile.quiet
include ../Makefile.defs

TARGET=libcilium.so
DEPS := $(shell find ../pkg accesslog npds test . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(DEPS)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $@ -buildmode=c-shared

all: $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(LIBDIR)
