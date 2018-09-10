include ../Makefile.quiet
include ../Makefile.defs

TARGET=libcilium.so
DEPS := $(shell find ../pkg accesslog npds test . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(DEPS)
	@$(ECHO_GO)
	$(GO) build $(GOBUILD) -o $@ -buildmode=c-shared
	pwd
	$(INSTALL) -s -m 0755 -T $(TARGET) libcilium.so.backup
	ls -lrt

all: $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	pwd
	ls -lrt
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(LIBDIR)
