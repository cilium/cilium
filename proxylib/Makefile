include ../Makefile.quiet
include ../Makefile.defs

TARGET=libcilium.so
DEPS := $(shell find ../pkg accesslog npds test . \( -name '*.go' ! -name '*_test.go' \))
$(TARGET): $(DEPS)
	@$(ECHO_GO)
	$(GO) build $(GOBUILD) -o $@ -buildmode=c-shared

all: $(TARGET)

# Cleaning up messes CI due to parallel builds, so do not rm the target for now
clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
#	-$(QUIET)rm -f $(TARGET)
#	$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(LIBDIR)
