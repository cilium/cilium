# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

EXTRA_GO_BUILD_LDFLAGS = -extldflags -Wl,-soname,libcilium.so.$(VERSION_MAJOR)

TARGET := libcilium.so

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD_WITH_CGO) -o $@.$(VERSION_MAJOR) -buildmode=c-shared
	$(QUIET)ln -sf $@.$(VERSION_MAJOR) $@ || cp $@.$(VERSION_MAJOR) $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET).$(VERSION_MAJOR) $(DESTDIR)$(LIBDIR)
	ln -sf $(TARGET).$(VERSION_MAJOR) $(DESTDIR)$(LIBDIR)/$(TARGET)

header: libcilium.h
libcilium.h: proxylib.go
	$(GO) tool cgo -exportheader libcilium.h proxylib.go

install-binary: install

install-bash-completion:
