# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET=bpf-geneve-datapath

.PHONY: all test $(TARGET) install clean

all: $(TARGET)

test:
	$(GO) test -v ./...

$(TARGET):
	$(GO_BUILD) -o $(@) .

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
