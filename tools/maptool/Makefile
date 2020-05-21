# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../Makefile.defs

TARGET := maptool

.PHONY: all $(TARGET) $(SUBDIRS) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
ifneq ($(RACE),"")
	$(QUIET)$(GO_BUILD_WITH_CGO) -o $@
else
	$(QUIET)$(GO_BUILD) -o $@
endif

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
