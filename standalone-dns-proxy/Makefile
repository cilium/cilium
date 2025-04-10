ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

include ${ROOT_DIR}/../Makefile.defs

TARGET := standalone-dns-proxy

.PHONY: $(TARGET)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(GO) clean $(GOCLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(@)
