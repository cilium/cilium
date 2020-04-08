include ../Makefile.defs

SUBDIRS = responder
TARGET = cilium-health

.PHONY: all $(SUBDIRS) install clean

all: $(TARGET) $(SUBDIRS)

SOURCES := $(shell find ../api/v1/health ../pkg/health cmd . \
	\( -name '*.go' ! -name '*_test.go' $(foreach dir,$(SUBDIRS),! -path './$(dir)/*') \) )
$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)

$(SUBDIRS): force
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

clean:
	@$(ECHO_CLEAN)
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean $(GOCLEAN)

install:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

.PHONY: force
force :;
