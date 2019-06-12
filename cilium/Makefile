include ../Makefile.quiet
include ../Makefile.defs

TARGET=cilium
SOURCES := $(shell find ../api ../daemon ../common ../pkg cmd . \( -name '*.go' ! -name '*_test.go' \))

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)
	strip $(TARGET)

all: $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) generate-bash-completion > bash_autocomplete
	$(INSTALL) -m 0644 -T bash_autocomplete $(DESTDIR)$(CONFDIR)/bash_completion.d/cilium
