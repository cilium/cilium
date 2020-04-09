include ../Makefile.quiet
include ../Makefile.defs

TARGET=cilium
LINKS=hubble
SOURCES := $(shell find ../api ../daemon ../common ../pkg cmd . \( -name '*.go' ! -name '*_test.go' \))

$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)

all: $(TARGET) links

links:
	$(foreach link,$(LINKS), ln -f -s $(TARGET) $(link) || cp $(TARGET) $(link);)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO) clean $(GOCLEAN)
	$(foreach link,$(LINKS), $(QUIET)rm -f $(link);)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > bash_autocomplete
	$(foreach link,$(LINKS),./$(link) completion bash >> bash_autocomplete;)
	$(QUIET)$(INSTALL) -m 0644 -T bash_autocomplete $(DESTDIR)$(CONFDIR)/bash_completion.d/cilium
	$(foreach link,$(LINKS),ln -f -s $(TARGET) $(DESTDIR)$(BINDIR)/$(link) || cp $(TARGET) $(DESTDIR)$(BINDIR)/$(link);)
