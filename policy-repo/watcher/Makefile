include ../../Makefile.defs

HOOKS = post-merge
SCRIPTS = cilium-policy-watcher

all:

install:
	$(INSTALL) -m 0755 -t $(DESTDIR)$(LIBDIR)/cilium/githooks/ $(HOOKS)
	$(INSTALL) -m 0755 -t $(DESTDIR)$(BINDIR) $(SCRIPTS)
