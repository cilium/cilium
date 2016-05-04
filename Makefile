include Makefile.defs

SUBDIRS = docker-plugin cilium cni bpf common
SUBDIRSLIB = cilium-net-daemon policy-repo integration

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests:
	for i in $(SUBDIRS); do $(MAKE) -C $$i -B tests; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i -B tests; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(RUNDIR)/cilium/globals
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/lib
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/githooks
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

runtime-tests:
	for i in $(SUBDIRS); do $(MAKE) -C $$i runtime-tests; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i -B runtime-tests; done

.PHONY: force
force :;
