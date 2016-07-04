include Makefile.defs

SUBDIRS = plugins cli bpf common
SUBDIRSLIB = daemon integration

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests: force
	for i in $(SUBDIRS); do $(MAKE) -C $$i -B tests; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i -B tests; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(RUNDIR)/cilium/globals
	$(INSTALL) -m 0755 -d $(DESTDIR)$(RUNDIR)/cilium/static
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/lib
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/githooks
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

runtime-tests:
	$(MAKE) -C tests runtime-tests
	for i in $(SUBDIRS); do $(MAKE) -C $$i runtime-tests; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i -B runtime-tests; done

.PHONY: force
force :;
