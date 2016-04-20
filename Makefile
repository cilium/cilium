include Makefile.defs

SUBDIRS = docker-plugin cilium cni bpf

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests:
	$(MAKE) -C common tests
	$(MAKE) -C cilium-net-daemon tests
	for i in $(SUBDIRS); do $(MAKE) -C $$i tests; done
	$(MAKE) -C policy-repo tests
	$(MAKE) -C integration tests

run-docker-plugin:
	$(MAKE) -C docker-plugin run

run-cilium-daemon:
	$(MAKE) -C cilium-net-daemon run

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(RUNDIR)/cilium/globals
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/lib
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/githooks
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

runtime-tests:
	for i in $(SUBDIRS); do $(MAKE) -C $$i runtime-tests; done

.PHONY: force
force :;
