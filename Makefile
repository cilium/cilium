include Makefile.defs

SUBDIRS = docker-plugin cilium-net-daemon cni bpf

all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i; done

tests:
	$(MAKE) -C common tests
	for i in $(SUBDIRS); do $(MAKE) -C $$i tests; done
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
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
