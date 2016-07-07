include ../Makefile.defs

SUBDIRS = cilium-docker cilium-cni

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests:
	for i in $(SUBDIRS); do $(MAKE) -C $$i -B tests; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done

install:
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

runtime-tests:
	for i in $(SUBDIRS); do $(MAKE) -C $$i runtime-tests; done

.PHONY: force
force :;
