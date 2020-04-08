include ../Makefile.defs

SUBDIRS = cilium-docker cilium-cni

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

clean:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

install:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

.PHONY: force
force :;
