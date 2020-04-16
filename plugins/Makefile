# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

SUBDIRS := cilium-docker cilium-cni

.PHONY: all $(SUBDIRS) clean install

all: $(SUBDIRS)

$(SUBDIRS): force
	@$(MAKE) $(SUBMAKEOPTS) -C $@ all

clean:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

install:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done

.PHONY: force
force :;
