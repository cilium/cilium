# Copyright Authors of Cilium
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

install-binary: install
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install-binary; done

install-bash-completion:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install-bash-completion; done

.PHONY: force
force :;
