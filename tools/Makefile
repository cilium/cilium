# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

SUBDIRS := alignchecker mount

.PHONY: all $(SUBDIRS) clean install

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done

install:
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

.PHONY: force
force :;
