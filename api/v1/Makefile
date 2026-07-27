# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../Makefile.defs

VOLUME ?= $(CURDIR)
CONTAINER_IMAGE ?= $(CILIUM_BUILDER_IMAGE)

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(VOLUME):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CONTAINER_IMAGE) \
		make -C /src -f Makefile.protoc
