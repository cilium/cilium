# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../Makefile.defs

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:f2d25e741d2e754e25fda8ebb0f65d099d6a7a49@sha256:020ddc0f54cd797f0b3e7f8b3dba0b3aedc76911d40076aa042b14fda4e3bee0

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
