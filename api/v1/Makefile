# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../Makefile.defs

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:772e4474a7f7e7ac6308a81e5a2ce26d88e6c103@sha256:3c6283dbe902ae747fcd42cbac5a85fa1394ccfe62aeb8f5b0d746c99f2c69dd

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
