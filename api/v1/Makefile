# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../Makefile.defs

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:c216208ed2de6f0e9bc43e6fe918f944ff6d98b8@sha256:fcdb9cfe9e4dcdbdba99d6b68bdfe1bf008f0f2196c3848f6a2b0d77cbd89b1a

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
