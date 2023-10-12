# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../../Makefile.defs

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:ebdc0986083d662ac4f07e1d91cd409108a1c212@sha256:d5380184c4797dd739619eb48997e6d531c2de314699bc2a1b13dca72343b72a

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
