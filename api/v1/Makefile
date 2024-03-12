# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../Makefile.defs

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:819a4f1e57eaacb6aabfc6a1a39d11d4fd794a88@sha256:24781dc80f2be2d8fd66b0ce1405e1f117a3a0ef388758b1ede7831778e3a4f7

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
