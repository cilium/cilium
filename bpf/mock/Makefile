# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

include ../../Makefile.defs
include ../../Makefile.quiet

builder-image: Dockerfile
	$(ECHO_DOCKER)
	# Pre-pull FROM docker images due to Buildkit sometimes failing to pull them.
	grep "^FROM " $< | cut -d ' ' -f2 | xargs -n1 $(CONTAINER_ENGINE) pull
	$(QUIET)tar c Dockerfile \
	 | $(CONTAINER_ENGINE) build $(DOCKER_BUILD_FLAGS) --tag cilium/bpf-mock -

DOCKER_CTR_ROOT_DIR := /src
DOCKER_CTR := $(CONTAINER_ENGINE) container run --rm \
		--workdir $(DOCKER_CTR_ROOT_DIR)/mock \
		--volume $(CURDIR)/..:$(DOCKER_CTR_ROOT_DIR) \
		--user "$(shell id -u):$(shell id -g)"
DOCKER_RUN := $(DOCKER_CTR) cilium/bpf-mock

check_helper_headers: generate_helper_headers mock_helpers
	# Check if helpers.h, helpers_skb.h and helpers_xdp.h are up to date.
	# Generate temp headers from lib/helpers.h, lib/helpers_skb.h and lib/helpers_xdp.h.
	# Compare them to the headers within the current directory.
	# The temp headers are removed after finishing.
	$(QUIET)rm -r mocks

generate_helper_headers:
	# Auto-generate helpers.h, helpers_skb.h, and helpers_xdp.h.
	# Take contents from bpf/helpers.h, bpf/helpers_skb.h and bpf/helpers_xdp.h.
	# Prune to be ready to mock and save to the current directory.
	$(QUIET)mkdir -p mocks
	$(QUIET)sed -f helpers.sed ../include/bpf/helpers.h > mocks/helpers.h
	$(QUIET)sed -f helpers_skb.sed ../include/bpf/helpers_skb.h > mocks/helpers_skb.h
	$(QUIET)sed -f helpers_xdp.sed ../include/bpf/helpers_xdp.h > mocks/helpers_xdp.h

mock_helpers: builder-image
	# Generate mock libraries for helpers.h, helpers_skb.h and helpers_xdp.h with CMock.
	$(QUIET) $(DOCKER_RUN) ./mock_helpers.sh

mock_customized: builder-image
	# Take the name of the header to be mocked.
	# Generate the corresponding mock library.
	$(QUIET) $(DOCKER_RUN) ./mock_customized.sh $(filename)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -r -- mocks
