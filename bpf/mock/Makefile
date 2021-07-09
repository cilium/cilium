# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2021 Authors of Cilium

# After unpacking CMock, you will find cmock.rb in the 'lib' directory.
# Please specify the path before making mock targets.
CMOCK ?= cmock.rb

check_helper_headers:
	# Check if helpers.h, helpers_skb.h and helpers_xdp.h are up to date.
	# Generate temp headers from lib/helpers.h, lib/helpers_skb.h and lib/helpers_xdp.h.
	# Compare them to the headers within the current directory.
	# The temp headers are removed after finishing.
	sed -f helpers.sed ../include/bpf/helpers.h > helpers_temp.h;
	sed -f helpers_skb.sed ../include/bpf/helpers_skb.h > helpers_skb_temp.h;
	sed -f helpers_xdp.sed ../include/bpf/helpers_xdp.h > helpers_xdp_temp.h;
	if cmp helpers_temp.h helpers.h; \
	then \
		echo mock/helpers.h is up to date!; \
	else \
		echo mock/helpers.h is out of date!; \
		rm helpers_temp.h helpers_skb_temp.h helpers_xdp_temp.h; \
		exit 1; \
	fi; \
	if cmp helpers_skb_temp.h helpers_skb.h; \
	then \
		echo mock/helpers_skb.h is up to date!; \
	else \
		echo mock/helpers_skb.h is out of date!; \
		rm helpers_temp.h helpers_skb_temp.h helpers_xdp_temp.h; \
		exit 1; \
	fi; \
	if cmp helpers_xdp_temp.h helpers_xdp_temp.h; \
	then \
		echo mock/helpers_xdp.h is up to date!; \
	else \
		echo mock/helpers_xdp.h is out of date!; \
		rm helpers_temp.h helpers_skb_temp.h helpers_xdp_temp.h; \
		exit 1; \
	fi; \
	rm helpers_temp.h helpers_skb_temp.h helpers_xdp_temp.h;
generate_helper_headers:
	# Auto-generate helpers.h, helpers_skb.h, and helpers_xdp.h.
	# Take contents from bpf/helpers.h, bpf/helpers_skb.h and bpf/helpers_xdp.h.
	# Prune to be ready to mock and save to the current directory.
	sed -f helpers.sed ../include/bpf/helpers.h > helpers.h; \
	sed -f helpers_skb.sed ../include/bpf/helpers_skb.h > helpers_skb.h; \
	sed -f helpers_xdp.sed ../include/bpf/helpers_xdp.h > helpers_xdp.h;
mock_helpers:
	# Generate mock libraries for helpers.h, helpers_skb.h and helpers_xdp.h with CMock.
	# Unfold folder mocks to the current directory.
	ruby $(CMOCK) -obpf.yaml helpers.h; \
	ruby $(CMOCK) -obpf.yaml helpers_skb.h; \
	ruby $(CMOCK) -obpf.yaml helpers_xdp.h; \
	mv mocks/* ./; \
	rmdir mocks;
mock_customized:
	# Take the name of the header to be mocked.
	# Generate the corresponding mock library.
	ruby $(CMOCK) -obpf.yaml $(filename); \
	mv mocks/* ./; \
	rmdir mocks;
