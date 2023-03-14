// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>

#include "node_config.h"

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/maps.h"

CHECK("xdp", "ipv6")
int bpf_test(__maybe_unused struct xdp_md *ctx)
{
	test_init();

	union v6addr v6;

	TEST("test_ipv6_addr_clear_suffix", {
		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 128);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xffffffff);
		assert(bpf_ntohl(v6.p4) == 0xffffffff);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 127);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xffffffff);
		assert(bpf_ntohl(v6.p4) == 0xfffffffe);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 95);
		assert(bpf_ntohl(v6.p1) == 0xffffffff);
		assert(bpf_ntohl(v6.p2) == 0xffffffff);
		assert(bpf_ntohl(v6.p3) == 0xfffffffe);
		assert(bpf_ntohl(v6.p4) == 0x00000000);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, 1);
		assert(bpf_ntohl(v6.p1) == 0x80000000);
		assert(bpf_ntohl(v6.p2) == 0x00000000);
		assert(bpf_ntohl(v6.p3) == 0x00000000);
		assert(bpf_ntohl(v6.p4) == 0x00000000);

		memset(&v6, 0xff, sizeof(v6));
		ipv6_addr_clear_suffix(&v6, -1);
		assert(bpf_ntohl(v6.p1) == 0x00000000);
		assert(bpf_ntohl(v6.p2) == 0x00000000);
		assert(bpf_ntohl(v6.p3) == 0x00000000);
		assert(bpf_ntohl(v6.p4) == 0x00000000);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
