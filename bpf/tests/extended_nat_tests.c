// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4
#define ENABLE_MASQUERADE_IPV6
#define SECLABEL 1
#include <bpf/config/global.h>

#include "nodeport_defaults.h"

ASSIGN_CONFIG(__u16, nodeport_port_min_nat_ext, 1024)
ASSIGN_CONFIG(__u16, nodeport_port_max_nat_ext, 29999)

#include <lib/nat.h>
#include <lib/nodeport.h>

CHECK("tc", "extended_nat_port_range_test")
int test_extended_nat_port_range_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* is_port_in_nat_range covers both ranges and the gap between them */
	assert(is_port_in_nat_range(32768) == true);
	assert(is_port_in_nat_range(65535) == true);
	assert(is_port_in_nat_range(29999) == true);
	assert(is_port_in_nat_range(1024) == true);
	assert(is_port_in_nat_range(30000) == false);
	assert(is_port_in_nat_range(1000) == false);

	/* IPv4: snat skip logic respects the extended bounds */
	struct ipv4_nat_target target_v4 = {};
	struct ipv4_ct_tuple tuple_v4 = {};

	tuple_v4.sport = bpf_htons(1000);
	assert(snat_v4_nat_can_skip(&target_v4, &tuple_v4) == true);

	tuple_v4.sport = bpf_htons(32768);
	assert(snat_v4_nat_can_skip(&target_v4, &tuple_v4) == false);

	tuple_v4.sport = bpf_htons(1024);
	assert(snat_v4_nat_can_skip(&target_v4, &tuple_v4) == false);

	/* IPv4: traffic from a local endpoint is never skipped */
	target_v4.from_local_endpoint = true;
	tuple_v4.sport = bpf_htons(1000);
	assert(snat_v4_nat_can_skip(&target_v4, &tuple_v4) == false);

	/* IPv4: range selection always yields the primary or extended range */
	for (int i = 0; i < 10; i++) {
		target_v4.min_port = 0;
		target_v4.max_port = 0;
		select_nat_port_range_ipv4(&target_v4);
		assert((target_v4.min_port == 32768 && target_v4.max_port == 65535) ||
		       (target_v4.min_port == 1024 && target_v4.max_port == 29999));
	}

	/* IPv6: mirror the IPv4 skip coverage */
	struct ipv6_nat_target target_v6 = {};
	struct ipv6_ct_tuple tuple_v6 = {};

	tuple_v6.sport = bpf_htons(1000);
	assert(snat_v6_nat_can_skip(&target_v6, &tuple_v6) == true);

	tuple_v6.sport = bpf_htons(32768);
	assert(snat_v6_nat_can_skip(&target_v6, &tuple_v6) == false);

	tuple_v6.sport = bpf_htons(1024);
	assert(snat_v6_nat_can_skip(&target_v6, &tuple_v6) == false);

	target_v6.from_local_endpoint = true;
	tuple_v6.sport = bpf_htons(1000);
	assert(snat_v6_nat_can_skip(&target_v6, &tuple_v6) == false);

	/* IPv6: range selection always yields the primary or extended range */
	for (int i = 0; i < 10; i++) {
		target_v6.min_port = 0;
		target_v6.max_port = 0;
		select_nat_port_range_ipv6(&target_v6);
		assert((target_v6.min_port == 32768 && target_v6.max_port == 65535) ||
		       (target_v6.min_port == 1024 && target_v6.max_port == 29999));
	}

	/* swap_nat_port_range toggles between the primary and extended ranges */
	target_v4.min_port = NODEPORT_PORT_MIN_NAT;
	target_v4.max_port = NODEPORT_PORT_MAX_NAT;
	swap_nat_port_range_ipv4(&target_v4);
	assert(target_v4.min_port == 1024 && target_v4.max_port == 29999);
	swap_nat_port_range_ipv4(&target_v4);
	assert(target_v4.min_port == 32768 && target_v4.max_port == 65535);

	target_v6.min_port = NODEPORT_PORT_MIN_NAT;
	target_v6.max_port = NODEPORT_PORT_MAX_NAT;
	swap_nat_port_range_ipv6(&target_v6);
	assert(target_v6.min_port == 1024 && target_v6.max_port == 29999);
	swap_nat_port_range_ipv6(&target_v6);
	assert(target_v6.min_port == 32768 && target_v6.max_port == 65535);

	test_finish();
}
