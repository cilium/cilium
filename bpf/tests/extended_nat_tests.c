// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1
#define SECLABEL 1
#define SECLABEL_IPV4 SECLABEL
#define SECLABEL_IPV6 SECLABEL
#include <bpf/config/global.h>

#include "nodeport_defaults.h"

ASSIGN_CONFIG(__u16, nodeport_port_min_nat_ext, 1024)
ASSIGN_CONFIG(__u16, nodeport_port_max_nat_ext, 29999)
ASSIGN_CONFIG(bool, enable_masquerade_ipv6, true)
ASSIGN_CONFIG(bool, enable_masquerade_ipv4, true)

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

#define HOST_IP		bpf_htonl(0x0A000001)	/* 10.0.0.1, also the SNAT address */
#define POD_IP		bpf_htonl(0x0A100001)	/* 10.16.0.1 */
#define REMOTE_IP	bpf_htonl(0x0A000002)	/* 10.0.0.2 */

/* A host flow (source address == SNAT address) is only tracked to reserve its
 * port. It must keep a port from either NAT range, whichever sub-range was
 * picked for the packet, and move only on a genuine collision.
 *
 *   node: HOST_IP 10.0.0.1 (also the SNAT address)
 *  +-------------------------------------------------+
 *  |  host netns                pod POD_IP 10.16.0.1 |
 *  |  :10250 (server reply)     :20000               |
 *  |  :45000 (client)           :10251               |
 *  |  :20000 (client)             |                  |
 *  |     |                        |                  |
 *  |     +-----------+------------+                  |
 *  |                 v                               |
 *  |  snat_v4_new_mapping(), picked range:           |
 *  |    primary  [32768, 65535] or                   |
 *  |    extended [1024, 29999]                       |
 *  +-----------------+-------------------------------+
 *                    |  TCP, src 10.0.0.1:<to_sport>
 *                    v
 *        REMOTE_IP 10.0.0.2:45678
 *
 *  step  source           picked    to_sport
 *  1     10.0.0.1:10250   primary   10250 (host, kept)
 *  2     10.0.0.1:45000   extended  45000 (host, kept)
 *  3     10.16.0.1:20000  extended  20000 (pod, kept: sent as 10.0.0.1:20000)
 *  4     10.0.0.1:20000   primary   random primary port: 3 already uses
 *                                   10.0.0.1:20000 -> 10.0.0.2:45678
 *  5     10.16.0.1:10251  primary   random primary port (pod, out of range)
 */
CHECK("tc", "extended_nat_host_flow_keeps_port_v4")
int test_extended_nat_host_flow_keeps_port_v4(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_nat_target target = {
		.addr = HOST_IP,
	};
	struct ipv4_ct_tuple host = {
		.nexthdr = IPPROTO_TCP,
		.saddr = HOST_IP,
		.daddr = REMOTE_IP,
		.dport = bpf_htons(45678),
		.flags = NAT_DIR_EGRESS,
	};
	struct ipv4_ct_tuple pod;
	struct ipv4_nat_entry state;
	void *map;
	__u16 port;

	test_init();

	map = get_cluster_snat_map_v4(target.cluster_id);
	assert(map);

	/* Host server reply from an extended-range port (e.g. kubelet 10250)
	 * while the primary range was picked for this packet.
	 */
	target.min_port = NODEPORT_PORT_MIN_NAT;
	target.max_port = NODEPORT_PORT_MAX_NAT;
	host.sport = bpf_htons(10250);
	assert(!snat_v4_new_mapping(ctx, map, &host, &state, &target, false, NULL));
	assert(state.to_saddr == HOST_IP);
	assert(state.to_sport == bpf_htons(10250));

	/* Host client with a primary-range port while the extended range was
	 * picked for this packet.
	 */
	target.min_port = CONFIG(nodeport_port_min_nat_ext);
	target.max_port = CONFIG(nodeport_port_max_nat_ext);
	host.sport = bpf_htons(45000);
	assert(!snat_v4_new_mapping(ctx, map, &host, &state, &target, false, NULL));
	assert(state.to_sport == bpf_htons(45000));

	/* A genuine collision still moves a host flow: a pod flow already holds
	 * HOST_IP:20000 toward the same remote, so the host flow gets a port
	 * from the picked sub-range instead.
	 */
	pod = host;
	pod.saddr = POD_IP;
	pod.sport = bpf_htons(20000);
	assert(!snat_v4_new_mapping(ctx, map, &pod, &state, &target, false, NULL));
	assert(state.to_sport == bpf_htons(20000));

	target.min_port = NODEPORT_PORT_MIN_NAT;
	target.max_port = NODEPORT_PORT_MAX_NAT;
	host.sport = bpf_htons(20000);
	assert(!snat_v4_new_mapping(ctx, map, &host, &state, &target, false, NULL));
	port = bpf_ntohs(state.to_sport);
	assert(port >= NODEPORT_PORT_MIN_NAT && port <= NODEPORT_PORT_MAX_NAT);

	/* Pod flows still keep their port only inside the picked sub-range. */
	pod.sport = bpf_htons(10251);
	assert(!snat_v4_new_mapping(ctx, map, &pod, &state, &target, false, NULL));
	port = bpf_ntohs(state.to_sport);
	assert(port >= NODEPORT_PORT_MIN_NAT && port <= NODEPORT_PORT_MAX_NAT);

	test_finish();
}

CHECK("tc", "extended_nat_host_flow_keeps_port_v6")
int test_extended_nat_host_flow_keeps_port_v6(__maybe_unused struct __ctx_buff *ctx)
{
	union v6addr host_ip = { .d1 = 0xfd00, .d2 = 0x1 };
	union v6addr pod_ip = { .d1 = 0xfd00, .d2 = 0x2 };
	union v6addr remote_ip = { .d1 = 0xfd00, .d2 = 0x3 };
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	struct ipv6_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
		.dport = bpf_htons(45678),
		.flags = NAT_DIR_EGRESS,
	};
	struct ipv6_nat_entry state;
	__u16 port;

	test_init();

	target.addr = host_ip;
	tuple.saddr = host_ip;
	tuple.daddr = remote_ip;

	/* Host server reply from an extended-range port while the primary
	 * range was picked for this packet.
	 */
	tuple.sport = bpf_htons(10250);
	assert(!snat_v6_new_mapping(ctx, &tuple, &state, &target, false, NULL));
	assert(state.to_sport == bpf_htons(10250));

	/* A pod flow with the same port gets one from the picked sub-range. */
	tuple.saddr = pod_ip;
	assert(!snat_v6_new_mapping(ctx, &tuple, &state, &target, false, NULL));
	port = bpf_ntohs(state.to_sport);
	assert(port >= NODEPORT_PORT_MIN_NAT && port <= NODEPORT_PORT_MAX_NAT);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
