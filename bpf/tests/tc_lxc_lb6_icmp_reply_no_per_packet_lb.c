// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Prevent automatic ENABLE_PER_PACKET_LB definition in bpf_lxc.c */
#define ENABLE_SOCKET_LB_FULL
#undef ENABLE_SOCKET_LB_HOST_ONLY  
#undef ENABLE_L7_LB
#undef ENABLE_SCTP
#undef ENABLE_CLUSTER_AWARE_ADDRESSING
#undef ENABLE_PER_PACKET_LB

#define POD_IP		v6_pod_one
#define CLUSTERIP_IP	v6_node_one
#define SERVICE_PORT	tcp_svc_one
#define BACKEND_IP	v6_pod_two
#define BACKEND_PORT	__bpf_htons(8080)
#define ICMP_ID		__bpf_htons(0x5678)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *node_mac = mac_two;

#include <bpf_lxc.c>

/* Force disable per-packet LB after bpf_lxc.c includes */
#ifdef ENABLE_PER_PACKET_LB
#undef ENABLE_PER_PACKET_LB
#endif

/* Verify that per-packet LB is now disabled */
#ifdef ENABLE_PER_PACKET_LB
#error "Test compilation failed: ENABLE_PER_PACKET_LB should be undefined"
#endif

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_CONTAINER	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

/* Test that ClusterIP replies to ICMPv6 echo when per-packet LB is disabled */
PKTGEN("tc", "tc_lxc_icmpv6_echo_reply_no_per_packet_lb")
int lxc_icmpv6_echo_reply_no_per_packet_lb_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6hdr;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

	/* Push IPv6 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	memcpy(&l3->saddr, (__u8 *)&POD_IP, 16);
	memcpy(&l3->daddr, (__u8 *)&CLUSTERIP_IP, 16);

	/* Push ICMPv6 header */
	icmp6hdr = pktgen__push_icmp6hdr(&builder);
	if (!icmp6hdr)
		return TEST_ERROR;

	icmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6hdr->icmp6_code = 0;
	icmp6hdr->icmp6_identifier = ICMP_ID;
	icmp6hdr->icmp6_sequence = __bpf_htons(1);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_icmpv6_echo_reply_no_per_packet_lb")
int lxc_icmpv6_echo_reply_no_per_packet_lb_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Create a ClusterIP service and manually add wildcard entry
	 * to test our non-per-packet LB datapath ICMPv6 handling code
	 */
	lb_v6_add_service((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, revnat_id);
	
	/* Manually create the wildcard entry that our datapath code should find */
	lb_v6_add_service((union v6addr *)&CLUSTERIP_IP, 0, IPPROTO_ANY, 0, revnat_id);

	/* Add a backend for the service */
	lb_v6_add_backend((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, 1, 1, 
			  (union v6addr *)&BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Configure IPCache entries */
	ipcache_v6_add_entry((union v6addr *)&POD_IP, 0, 112233, 0, 0);
	ipcache_v6_add_entry((union v6addr *)&CLUSTERIP_IP, 0, WORLD_IPV6_ID, 0, 0);
	ipcache_v6_add_entry((union v6addr *)&BACKEND_IP, 0, 112244, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_lxc_icmpv6_echo_reply_no_per_packet_lb")
int lxc_icmpv6_echo_reply_no_per_packet_lb_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp6hdr;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->nexthdr == IPPROTO_ICMPV6);

	icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp6hdr out of bounds");

	/* Verify this is an ICMPv6 echo reply */
	test_log("ICMPv6 type: %d", icmp6hdr->icmp6_type);
	assert(icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY);

	/* Verify the ICMP ID is preserved */
	assert(icmp6hdr->icmp6_identifier == ICMP_ID);

	/* Verify IPv6 addresses are swapped */
	assert(memcmp(&l3->saddr, (__u8 *)&CLUSTERIP_IP, 16) == 0);
	assert(memcmp(&l3->daddr, (__u8 *)&POD_IP, 16) == 0);

	/* Verify MAC addresses are swapped */
	assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);

	test_finish();
}

