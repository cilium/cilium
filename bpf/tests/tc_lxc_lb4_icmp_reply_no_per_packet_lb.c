// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Prevent automatic ENABLE_PER_PACKET_LB definition in bpf_lxc.c */
#define ENABLE_SOCKET_LB_FULL
#undef ENABLE_SOCKET_LB_HOST_ONLY  
#undef ENABLE_L7_LB
#undef ENABLE_SCTP
#undef ENABLE_CLUSTER_AWARE_ADDRESSING
#undef ENABLE_PER_PACKET_LB

#define POD_IP		v4_pod_one
#define CLUSTERIP_IP	v4_svc_two
#define SERVICE_PORT	tcp_svc_one
#define BACKEND_IP	v4_pod_two
#define BACKEND_PORT	__bpf_htons(8080)
#define ICMP_ID		__bpf_htons(0x1234)

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

/* Test that ClusterIP replies to ICMP echo when per-packet LB is disabled */
PKTGEN("tc", "tc_lxc_icmp_echo_reply_no_per_packet_lb")
int lxc_icmp_echo_reply_no_per_packet_lb_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *icmphdr;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)pod_mac, (__u8 *)node_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = POD_IP;
	l3->daddr = CLUSTERIP_IP;

	/* Push ICMP header */
	icmphdr = pktgen__push_icmphdr(&builder);
	if (!icmphdr)
		return TEST_ERROR;

	icmphdr->type = ICMP_ECHO;
	icmphdr->code = 0;
	icmphdr->un.echo.id = ICMP_ID;
	icmphdr->un.echo.sequence = __bpf_htons(1);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lxc_icmp_echo_reply_no_per_packet_lb")
int lxc_icmp_echo_reply_no_per_packet_lb_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Create a ClusterIP service and manually add wildcard entry
	 * to test our non-per-packet LB datapath ICMP handling code
	 */
	lb_v4_add_service(CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, revnat_id);
	
	/* Manually create the wildcard entry that our datapath code should find */
	lb_v4_add_service(CLUSTERIP_IP, 0, IPPROTO_ANY, 0, revnat_id);

	/* Add a backend for the service */
	lb_v4_add_backend(CLUSTERIP_IP, SERVICE_PORT, 1, 1, BACKEND_IP, 
			  BACKEND_PORT, IPPROTO_TCP, 0);

	/* Configure IPCache entries */
	ipcache_v4_add_entry(POD_IP, 0, 112233, 0, 0);
	ipcache_v4_add_entry(CLUSTERIP_IP, 0, WORLD_IPV4_ID, 0, 0);
	ipcache_v4_add_entry(BACKEND_IP, 0, 112244, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_lxc_icmp_echo_reply_no_per_packet_lb")
int lxc_icmp_echo_reply_no_per_packet_lb_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct icmphdr *icmphdr;

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

	assert(l2->h_proto == bpf_htons(ETH_P_IP));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->protocol == IPPROTO_ICMP);

	icmphdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if ((void *)icmphdr + sizeof(struct icmphdr) > data_end)
		test_fatal("icmphdr out of bounds");

	/* Verify this is an ICMP echo reply */
	test_log("ICMP type: %d", icmphdr->type);
	assert(icmphdr->type == ICMP_ECHOREPLY);

	/* Verify the ICMP ID is preserved */
	assert(icmphdr->un.echo.id == ICMP_ID);

	/* Verify IP addresses are swapped */
	assert(l3->saddr == CLUSTERIP_IP);
	assert(l3->daddr == POD_IP);

	/* Verify MAC addresses are swapped */
	assert(memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)pod_mac, ETH_ALEN) == 0);

	test_finish();
}