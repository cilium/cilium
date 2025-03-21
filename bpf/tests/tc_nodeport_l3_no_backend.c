// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ETH_HLEN			0

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define SERVICE_NO_BACKEND_RESPONSE	1
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1

#define DISABLE_LOOPBACK_LB		1

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define CLIENT_IPV6		v6_pod_one
#define FRONTEND_IPV6		v6_pod_two
#define BACKEND_IPV6		v6_node_two

#include <bpf_host.c>

ASSIGN_CONFIG(__u32, nat_ipv4_masquerade, FRONTEND_IP)
/* aka FRONTEND_IP aka v6_pod_two: */
DEFINE_IPV6(nat_ipv6_masquerade,
	    0xfd, 0x04, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0x02);

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that a SVC without backends returns a TCP RST or ICMP error */
PKTGEN("tc", "tc_nodeport_l3_ipv4_no_backend")
int nodeport_l3_ipv4_no_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */
	l4 = pktgen__push_ipv4_tcp_packet(&builder, NULL, NULL,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_l3_ipv4_no_backend")
int nodeport_l3_ipv4_no_backend_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

static __always_inline int
ipv4_validate_icmp_reply(const struct __ctx_buff *ctx, __u32 retval)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == retval);

	l3 = data + sizeof(__u32);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 header out of bounds");

	assert(l3->saddr == FRONTEND_IP);
	assert(l3->daddr == CLIENT_IP);

	assert(l3->ihl == 5);
	assert(l3->version == 4);
	assert(l3->tos == 0);
	assert(l3->ttl == 64);
	assert(l3->protocol == IPPROTO_ICMP);

	if (csum_fold(csum_diff(NULL, 0, l3, sizeof(*l3), 0)))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	l4 = data + sizeof(__u32) + sizeof(struct iphdr);
	if ((void *) l4 + sizeof(struct icmphdr) > data_end)
		test_fatal("l4 header out of bounds");

	assert(l4->type == ICMP_DEST_UNREACH);
	assert(l4->code == ICMP_PORT_UNREACH);

	/* reference checksum is calculated with wireshark by dumping the
	 * context with the runner option and importing the packet into
	 * wireshark
	 */
	assert(l4->checksum == bpf_htons(0x2c3f));

	test_finish();
}

CHECK("tc", "tc_nodeport_l3_ipv4_no_backend")
int nodeport_l3_ipv4_no_backend_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ipv4_validate_icmp_reply(ctx, CTX_ACT_REDIRECT);
}

/* Test that the ICMP error message leaves the node */
PKTGEN("tc", "tc_nodeport_l3_ipv4_no_backend2_reply")
int nodeport_l3_ipv4_no_backend2_reply_pktgen(struct __ctx_buff *ctx)
{
	/* Start with the initial request, and let SETUP() below rebuild it. */
	return nodeport_l3_ipv4_no_backend_pktgen(ctx);
}

SETUP("tc", "tc_nodeport_l3_ipv4_no_backend2_reply")
int nodeport_l3_ipv4_no_backend2_reply_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, iphdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	if (__tail_no_service_ipv4(ctx))
		return TEST_ERROR;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_l3_ipv4_no_backend2_reply")
int nodeport_l3_ipv4_no_backend2_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ipv4_validate_icmp_reply(ctx, CTX_ACT_OK);
}

/* Test that a SVC without backends returns a TCP RST or ICMP error */
PKTGEN("tc", "tc_nodeport_l3_ipv6_no_backend")
int nodeport_l3_ipv6_no_backend_pktgen(struct __ctx_buff *ctx)
{
struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* We are building an L3 skb which doesn't have L2 header, so in theory
	 * we need to skip L2 header and set ctx->protocol = bpf_ntohs(ETH_P_IP),
	 * but bpf verifier doesn't allow us to do so, and kernel also doesn't
	 * handle an L3 skb properly (see https://elixir.bootlin.com/linux/v6.2.1/source/net/bpf/test_run.c#L1156).
	 * Therefore we workaround the issue by pushing L2 header in the PKTGEN
	 * and stripping it in the SETUP.
	 */
	l4 = pktgen__push_ipv6_tcp_packet(&builder, NULL, NULL,
					  (__u8 *)CLIENT_IPV6,
					  (__u8 *)FRONTEND_IPV6,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_l3_ipv6_no_backend")
int nodeport_l3_ipv6_no_backend_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
	__u16 revnat_id = 1;

	union v6addr frontend_ip = {};

	memcpy(frontend_ip.addr, (void *)FRONTEND_IPV6, 16);

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);

	union v6addr backend_ip = {};

	memcpy(backend_ip.addr, (void *)BACKEND_IPV6, 16);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, ipv6hdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

static __always_inline int
ipv6_validate_icmp_reply(const struct __ctx_buff *ctx, __u32 retval)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	struct ratelimit_value *value;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == retval);

	l3 = data + sizeof(__u32);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 header out of bounds");

	assert(!memcmp(&l3->saddr, (const void *)FRONTEND_IPV6, sizeof(l3->saddr)));
	assert(!memcmp(&l3->daddr, (const void *)CLIENT_IPV6, sizeof(l3->daddr)));

	assert(l3->hop_limit == 64);
	assert(l3->version == 6);
	assert(l3->nexthdr == IPPROTO_ICMPV6);

	l4 = data + sizeof(__u32) + sizeof(struct ipv6hdr);
	if ((void *) l4 + sizeof(struct icmp6hdr) > data_end)
		test_fatal("l4 header out of bounds");

	assert(l4->icmp6_type == ICMPV6_DEST_UNREACH);
	assert(l4->icmp6_code == ICMPV6_PORT_UNREACH);

	struct ratelimit_key key = {
		.usage = RATELIMIT_USAGE_ICMPV6,
		.key = {
			.icmpv6 = {
				.netdev_idx = 1,
			},
		},
	};

	value = map_lookup_elem(&RATELIMIT_MAP, &key);
	if (!value)
		test_fatal("ratelimit map lookup failed");

	assert(value->tokens > 0);

	test_finish();
}

CHECK("tc", "tc_nodeport_l3_ipv6_no_backend")
int nodeport_l3_ipv6_no_backend_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ipv6_validate_icmp_reply(ctx, CTX_ACT_REDIRECT);
}

/* Test that the ICMP error message leaves the node */
PKTGEN("tc", "tc_nodeport_l3_ipv6_no_backend2_reply")
int nodeport_l3_ipv6_no_backend2_reply_pktgen(struct __ctx_buff *ctx)
{
	/* Start with the initial request, and let SETUP() below rebuild it. */
	return nodeport_l3_ipv6_no_backend_pktgen(ctx);
}

SETUP("tc", "tc_nodeport_l3_ipv6_no_backend2_reply")
int nodeport_l3_ipv6_no_backend2_reply_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	/* As commented in PKTGEN, now we strip the L2 header. Bpf helper
	 * skb_adjust_room will use L2 header to overwrite L3 header, so we play
	 * a trick to memcpy(ethhdr, ipv6hdr, ETH_HLEN) ahead of skb_adjust_room
	 * so as to guarantee L3 header keeps intact.
	 */
	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);

	if (__tail_no_service_ipv6(ctx))
		return TEST_ERROR;

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_l3_ipv6_no_backend2_reply")
int nodeport_l3_ipv6_no_backend2_reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return ipv6_validate_icmp_reply(ctx, CTX_ACT_OK);
}
