/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ATTACHMENT_XDP
# define ATTACH "xdp"
# include <bpf/ctx/xdp.h>
#else
# define ATTACH "tc"
# include <bpf/ctx/skb.h>
#endif

#include "common.h"

#include "pktgen.h"
#include "scapy.h"

#define BACKEND_EP_ID			127
#define NATIVE_IFINDEX			22

#define fib_lookup mock_fib_lookup
long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = NATIVE_IFINDEX;

	return 0;
}

#ifdef ATTACHMENT_XDP
# include "lib/bpf_xdp.h"
# define netdev_receive_packet	xdp_receive_packet
#else
# define CHECK_REPLY	1
# include "lib/bpf_host.h"
#endif

ASSIGN_CONFIG(__u32, interface_ifindex, NATIVE_IFINDEX);

#include "lib/endpoint.h"

const __u8 kpr_v4_dsr_remote_node_syn[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn_post_option_xdp)
};

const __u8 kpr_v4_dsr_remote_node_synack[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack_post_option_xdp)
};

const __u8 kpr_v4_dsr_remote_node_data_option[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_remote_node_data_option)
};

const __u8 kpr_v4_dsr_remote_node_reply[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_remote_node_reply)
};

const __u8 kpr_v4_dsr_remote_node_reply_post[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_remote_node_reply_post)
};

const __u8 kpr_v4_dsr_remote_node_reply2_post[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_remote_node_reply2_post)
};

const __u8 kpr_v6_dsr_remote_node_syn[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn_post_option_xdp)
};

const __u8 kpr_v6_dsr_remote_node_synack[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack_post_option_xdp)
};

const __u8 kpr_v6_dsr_remote_node_data_option[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_remote_node_data_option)
};

const __u8 kpr_v6_dsr_remote_node_reply[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_remote_node_reply)
};

const __u8 kpr_v6_dsr_remote_node_reply_post[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_remote_node_reply_post)
};

const __u8 kpr_v6_dsr_remote_node_reply2_post[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_remote_node_reply2_post)
};

#ifdef ENABLE_IPV4
/* Backend node receives SYN with DSR-info. Reply can be RevDNATed.
 * Then we receive a second packet without DSR-info. Replies can still be
 * RevDNATed.
 */
PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_1syn")
int kpr_v4_dsr_remote_node_1syn_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_syn,
			sizeof(kpr_v4_dsr_remote_node_syn));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_1syn")
int kpr_v4_dsr_remote_node_1syn_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(v4_pod_one, 123, BACKEND_EP_ID, 0, 0, 0, NULL, NULL);

	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_1syn")
int kpr_v4_dsr_remote_node_1syn_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_syn",
			   "Ether", ctx, pkt_offset,
			   kpr_v4_dsr_remote_node_syn,
			   sizeof(kpr_v4_dsr_remote_node_syn));

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_pod_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_dst_one;
	tuple.dport = tcp_src_one;
	ipv4_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr_internal)
		test_fatal("CT entry doesn't have the .dsr_internal flag set");
	if (ct_entry->nat_addr.p4 != v4_svc_one)
		test_fatal("CT entry doesn't have the RevDNAT addr set");
	if (ct_entry->nat_port != tcp_svc_one)
		test_fatal("CT entry doesn't have the RevDNAT port set");

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_2reply")
int kpr_v4_dsr_remote_node_2reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_reply,
			sizeof(kpr_v4_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_2reply")
int kpr_v4_dsr_remote_node_2reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_2reply")
int kpr_v4_dsr_remote_node_2reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_reply_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_remote_node_reply_post,
			   sizeof(kpr_v4_dsr_remote_node_reply_post));

	test_finish();
}
#endif

PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_3synack")
int kpr_v4_dsr_remote_node_3synack_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_synack,
			sizeof(kpr_v4_dsr_remote_node_synack));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_3synack")
int kpr_v4_dsr_remote_node_3synack_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_3synack")
int kpr_v4_dsr_remote_node_3synack_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_synack",
			   "Ether", ctx, pkt_offset,
			   kpr_v4_dsr_remote_node_synack,
			   sizeof(kpr_v4_dsr_remote_node_synack));

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_4reply")
int kpr_v4_dsr_remote_node_4reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_reply,
			sizeof(kpr_v4_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_4reply")
int kpr_v4_dsr_remote_node_4reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_4reply")
int kpr_v4_dsr_remote_node_4reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_reply_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_remote_node_reply_post,
			   sizeof(kpr_v4_dsr_remote_node_reply_post));

	test_finish();
}
#endif

/* Now receive a non-SYN with different DSR-info.
 * The RevDNAT follows accordingly.
 */
PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_5data_dsr_info")
int kpr_v4_dsr_remote_node_5data_dsr_info_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_data_option,
			sizeof(kpr_v4_dsr_remote_node_data_option));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_5data_dsr_info")
int kpr_v4_dsr_remote_node_5data_dsr_info_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_5data_dsr_info")
int kpr_v4_dsr_remote_node_5data_dsr_info_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_data_option",
			   "Ether", ctx, pkt_offset,
			   kpr_v4_dsr_remote_node_data_option,
			   sizeof(kpr_v4_dsr_remote_node_data_option));

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_pod_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_dst_one;
	tuple.dport = tcp_src_one;
	ipv4_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr_internal)
		test_fatal("CT entry doesn't have the .dsr_internal flag set");
	if (ct_entry->nat_addr.p4 != v4_svc_one)
		test_fatal("CT entry doesn't have the RevDNAT addr set");
	if (ct_entry->nat_port != tcp_svc_two)
		test_fatal("CT entry doesn't have the RevDNAT port set");

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v4_dsr_remote_node_6reply")
int kpr_v4_dsr_remote_node_6reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_remote_node_reply,
			sizeof(kpr_v4_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v4_dsr_remote_node_6reply")
int kpr_v4_dsr_remote_node_6reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v4_dsr_remote_node_6reply")
int kpr_v4_dsr_remote_node_6reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_remote_node_reply2_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_remote_node_reply2_post,
			   sizeof(kpr_v4_dsr_remote_node_reply2_post));

	test_finish();
}
#endif
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_1syn")
int kpr_v6_dsr_remote_node_1syn_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_syn,
			sizeof(kpr_v6_dsr_remote_node_syn));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_1syn")
int kpr_v6_dsr_remote_node_1syn_setup(struct __ctx_buff *ctx)
{
	union v6addr backend_ip = { v6_pod_one_addr };

	endpoint_v6_add_entry(&backend_ip, 123, BACKEND_EP_ID, 0, 0, NULL, NULL);

	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_1syn")
int kpr_v6_dsr_remote_node_1syn_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_syn",
			   "Ether", ctx, pkt_offset,
			   kpr_v6_dsr_remote_node_syn,
			   sizeof(kpr_v6_dsr_remote_node_syn));

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr backend_ip = { v6_pod_one_addr };
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &backend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_dst_one;
	tuple.dport = tcp_src_one;
	ipv6_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr_internal)
		test_fatal("CT entry doesn't have the .dsr_internal flag set");
	if (!ipv6_addr_equals(&ct_entry->nat_addr, &frontend_ip))
		test_fatal("CT entry doesn't have the RevDNAT addr set");
	if (ct_entry->nat_port != tcp_svc_one)
		test_fatal("CT entry doesn't have the RevDNAT port set");

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_2reply")
int kpr_v6_dsr_remote_node_2reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_reply,
			sizeof(kpr_v6_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_2reply")
int kpr_v6_dsr_remote_node_2reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_2reply")
int kpr_v6_dsr_remote_node_2reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_reply_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_remote_node_reply_post,
			   sizeof(kpr_v6_dsr_remote_node_reply_post));

	test_finish();
}
#endif

PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_3synack")
int kpr_v6_dsr_remote_node_3synack_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_synack,
			sizeof(kpr_v6_dsr_remote_node_synack));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_3synack")
int kpr_v6_dsr_remote_node_3synack_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_3synack")
int kpr_v6_dsr_remote_node_3synack_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_synack",
			   "Ether", ctx, pkt_offset,
			   kpr_v6_dsr_remote_node_synack,
			   sizeof(kpr_v6_dsr_remote_node_synack));

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_4reply")
int kpr_v6_dsr_remote_node_4reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_reply,
			sizeof(kpr_v6_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_4reply")
int kpr_v6_dsr_remote_node_4reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_4reply")
int kpr_v6_dsr_remote_node_4reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_reply_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_remote_node_reply_post,
			   sizeof(kpr_v6_dsr_remote_node_reply_post));

	test_finish();
}
#endif

PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_5data_dsr_info")
int kpr_v6_dsr_remote_node_5data_dsr_info_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_data_option,
			sizeof(kpr_v6_dsr_remote_node_data_option));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_5data_dsr_info")
int kpr_v6_dsr_remote_node_5data_dsr_info_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_5data_dsr_info")
int kpr_v6_dsr_remote_node_5data_dsr_info_check(__maybe_unused const struct __ctx_buff *ctx)
{
	__u32 pkt_offset = sizeof(__u32);
	void *data, *data_end;
	__u32 *status_code;

#ifdef ATTACHMENT_XDP
	pkt_offset += sizeof(__u32);
#endif

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_data_option",
			   "Ether", ctx, pkt_offset,
			   kpr_v6_dsr_remote_node_data_option,
			   sizeof(kpr_v6_dsr_remote_node_data_option));

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr backend_ip = { v6_pod_one_addr };
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_IN;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &backend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_dst_one;
	tuple.dport = tcp_src_one;
	ipv6_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr_internal)
		test_fatal("CT entry doesn't have the .dsr_internal flag set");
	if (!ipv6_addr_equals(&ct_entry->nat_addr, &frontend_ip))
		test_fatal("CT entry doesn't have the RevDNAT addr set");
	if (ct_entry->nat_port != tcp_svc_two)
		test_fatal("CT entry doesn't have the RevDNAT port set");

	test_finish();
}

#ifdef CHECK_REPLY
PKTGEN(ATTACH, "kpr_v6_dsr_remote_node_6reply")
int kpr_v6_dsr_remote_node_6reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_remote_node_reply,
			sizeof(kpr_v6_dsr_remote_node_reply));

	pktgen__finish(&builder);

	return 0;
}

SETUP(ATTACH, "kpr_v6_dsr_remote_node_6reply")
int kpr_v6_dsr_remote_node_6reply_setup(struct __ctx_buff *ctx)
{
	return netdev_send_packet(ctx);
}

CHECK(ATTACH, "kpr_v6_dsr_remote_node_6reply")
int kpr_v6_dsr_remote_node_6reply_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_remote_node_reply2_post",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_remote_node_reply2_post,
			   sizeof(kpr_v6_dsr_remote_node_reply2_post));

	test_finish();
}
#endif
#endif /* ENABLE_IPV6 */
