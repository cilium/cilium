// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

PKTGEN("tc", "netdev_wireguard_to_remote_node_ipv4")
int netdev_wireguard_to_remote_node_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)remote_node_mac,
					  NODE_IP, REMOTE_NODE_IP,
					  WG_PORT, WG_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_wireguard_to_remote_node_ipv4")
int netdev_wireguard_to_remote_node_ipv4_setup(struct __ctx_buff *ctx)
{
	ctx->mark = MARK_MAGIC_WG_ENCRYPTED;

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_wireguard_to_remote_node_ipv4")
int netdev_wireguard_to_remote_node_ipv4_check(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct udphdr *l4;

	test_init();

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != WG_PORT)
		test_fatal("bad src port");

	if (l4->dest != WG_PORT)
		test_fatal("bad dst port");

	test_finish();
}
