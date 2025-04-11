// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

PKTGEN("tc", "netdev_host_to_remote_pod_ipv4_udp")
int netdev_host_to_remote_pod_ipv4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)remote_node_mac,
					  NODE_IP, REMOTE_POD_IP,
					  NODE_PORT, REMOTE_POD_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_host_to_remote_pod_ipv4_udp")
int netdev_host_to_remote_pod_ipv4_udp_setup(struct __ctx_buff *ctx)
{
	ctx->mark = MARK_MAGIC_HOST;

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_host_to_remote_pod_ipv4_udp")
int netdev_host_to_remote_pod_ipv4_udp_check(struct __ctx_buff *ctx)
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

#if defined(ENABLE_WIREGUARD) && defined(ENABLE_NODE_ENCRYPTION)
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == HOST_ID);

	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		assert(settings->redirect_ifindex == WG_IFINDEX);
#else
	assert(*status_code == CTX_ACT_OK);
#endif

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IPd");

	if (l3->daddr != REMOTE_POD_IP)
		test_fatal("bad dest IP");

	if (l4->source != NODE_PORT)
		test_fatal("bad src port");

	if (l4->dest != REMOTE_POD_PORT)
		test_fatal("bad dst port");

	test_finish();
}

/***********************************************************************/

PKTGEN("tc", "netdev_host_to_remote_node_ipv4_udp")
int netdev_host_to_remote_node_ipv4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)remote_node_mac,
					  NODE_IP, REMOTE_NODE_IP,
					  NODE_PORT, REMOTE_NODE_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_host_to_remote_node_ipv4_udp")
int netdev_host_to_remote_node_ipv4_udp_setup(struct __ctx_buff *ctx)
{
	ctx->mark = MARK_MAGIC_HOST;

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_host_to_remote_node_ipv4_udp")
int netdev_host_to_remote_node_ipv4_udp_check(struct __ctx_buff *ctx)
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

#if defined(ENABLE_WIREGUARD) && defined(ENABLE_NODE_ENCRYPTION)
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == HOST_ID);

	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		assert(settings->redirect_ifindex == WG_IFINDEX);
#else
	assert(*status_code == CTX_ACT_OK);
#endif

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IPd");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != NODE_PORT)
		test_fatal("bad src port");

	if (l4->dest != REMOTE_NODE_PORT)
		test_fatal("bad dst port");

	test_finish();
}

/***********************************************************************/

PKTGEN("tc", "netdev_host_to_world_ipv4_udp")
int netdev_host_to_world_ipv4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)external_mac,
					  NODE_IP, EXTERNAL_IP,
					  NODE_PORT, EXTERNAL_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_host_to_world_ipv4_udp")
int netdev_host_to_world_ipv4_udp_setup(struct __ctx_buff *ctx)
{
	ctx->mark = MARK_MAGIC_HOST;

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_host_to_world_ipv4_udp")
int netdev_host_to_world_ipv4_udp_check(struct __ctx_buff *ctx)
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

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IPd");

	if (l3->daddr != EXTERNAL_IP)
		test_fatal("bad dest IP");

	if (l4->source != NODE_PORT)
		test_fatal("bad src port");

	if (l4->dest != EXTERNAL_PORT)
		test_fatal("bad dst port");

	test_finish();
}
