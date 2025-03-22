// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

PKTGEN("tc", "netdev_esp_to_remote_node_ipv4")
int netdev_esp_to_remote_node_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;
	struct ip_esp_hdr *esp;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)remote_node_mac,
				      NODE_IP, REMOTE_NODE_IP);
	if (!l3)
		return TEST_ERROR;

	esp = pktgen__push_default_esphdr(&builder);
	if (!esp)
		return TEST_ERROR;

	esp->spi = REMOTE_NODE_SPI;
	/* TODO macro-fy this, and validate it */
	esp->seq_no = 123;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_esp_to_remote_node_ipv4")
int netdev_esp_to_remote_node_ipv4_setup(struct __ctx_buff *ctx)
{
	/* TODO is this correct? */
	ctx->mark = ipsec_encode_encryption_mark(REMOTE_NODE_SPI, REMOTE_NODE_NODE_ID);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_esp_to_remote_node_ipv4")
int netdev_esp_to_remote_node_ipv4_check(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct ip_esp_hdr *esp;

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

	esp = (void *)l3 + sizeof(struct iphdr);
	if ((void *)esp + sizeof(*esp) > data_end)
		test_fatal("esp out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_ESP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (esp->spi != REMOTE_NODE_SPI)
		test_fatal("bad spi");

	test_finish();
}
