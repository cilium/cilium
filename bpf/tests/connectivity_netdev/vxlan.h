// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifdef ENABLE_EGRESS_GATEWAY
PKTGEN("tc", "netdev_vxlan_ipv4_pod_to_world_ipv4")
int netdev_vxlan_ipv4_pod_to_world_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_node_mac,
					       NODE_IP, REMOTE_NODE_IP,
					       0 /* TODO */, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	vxlan->vx_vni = sec_identity_to_tunnel_vni(POD_IDENTITY);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)remote_node_mac,
				      POD_IP, EXTERNAL_IP);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_vxlan_ipv4_pod_to_world_ipv4")
int netdev_vxlan_ipv4_pod_to_world_ipv4_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, POD_IDENTITY, MARK_MAGIC_OVERLAY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_vxlan_ipv4_pod_to_world_ipv4")
int netdev_vxlan_ipv4_pod_to_world_ipv4_check(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

#ifdef ENABLE_WIREGUARD
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == POD_IDENTITY);

	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		assert(settings->redirect_ifindex == WG_IFINDEX);
#else
	assert(*status_code == CTX_ACT_OK);
#endif

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != 0)
		test_fatal("bad src port");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("bad dst port");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != POD_IDENTITY)
		test_fatal("bad VNI");

	test_finish();
}
#endif /* ENABLE_EGRESS_GATEWAY */

#ifdef TUNNEL_MODE
PKTGEN("tc", "netdev_vxlan_ipv4_pod_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_pod_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_node_mac,
					       NODE_IP, REMOTE_NODE_IP,
					       0 /* TODO */, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	vxlan->vx_vni = sec_identity_to_tunnel_vni(POD_IDENTITY);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)remote_node_mac,
				      POD_IP, REMOTE_POD_IP);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_vxlan_ipv4_pod_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_pod_ipv4_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, POD_IDENTITY, MARK_MAGIC_OVERLAY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_vxlan_ipv4_pod_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_pod_ipv4d_check(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

#ifdef ENABLE_WIREGUARD
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == POD_IDENTITY);

	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		assert(settings->redirect_ifindex == WG_IFINDEX);
#else
	assert(*status_code == CTX_ACT_OK);
#endif

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != 0)
		test_fatal("bad src port");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("bad dst port");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != POD_IDENTITY)
		test_fatal("bad VNI");

	test_finish();
}

PKTGEN("tc", "netdev_vxlan_ipv4_pod_to_remote_node_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_node_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_node_mac,
					       NODE_IP, REMOTE_NODE_IP,
					       0 /* TODO */, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	vxlan->vx_vni = sec_identity_to_tunnel_vni(POD_IDENTITY);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)remote_node_mac,
				      POD_IP, REMOTE_NODE_IP);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_vxlan_ipv4_pod_to_remote_node_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_node_ipv4_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, POD_IDENTITY, MARK_MAGIC_OVERLAY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_vxlan_ipv4_pod_to_remote_node_ipv4")
int netdev_vxlan_ipv4_pod_to_remote_node_ipv4_check(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

#ifdef ENABLE_WIREGUARD
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == POD_IDENTITY);

	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		assert(settings->redirect_ifindex == WG_IFINDEX);
#else
	assert(*status_code == CTX_ACT_OK);
#endif

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != 0)
		test_fatal("bad src port");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("bad dst port");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != POD_IDENTITY)
		test_fatal("bad VNI");

	test_finish();
}

PKTGEN("tc", "netdev_vxlan_ipv4_host_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_host_to_remote_pod_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_node_mac,
					       NODE_IP, REMOTE_NODE_IP,
					       0 /* TODO */, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	vxlan->vx_vni = sec_identity_to_tunnel_vni(REMOTE_NODE_ID);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)remote_node_mac,
				      NODE_IP, REMOTE_POD_IP);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "netdev_vxlan_ipv4_host_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_host_to_remote_pod_ipv4_setup(struct __ctx_buff *ctx)
{
	/* TODO correct identity? */
	set_identity_mark(ctx, HOST_ID, MARK_MAGIC_OVERLAY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_vxlan_ipv4_host_to_remote_pod_ipv4")
int netdev_vxlan_ipv4_host_to_remote_pod_ipv4_check(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

#ifdef ENABLE_WIREGUARD
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

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != 0)
		test_fatal("bad src port");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("bad dst port");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != REMOTE_NODE_ID)
		test_fatal("bad VNI");

	test_finish();
}

# ifdef ENABLE_IPSEC
#  ifdef TEST_HIGH_COMPLEXITY
PKTGEN("tc", "netdev_vxlan_ipv4_esp_to_remote_node_ipv4")
int netdev_vxlan_ipv4_esp_to_remote_node_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct vxlanhdr *vxlan;
	struct ip_esp_hdr *esp;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	vxlan = pktgen__push_ipv4_vxlan_packet(&builder,
					       (__u8 *)node_mac, (__u8 *)remote_node_mac,
					       NODE_IP, REMOTE_NODE_IP,
					       0 /* TODO */, TUNNEL_PORT);
	if (!vxlan)
		return TEST_ERROR;

	/* XFRM preserves the original identity in CB_ENCRYPT_IDENTITY,
	 * and from-host then restores it when calling do_netdev_encrypt_encap().
	 */
	vxlan->vx_vni = sec_identity_to_tunnel_vni(POD_IDENTITY);

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

SETUP("tc", "netdev_vxlan_ipv4_esp_to_remote_node_ipv4")
int netdev_vxlan_ipv4_esp_to_remote_node_ipv4_setup(struct __ctx_buff *ctx)
{
	set_identity_mark(ctx, POD_IDENTITY, MARK_MAGIC_OVERLAY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "netdev_vxlan_ipv4_esp_to_remote_node_ipv4")
int netdev_vxlan_ipv4_esp_to_remote_node_ipv4_check(struct __ctx_buff *ctx)
{
	struct vxlanhdr *vxlan;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	vxlan = (void *)l4 + sizeof(*l4);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		test_fatal("vxlan out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("bad l2 proto");

	if (l3->protocol != IPPROTO_UDP)
		test_fatal("bad l3 proto");

	if (l3->saddr != NODE_IP)
		test_fatal("bad src IP");

	if (l3->daddr != REMOTE_NODE_IP)
		test_fatal("bad dest IP");

	if (l4->source != 0)
		test_fatal("bad src port");

	if (l4->dest != TUNNEL_PORT)
		test_fatal("bad dst port");

	if (tunnel_vni_to_sec_identity(vxlan->vx_vni) != POD_IDENTITY)
		test_fatal("bad VNI");

	test_finish();
}
#  endif /* TEST_HIGH_COMPLEXITY */
# endif /* ENABLE_IPSEC */
#endif /* TUNNEL_MODE */
