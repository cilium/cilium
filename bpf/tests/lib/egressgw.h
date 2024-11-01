/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_NODE_IP		v4_node_one

#define GATEWAY_NODE_IP		v4_node_two

#define EXTERNAL_SVC_IP		v4_ext_one
#define EXTERNAL_SVC_PORT	__bpf_htons(1234)

#define EGRESS_IP		IPV4(1, 2, 3, 4)
#define EGRESS_IP2		IPV4(2, 3, 4, 5)
#define EGRESS_IP3		IPV4(3, 3, 4, 5)

static volatile const __u8 *client_mac  = mac_one;
static volatile const __u8 *gateway_mac = mac_two;
static volatile const __u8 *ext_svc_mac = mac_three;

enum egressgw_test {
	TEST_SNAT1                    = 0,
	TEST_SNAT2                    = 1,
	TEST_SNAT_TUPLE_COLLISION     = 2,
	TEST_SNAT_EXCL_CIDR           = 3,
	TEST_REDIRECT                 = 4,
	TEST_REDIRECT_EXCL_CIDR       = 5,
	TEST_REDIRECT_SKIP_NO_GATEWAY = 6,
	TEST_XDP_REPLY                = 7,
	TEST_FIB                      = 8,
	TEST_DROP_NO_EGRESS_IP        = 9,
};

struct egressgw_test_ctx {
	__u16 test;
	enum ct_dir dir;
	bool redirect;
	bool tuple_collision;
	__u64 packets;
	__u32 status_code;
};

static __always_inline __be16 client_port(__u16 t)
{
	return CLIENT_PORT + bpf_htons(t);
}

#ifdef ENABLE_EGRESS_GATEWAY
static __always_inline void add_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr,
						      __be32 gateway_ip, __be32 egress_ip)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	struct egress_gw_policy_entry in_val = {
		.egress_ip  = egress_ip,
		.gateway_ip = gateway_ip,
	};

	map_update_elem(&EGRESS_POLICY_MAP, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	map_delete_elem(&EGRESS_POLICY_MAP, &in_key);
}
#endif /* ENABLE_EGRESS_GATEWAY */

static __always_inline int egressgw_pktgen(struct __ctx_buff *ctx,
					   struct egressgw_test_ctx test_ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	if (test_ctx.dir == CT_INGRESS)
		ethhdr__set_macs(l2, (__u8 *)ext_svc_mac, (__u8 *)client_mac);
	else /* CT_EGRESS */
		ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)ext_svc_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	if (test_ctx.dir == CT_INGRESS) {
		l3->saddr = EXTERNAL_SVC_IP;
		if (test_ctx.tuple_collision) {
			l3->daddr = EGRESS_IP3;
		} else {
			l3->daddr = EGRESS_IP;
		}
	} else { /* CT_EGRESS */
		l3->saddr = CLIENT_IP;
		l3->daddr = EXTERNAL_SVC_IP;
	}

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	if (test_ctx.dir == CT_INGRESS) {
		/* Get the destination port from the NAT entry. */
		struct ipv4_ct_tuple tuple = {
			.saddr   = CLIENT_IP,
			.daddr   = EXTERNAL_SVC_IP,
			.dport   = EXTERNAL_SVC_PORT,
			.sport   = client_port(test_ctx.test),
			.nexthdr = IPPROTO_TCP,
		};
		struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

		if (!nat_entry)
			return TEST_ERROR;
		l4->source = EXTERNAL_SVC_PORT;
		l4->dest = nat_entry->to_sport;
	} else { /* CT_EGRESS */
		l4->source = client_port(test_ctx.test);
		l4->dest = EXTERNAL_SVC_PORT;
	}

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline int egressgw_snat_check(const struct __ctx_buff *ctx,
					       struct egressgw_test_ctx test_ctx)
{
	void *data, *data_end;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__be32 expected_saddr;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*(__u32 *)data == test_ctx.status_code);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (test_ctx.dir == CT_INGRESS) {
		if (memcmp(l2->h_source, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
			test_fatal("src MAC is not the external svc MAC")

		if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
			test_fatal("dst MAC is not the client MAC")

		if (l3->saddr != EXTERNAL_SVC_IP)
			test_fatal("src IP has changed");

		if (l3->daddr != CLIENT_IP)
			test_fatal("dst IP hasn't been revSNATed to client IP");
	} else { /* CT_EGRESS */
		if (test_ctx.redirect) {
			if (memcmp(l2->h_source, (__u8 *)mac_zero, ETH_ALEN) != 0)
				test_fatal("src MAC is not the secondary iface MAC")

			if (memcmp(l2->h_dest, (__u8 *)mac_zero, ETH_ALEN) != 0)
				test_fatal("dst MAC is not the external svc MAC")

			if (l3->saddr != CLIENT_IP)
				test_fatal("src IP has changed before redirecting to egress iface");
		} else {
			if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
				test_fatal("src MAC is not the client MAC")

			if (memcmp(l2->h_dest, (__u8 *)ext_svc_mac, ETH_ALEN) != 0)
				test_fatal("dst MAC is not the external svc MAC")

			expected_saddr = EGRESS_IP;
			if (test_ctx.tuple_collision)
				expected_saddr = EGRESS_IP3;

			if (l3->saddr != expected_saddr)
				test_fatal("src IP hasn't been NATed to egress gateway IP");
		}

		if (l3->daddr != EXTERNAL_SVC_IP)
			test_fatal("dst IP has changed");
	}

	/* SNAT happens *after* redirect: */
	if (!test_ctx.redirect) {
		/* Lookup the SNAT mapping for the original packet to determine the new source port */
		struct ipv4_ct_tuple tuple = {
			.daddr   = CLIENT_IP,
			.saddr   = EXTERNAL_SVC_IP,
			.dport   = EXTERNAL_SVC_PORT,
			.sport   = client_port(test_ctx.test),
			.nexthdr = IPPROTO_TCP,
			.flags = TUPLE_F_OUT,
		};
		struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

		if (!ct_entry)
			test_fatal("no CT entry found");
		if (ct_entry->packets != test_ctx.packets)
			test_fatal("bad packet count (expected %u, actual %u)",
				   test_ctx.packets, ct_entry->packets)

		tuple.saddr = CLIENT_IP;
		tuple.daddr = EXTERNAL_SVC_IP;

		struct ipv4_nat_entry *nat_entry = __snat_lookup(&SNAT_MAPPING_IPV4, &tuple);

		if (!nat_entry)
			test_fatal("could not find a NAT entry for the packet");

		if (test_ctx.dir == CT_INGRESS) {
			if (l4->source != EXTERNAL_SVC_PORT)
				test_fatal("src port has changed");

			if (l4->dest != client_port(test_ctx.test))
				test_fatal("dst TCP port hasn't been revSNATed to client port");
		} else { /* CT_EGRESS */
			if (l4->source != nat_entry->to_sport)
				test_fatal("src TCP port hasn't been NATed to egress gateway port");

			if (l4->dest != EXTERNAL_SVC_PORT)
				test_fatal("dst port has changed");
		}
	}

	test_finish();
}

static __always_inline int egressgw_status_check(const struct __ctx_buff *ctx,
						 struct egressgw_test_ctx test_ctx)
{
	void *data, *data_end;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*(__u32 *)data == test_ctx.status_code);

	test_finish();
}

static __always_inline int create_ct_entry(struct __ctx_buff *ctx, __be16 client_port)
{
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};

	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = EXTERNAL_SVC_IP;
	tuple.sport = EXTERNAL_SVC_PORT;
	tuple.saddr = CLIENT_IP;
	tuple.dport = client_port;
	__ipv4_ct_tuple_reverse(&tuple);

	return ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
			 CT_EGRESS, &ct_state, NULL);
}
