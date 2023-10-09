/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#define ROUTER_IP
#include "config_replacement.h"
#undef ROUTER_IP

#define NODE_ID 2333
#define ENCRYPT_KEY 3
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_IPSEC
#define ENCAP_IFINDEX 4

#include "bpf_lxc.c"

#include "lib/ipcache.h"
#include "lib/policy.h"

#define FROM_CONTAINER 0

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

static __always_inline int
pktgen_from_lxc(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "01_ipv4_from_lxc_no_node_id")
int ipv4_from_lxc_no_node_id_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx);
}

SETUP("tc", "01_ipv4_from_lxc_no_node_id")
int ipv4_from_lxc_no_node_id_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_all_entry();

	ipcache_v4_add_entry(v4_pod_two, 0, 233, v4_node_two, ENCRYPT_KEY);

	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = ENCRYPT_KEY };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "01_ipv4_from_lxc_no_node_id")
int ipv4_from_lxc_no_node_id_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	key.reason = (__u8)-DROP_NO_NODE_ID;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&METRICS_MAP, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	__u64 count = 1;

	assert_metrics_count(key, count);

	test_finish();
}

PKTGEN("tc", "02_ipv4_from_lxc_encrypt")
int ipv4_from_lxc_encrypt_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx);
}

SETUP("tc", "02_ipv4_from_lxc_encrypt")
int ipv4_from_lxc_encrypt_setup(struct __ctx_buff *ctx)
{
	struct node_key node_ip = {};
	__u32 node_id = NODE_ID;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = v4_node_two;
	map_update_elem(&NODE_MAP, &node_ip, &node_id, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "02_ipv4_from_lxc_encrypt")
int ipv4_from_lxc_encrypt_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL_IPV4);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("l2 proto hasn't been set to ETH_P_IP");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != v4_pod_one)
		test_fatal("src IP was changed");

	if (l3->daddr != v4_pod_two)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");

	test_finish();
}

PKTGEN("tc", "03_ipv4_from_lxc_new_local_key")
int ipv4_from_lxc_new_local_key_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx);
}

SETUP("tc", "03_ipv4_from_lxc_new_local_key")
int ipv4_from_lxc_new_local_key_setup(struct __ctx_buff *ctx)
{
	/* The new key is configured locally but not yet on the destination node.
	 */
	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = ENCRYPT_KEY + 1 };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "03_ipv4_from_lxc_new_local_key")
int ipv4_from_lxc_new_local_key_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL_IPV4);

	test_finish();
}

PKTGEN("tc", "04_ipv4_from_lxc_new_remote_key")
int ipv4_from_lxc_new_remote_key_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_lxc(ctx);
}

SETUP("tc", "04_ipv4_from_lxc_new_remote_key")
int ipv4_from_lxc_new_remote_key_setup(struct __ctx_buff *ctx)
{
	/* The new key is configured on the destination node but not yet locally.
	 */
	ipcache_v4_add_entry(v4_pod_two, 0, 233, v4_node_two, ENCRYPT_KEY + 1);

	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = ENCRYPT_KEY };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "04_ipv4_from_lxc_new_remote_key")
int ipv4_from_lxc_new_remote_key_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL_IPV4);

	test_finish();
}

PKTGEN("tc", "05_ipv6_from_lxc_encrypt")
int ipv6_from_lxc_encrypt_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)&v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "05_ipv6_from_lxc_encrypt")
int ipv6_from_lxc_encrypt_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_all_entry();

	ipcache_v6_add_entry((union v6addr *)v6_pod_two, 0, 233, v4_node_two, ENCRYPT_KEY);

	__u32 encrypt_key = 0;
	struct encrypt_config encrypt_value = { .encrypt_key = ENCRYPT_KEY };

	map_update_elem(&ENCRYPT_MAP, &encrypt_key, &encrypt_value, BPF_ANY);

	struct node_key node_ip = {};
	__u32 node_id = NODE_ID;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = v4_node_two;
	map_update_elem(&NODE_MAP, &node_ip, &node_id, BPF_ANY);

	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "05_ipv6_from_lxc_encrypt")
int ipv6_from_lxc_encrypt_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	__u8 *payload;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);
	assert(ctx->mark == (NODE_ID << 16 | ENCRYPT_KEY << 12 | MARK_MAGIC_ENCRYPT));
	assert(ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY) == SECLABEL_IPV6);

	l2 = data + sizeof(*status_code);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("l2 proto hasn't been set to ETH_P_IPV6");

	if (memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) != 0)
		test_fatal("src mac hasn't been set to source ep's mac");

	if (memcmp(l2->h_dest, (__u8 *)mac_two, ETH_ALEN) != 0)
		test_fatal("dest mac hasn't been set to dest ep's mac");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	if (memcmp((__u8 *)&l3->saddr, (__u8 *)v6_pod_one, 16) != 0)
		test_fatal("src IP was changed");

	if (memcmp((__u8 *)&l3->daddr, (__u8 *)v6_pod_two, 16) != 0)
		test_fatal("dest IP was changed");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != tcp_src_one)
		test_fatal("src TCP port was changed");

	if (l4->dest != tcp_svc_one)
		test_fatal("dst TCP port was changed");

	payload = (void *)l4 + sizeof(struct tcphdr);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("paylaod out of bounds\n");

	if (memcmp(payload, default_data, sizeof(default_data)) != 0)
		test_fatal("tcp payload was changed");
	test_finish();
}
