// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2016-2021 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

/* most values taken from node_config.h */
#define CONNTRACK
#define ENDPOINTS_MAP test_cilium_lxc
#define POLICY_PROG_MAP_SIZE ENDPOINTS_MAP_SIZE
#define METRICS_MAP test_cilium_metrics
#define NAT46_PREFIX {.addr = {                   \
	0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
	0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0    \
} }

#define ENDPOINTS_MAP_SIZE 65536
#define IPCACHE_MAP_SIZE 512000
#define NODE_MAP_SIZE 16384
#define METRICS_MAP_SIZE 65536
#define EVENTS_MAP test_events_map

#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CT_CONNECTION_LIFETIME_TCP	21600
#define CT_CONNECTION_LIFETIME_NONTCP	60
#define CT_SERVICE_LIFETIME_TCP		21600
#define CT_SERVICE_LIFETIME_NONTCP	60
#define CT_SYN_TIMEOUT			60
#define CT_CLOSE_TIMEOUT		10
#define CT_REPORT_INTERVAL		5
#define CT_REPORT_FLAGS			0xff
#define MTU 1500

#define DEBUG

#include <lib/dbg.h>
#include <lib/conntrack.h>
#include <lib/conntrack_map.h>

__section("action/test-nop")
int test_nop(struct __ctx_buff __maybe_unused *ctx)
{
	return CTX_ACT_OK;
}

__section("action/test-map")
int test_map(struct __ctx_buff __maybe_unused *ctx)
{
	/*
	 * Declare static, otherwise this ends up in .rodata.
	 * On new clang + pre-5.12 kernel, this causes BTF to be rejected,
	 * since the Datasec is patched up to the real size of .rodata,
	 * but vlen remains 0, since this is a var with local scope.
	 * See https://lore.kernel.org/bpf/20210119153519.3901963-1-yhs@fb.com.
	 */
	static struct ipv4_ct_tuple ct_key = (struct ipv4_ct_tuple){
		.saddr = bpf_htonl(16843009), /* 1.1.1.1 */
		.daddr = bpf_htonl(16843010), /* 1.1.1.2 */
		.sport = bpf_htons(1001),
		.dport = bpf_htons(1002),
		.nexthdr = 0,
		.flags = 0,
	};

	struct ct_entry ct_val = (struct ct_entry){
		.rx_packets = 1000,
		.tx_packets = 1000,
	};

	map_update_elem(&CT_MAP_TCP4, &ct_key, &ct_val, 0);
	return CTX_ACT_OK;
}

__section("action/test-ct4-rst1")
int test_ct4_rst1(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {}, ct_state_new = {};
	__u16 proto;
	__u32 monitor = 0;
	int ret;

	bpf_clear_meta(ctx);
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	switch (ret) {
	case CT_NEW:
		ct_state_new.node_port = ct_state.node_port;
		ct_state_new.ifindex = ct_state.ifindex;
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
				 CT_EGRESS, &ct_state_new, 0);
		break;

	default:
		ret = -1;
		break;
	}

out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-ct4-rst2")
int test_ct4_rst2(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	__u16 proto;
	__u32 monitor = 0;
	int ret;

	bpf_clear_meta(ctx);
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return CTX_ACT_OK;
}

BPF_LICENSE("GPL");
