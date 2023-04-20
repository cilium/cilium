// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#include <node_config.h>

#undef EVENTS_MAP
#define EVENTS_MAP test_events_map
#define DEBUG

#include <lib/dbg.h>
#include <lib/conntrack.h>
#include <lib/conntrack_map.h>
#include <lib/time.h>

__always_inline int mkpkt(void *dst, bool first)
{
	void *orig = dst;
	struct ethhdr *l2 = dst;

	l2->h_proto = bpf_htons(ETH_P_IP);

	if (first) {
		char src[6] = {1, 0, 0, 3, 0, 10};
		char dest[6] = {1, 0, 0, 3, 0, 20};

		memcpy(l2->h_source, src, sizeof(src));
		memcpy(l2->h_dest, dest, sizeof(dest));
	} else {
		char src[6] = {1, 0, 0, 3, 0, 20};
		char dest[6] = {1, 0, 0, 3, 0, 10};

		memcpy(l2->h_source, src, sizeof(src));
		memcpy(l2->h_dest, dest, sizeof(dest));
	}

	dst += sizeof(struct ethhdr);

	struct iphdr *l3 = dst;

	l3->version = 4;
	l3->ihl = 5;
	l3->protocol = IPPROTO_TCP;

	if (first) {
		l3->saddr =  0x0A00030A; /* 10.3.0.10 */
		l3->daddr = 0x1400030A; /* 10.3.0.20 */
	} else {
		l3->saddr = 0x1400030A; /* 10.3.0.20 */
		l3->daddr =  0x0A00030A; /* 10.3.0.10 */
	}

	dst += sizeof(struct iphdr);

	char tcp_data[11] = "pizza! :-)";

	struct tcphdr *l4 = dst;

	l4->doff = 5;
	if (first) {
		l4->source = __bpf_htons(3010);
		l4->dest = __bpf_htons(3020);
		l4->syn = 1;
	} else {
		l4->source = __bpf_htons(3020);
		l4->dest = __bpf_htons(3010);
		l4->rst = 1;
	}
	dst += sizeof(struct tcphdr);

	memcpy(dst, tcp_data, sizeof(tcp_data));
	dst += sizeof(tcp_data);

	return dst - orig;
}

static char pkt[100];

CHECK("tc", "ct4")
int test_ct4_rst1_check(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int pkt_size = mkpkt(pkt, true);

	{
		unsigned int data_len = ctx->data_end - ctx->data;
		int offset = pkt_size - 256 - 320 - data_len;

		ctx_adjust_troom(ctx, offset);

		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	TEST("ct4_syn", {
		struct ipv4_ct_tuple tuple = {};
		void *data;
		void *data_end;
		struct iphdr *ip4;
		int l3_off = ETH_HLEN;
		int l4_off;
		struct ct_state ct_state = {};
		struct ct_state ct_state_new = {};
		__u16 proto;
		__u32 monitor = 0;
		int ret;

		bpf_clear_meta(ctx);
		assert(validate_ethertype(ctx, &proto));
		assert(revalidate_data(ctx, &data, &data_end, &ip4));

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
					 CT_EGRESS, &ct_state_new, false, false, NULL);
			break;

		default:
			test_log("ct_lookup4, expected CT_NEW, got %d", ret);
			test_fail();
		}

		if (data + pkt_size > data_end)
			test_fatal("packet shrank");

		/* unexpected data modification */
		assert(memcmp(pkt, data, pkt_size) == 0);
	});

	pkt_size = mkpkt(pkt, false);
	{
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		if (data + pkt_size > data_end)
			return TEST_ERROR;

		memcpy(data, pkt, pkt_size);
	}

	#define TEST_LOG

	TEST("ct4_rst", {
		struct ipv4_ct_tuple tuple = {};
		void *data;
		void *data_end;
		struct iphdr *ip4;
		int l3_off = ETH_HLEN;
		int l4_off;
		struct ct_state ct_state = {};
		__u16 proto;
		__u32 monitor = 0;

		bpf_clear_meta(ctx);
		assert(validate_ethertype(ctx, &proto));
		assert(revalidate_data(ctx, &data, &data_end, &ip4));

		tuple.nexthdr = ip4->protocol;
		tuple.daddr = ip4->daddr;
		tuple.saddr = ip4->saddr;
		l4_off = l3_off + ipv4_hdrlen(ip4);

		ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			   &ct_state, &monitor);

		if (data + pkt_size > data_end)
			test_fatal("packet shrank");

		/* unexpected data modification */
		assert(memcmp(pkt, data, pkt_size) == 0);

		tuple.nexthdr = IPPROTO_TCP;
		tuple.saddr = 0x1400030A; /* 10.3.0.20 */
		tuple.daddr = 0x0A00030A; /* 10.3.0.10 */
		tuple.sport = __bpf_htons(3010);
		tuple.dport = __bpf_htons(3020);
		tuple.flags = 0;

		struct ct_entry *entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

		assert(entry);

		__u32 expires = entry->lifetime - bpf_ktime_get_sec();

		if (expires > 10)
			test_fatal("Expiration is %ds even if RST flag was set", expires);

	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
