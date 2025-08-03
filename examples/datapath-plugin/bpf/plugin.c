// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "exits.h"

__u16 proxy_port;

SEC("tc")
int from_client(struct __sk_buff *ctx)
{
	struct bpf_sock_tuple proxy = {
		.ipv4 = {
			.dport = bpf_htons(proxy_port),
		},
	};
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_sock_tuple *tuple;
	struct bpf_sock *sk;
	struct ethhdr *eth;
	struct iphdr *ip4;
	int ret;

	ret = get_cilium_return();

	/* Ignore traffic that Cilium dropped or redirected (we only operate
	 * in kernel routing mode).
	 */
	if (ret != TC_ACT_OK) {
		bpf_printk("cilium did not return TC_ACT_OK: %d\n", ret);
		return ret;
	}
	
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >= data_end) {
		bpf_printk("packet not big enough to contain ethernet and ip headers\n");
		return TC_ACT_OK;
	}

	eth = (struct ethhdr *)data;

	/* Only redirect IPv4 traffic. */
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("not an IP packet\n");
		return TC_ACT_OK;
	}

	ip4 = (struct iphdr *)(data + sizeof(*eth));

	/* Only redirect TCP traffic. */
	if (ip4->protocol != IPPROTO_TCP) {
		bpf_printk("not a TCP packet: %d\n", (int)ip4->protocol);
		return TC_ACT_OK;
	}

	tuple = (struct bpf_sock_tuple *)&ip4->saddr;
	if ((void *)tuple + sizeof(tuple->ipv4) > data_end) {
		bpf_printk("tuple bounds check failed\n");
		return TC_ACT_OK;
	}

	/* First, see if there is an established socket. */
	sk = bpf_sk_lookup_tcp(ctx, tuple, sizeof(tuple->ipv4),
			       BPF_F_CURRENT_NETNS, 0);
	if (sk) {
		if (sk->state != BPF_TCP_LISTEN) {
			bpf_printk("found established socket\n");
			goto assign;
		}
		bpf_printk("found listening socket socket\n");
		goto release;
	}

	tuple = &proxy;

	/* If that fails, look for the listening proxy socket and direct traffic
	 * there.
	 */
	sk = bpf_sk_lookup_tcp(ctx, tuple, sizeof(tuple->ipv4),
			       BPF_F_CURRENT_NETNS, 0);
	if (!sk) {
		bpf_printk("did not find proxy socket\n");
		return TC_ACT_SHOT;
	}

	bpf_printk("found proxy socket (protocol=%d,family=%d,state=%d)\n",
		   (int)sk->protocol,
		   (int)sk->family,
		   (int)sk->state);
assign:
	if (sk->state == BPF_TCP_LISTEN)
		bpf_printk("bpf_sk_assign returned %d\n", bpf_sk_assign(ctx, sk, 0));
release:
	bpf_sk_release(sk);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
