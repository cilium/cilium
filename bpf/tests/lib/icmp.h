/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

struct validate_icmpv6_reply_args {
	const struct __ctx_buff *ctx;
	const __u8 *src_mac;
	const __u8 *dst_mac;
	const __u8 *src_ip;
	const __u8 *dst_ip;
	__u8 icmp_type;
	__u8 icmp_code;
	__u16 checksum;
	__u32 dst_idx;
	__u32 retval;
};

static __always_inline int
validate_icmpv6_reply(const struct validate_icmpv6_reply_args *args)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;
	struct ratelimit_value *value;

	test_init();

	data = (void *)(long)ctx_data(args->ctx);
	data_end = (void *)(long)args->ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	test_log("Status code: %d", *status_code);
	assert(*status_code == args->retval);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 header out of bounds");

	assert(memcmp(l2->h_dest, args->dst_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_source, args->src_mac, ETH_ALEN) == 0);
	assert(l2->h_proto == __bpf_htons(ETH_P_IPV6));

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 header out of bounds");

	assert(!memcmp(&l3->saddr, args->src_ip, sizeof(l3->saddr)));
	assert(!memcmp(&l3->daddr, args->dst_ip, sizeof(l3->daddr)));

	assert(l3->hop_limit == 64);
	assert(l3->version == 6);
	assert(l3->nexthdr == IPPROTO_ICMPV6);

	l4 = data + sizeof(__u32) + sizeof(struct ethhdr) +
	     sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct icmp6hdr) > data_end)
		test_fatal("l4 header out of bounds");

	assert(l4->icmp6_type == args->icmp_type);
	assert(l4->icmp6_code == args->icmp_code);
	assert(l4->icmp6_cksum == bpf_htons(args->checksum));

	struct ratelimit_key key = {
		.usage = RATELIMIT_USAGE_ICMPV6,
		.key = {
			.icmpv6 = {
				.netdev_idx = args->dst_idx,
			},
		},
	};

	value = map_lookup_elem(&cilium_ratelimit, &key);
	if (!value)
		test_fatal("ratelimit map lookup failed");

	assert(value->tokens > 0);

	test_finish();
}
