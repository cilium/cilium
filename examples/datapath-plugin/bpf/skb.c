// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

char attachment_context[256];

SEC("freplace")
int before_skb(struct __sk_buff *ctx)
{
	bpf_printk("before %s in %s\n", attachment_context);

	return TC_ACT_UNSPEC;
}

SEC("freplace")
int after_skb(struct __sk_buff *ctx, int ret)
{
	bpf_printk("after %s in %s (ret=%d)\n", attachment_context, ret);

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";

