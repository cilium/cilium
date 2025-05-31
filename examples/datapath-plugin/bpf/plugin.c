// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "exits.h"

enum direction {
	ingress,
	egress,
};

__u64 endpoint_id;
__u32 direction;

static __always_inline
const char *direction_str()
{
	switch (direction) {
	case ingress:
		return "ingress";
	case egress:
		return "egress";
	}

	return "unknown";
}

SEC("tc")
int before_cilium_host(struct __sk_buff *ctx)
{
	bpf_printk("before cilium_host %s\n", direction_str());

	return TC_ACT_UNSPEC;
}

SEC("tc")
int after_cilium_host(struct __sk_buff *ctx)
{
	int ret = get_cilium_return();

	bpf_printk("after cilium_host %s (ret = %d)\n", direction_str(), ret);

	return ret;
}

SEC("tc")
int before_cilium_lxc(struct __sk_buff *ctx)
{
	bpf_printk("before lxc %llu %s\n", endpoint_id, direction_str());

	return TC_ACT_UNSPEC;
}

SEC("tc")
int after_cilium_lxc(struct __sk_buff *ctx)
{
	int ret = get_cilium_return();

	bpf_printk("after lxc %llu %s (ret = %d)\n", endpoint_id,
		   direction_str(), ret);

	return ret;
}

char _license[] SEC("license") = "GPL";
