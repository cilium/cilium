// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

char program_name[256];
char pod_namespace[256];
char pod_name[256];

SEC("freplace")
int before_lxc(struct __sk_buff *ctx)
{
	bpf_printk("before %s in %s/%s\n", program_name, pod_namespace, pod_name);

	return TC_ACT_UNSPEC;
}

SEC("freplace")
int after_lxc(struct __sk_buff *ctx, int ret)
{
	bpf_printk("after %s in %s/%s (ret=%d)\n", program_name, pod_namespace, pod_name, ret);

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";

