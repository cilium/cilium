/*
 * METADATA INPUT:
 *  cb[0] source security label
 *  cb[1] ifindex to forward to upon success
 */

#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/dbg.h"

__BPF_MAP(LXC_POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32), sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_JMP, LXC_SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	struct policy_entry *policy;
	__u32 src_label = skb->cb[0];
	int ifindex = skb->cb[1];

	printk("Handle policy %d %d\n", src_label, ifindex);

	policy = map_lookup_elem(&LXC_POLICY_MAP, &src_label);
	if (!policy) {
		printk("Denied!\n");
		//return TC_ACT_SHOT;
		return redirect(ifindex, 0);
	}

	// FIXME: bump counters

	return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
