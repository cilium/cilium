#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"

__BPF_MAP(LXC_POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32), sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	struct policy_entry *policy;
	__u32 src_label = 0xffff; /* FIXME*/
	int ifindex = 3; /* FIXME */

	policy = map_lookup_elem(&LXC_POLICY_MAP, &src_label);
	if (!policy)
		return TC_ACT_SHOT;

	return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
