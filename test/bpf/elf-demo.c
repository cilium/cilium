// SPDX-License-Identifier: GPL-2.0
// Copyright Authors of Cilium

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/eth.h"

DEFINE_U32(FOO, 0xF0F0F0F0);
DEFINE_U32(BAR, 0xCECECECE);
DEFINE_IPV6(GLOBAL_IPV6, 0x1, 0, 0x1, 0, 0, 0x1, 0, 0x1, 0x1, 0, 0x1, 0, 0, 0x1, 0, 0x1);
DEFINE_MAC(LOCAL_MAC, 0, 0x1, 0, 0, 0, 0x1);

#define CALLS_MAP_ID 0
#undef CALLS_MAP
#define CALLS_MAP test_cilium_calls_4278124286 // 0xFEFEFEFE

// Note: This program is meant to exercise ELF substitution logic and eBPF
// loader behaviour. The programs are not assigned to sections, so don't have
// their progbits emitted to the ELF, and cannot be loaded into the kernel.

int tail_lxc_prog(struct __sk_buff *skb) {
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, int ());
} CALLS_MAP __section_maps_btf = {
	.values = {
		[CALLS_MAP_ID] = &tail_lxc_prog,
	},
};

int __main(struct __sk_buff *skb)
{
	union v6addr v6 = {};
	union macaddr mac = fetch_mac(LOCAL_MAC);

	skb->mark = fetch_u32(FOO);
	skb->cb[0] = fetch_u32(BAR);

	BPF_V6(v6, GLOBAL_IPV6);
	skb->cb[1] = v6.p1;
	skb->cb[2] = v6.p2;
	skb->cb[3] = v6.p3;
	skb->cb[4] = v6.p4;

	skb->priority = mac.p1;
	skb->tc_classid = mac.p2;

	tail_call(skb, &CALLS_MAP, CALLS_MAP_ID);

	return TC_ACT_SHOT;
}

char __license[] __section("license") = "";
