// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include <linux/bpf.h>

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <bpf/ctx/skb.h>

#include <node_config.h>
#include <lib/static_data.h>

#include "bpf/compiler.h"
#include "lib/common.h"
#include "lib/sock.h"
#include "lib/sock_term.h"
#include "lib/dbg.h"
#include "lib/conntrack.h"
#include "lib/conntrack_map.h"

__section("iter/bpf_map_elem")
int iterate_ct(struct bpf_iter__bpf_map_elem *ctx)
{
	const struct ipv4_ct_tuple *key = (struct ipv4_ct_tuple*) ctx->key;
	struct ct_entry *value = (struct ct_entry*) ctx->value;

	if (!ctx) {
		return 0;
	}
	if (!key) {
		return 0;
	}
	if (!value) {
		return 0;
	} 

	struct ipv4_ct_tuple qkey = {
		.daddr = key->daddr,
		.saddr = key->saddr,
		.dport = key->dport,
		.sport = key->sport,
		.nexthdr = key->nexthdr,
		.flags = key->flags,
	};

	struct ct_entry *value2 = map_lookup_elem(&cilium_ct_any4_global, &qkey);
	if (!value2) {
		return 0;
	}

	__u32 now = (__u32)bpf_mono_now();
	if (now < value->lifetime) {
		return 0;
	}

	map_delete_elem(&cilium_ct_any4_global, &qkey);
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
