/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct l2_responder_v4_key {
	__u32 ip4;
	__u32 ifindex;
};

struct l2_responder_stats {
	__u64 responses_sent;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct l2_responder_v4_key);
	__type(value, struct l2_responder_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, L2_RESPONDER_MAP4_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_l2_responder_v4 __section_maps_btf;

struct l2_responder_v6_key {
	union v6addr ip6;
	__u32 ifindex;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct l2_responder_v6_key);
	__type(value, struct l2_responder_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, L2_RESPONDER_MAP6_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_l2_responder_v6 __section_maps_btf;

DECLARE_CONFIG(bool, enable_l2_announcements, "Enable L2 Announcements")
DECLARE_CONFIG(__u64, l2_announcements_max_liveness,
	       "If the agent is down for longer than the lease duration, stop responding")

static __always_inline
int handle_l2_announcement(struct __ctx_buff *ctx, struct ipv6hdr *ip6)
{
	union macaddr mac = CONFIG(interface_mac);
	union macaddr smac;
	__be32 __maybe_unused sip;
	__be32 __maybe_unused tip;
	union v6addr __maybe_unused tip6;
	struct l2_responder_stats *stats;
	int ret;
	__u64 time;

	/* Announcing L2 addresses for a L3 device makes no sense: */
	if (THIS_IS_L3_DEV)
		return CTX_ACT_OK;

	time = config_get(RUNTIME_CONFIG_AGENT_LIVENESS);
	if (!time)
		return CTX_ACT_OK;

	/* If the agent is not active for X seconds, we can't trust the contents
	 * of the responder map anymore. So stop responding, assuming other nodes
	 * will take over for a node without an active agent.
	 */
	if (ktime_get_ns() - (time) > CONFIG(l2_announcements_max_liveness))
		return CTX_ACT_OK;

	if (!ip6) {
		struct l2_responder_v4_key key;

		if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
			return CTX_ACT_OK;

		key.ip4 = tip;
		key.ifindex = ctx->ingress_ifindex;
		stats = map_lookup_elem(&cilium_l2_responder_v4, &key);
		if (!stats)
			return CTX_ACT_OK;

		ret = arp_respond(ctx, &mac, tip, &smac, sip, 0);
	} else {
#ifdef ENABLE_IPV6
		struct l2_responder_v6_key key6;
		int l3_off;

		if (!icmp6_ndisc_validate(ctx, ip6, &mac, &tip6))
			return CTX_ACT_OK;

		key6.ip6 = tip6;
		key6.ifindex = ctx->ingress_ifindex;
		key6.pad = 0;
		stats = map_lookup_elem(&cilium_l2_responder_v6, &key6);
		if (!stats)
			return CTX_ACT_OK;

		l3_off = (int)((__u8 *)ip6 - (__u8 *)ctx_data(ctx));

		ret = icmp6_send_ndisc_adv(ctx, l3_off, &mac, false);
#else
		return CTX_ACT_OK;
#endif
	}

	if (ret == CTX_ACT_REDIRECT)
		__sync_fetch_and_add(&stats->responses_sent, 1);

	return ret;
}
