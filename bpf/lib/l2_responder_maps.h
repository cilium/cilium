/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Map types and BPF map declarations for the L2 responder.
 * This header is safe to include from any BPF program — it carries no
 * function implementations and requires no ARP/ICMPv6/runtime-config
 * headers.  Programs that need the full announcement handler (arp.h,
 * icmp6.h, RUNTIME_CONFIG_AGENT_LIVENESS) should include l2_responder.h.
 */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

#include "static_data.h"

/* The gate for consulting the maps below: a consumer that wants to ask
 * "is this address one this node currently L2-announces?" must skip the
 * lookup entirely when L2 announcements are disabled. Declared here (not
 * in the full l2_responder.h) so map consumers can gate without pulling
 * the announcement handler's ARP/ICMPv6 include chain. */
DECLARE_CONFIG(bool, enable_l2_announcements, "Enable L2 Announcements")

struct l2_responder_v4_key {
	union v4addr ip4;
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
