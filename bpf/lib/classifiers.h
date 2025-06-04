/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"

typedef __u8 cls_flags_t;

/* Classification flags used to enrich trace/drop notifications events. */
enum {
	/* Packet uses IPv6. This flag is only needed/set in trace event:
	 * - carrying the orig_ip IPv6 info from send_trace_notify6, or
	 * - with L3 IPv6 packets, to instruct Hubble to use the right decoder.
	 */
	CLS_FLAG_IPV6	   = (1 << 0),
	/* Packet originates from a L3 device (no ethernet header). */
	CLS_FLAG_L3_DEV    = (1 << 1),
};

/* Wrapper for specifying empty flags during the trace/drop event. */
#define CLS_FLAG_NONE ((cls_flags_t)0)

/**
 * ctx_classify
 * @ctx: socket buffer
 * @proto: the layer 3 protocol (ETH_P_IP, ETH_P_IPV6).
 *
 * Compute classifiers (CLS_FLAG_*) for the given packet to be used during
 * trace/drop notification events.
 */
static __always_inline cls_flags_t
ctx_classify(struct __ctx_buff *ctx __maybe_unused, __be16 proto)
{
	cls_flags_t flags = CLS_FLAG_NONE;

	/*
	 * Retrieve protocol when not being provided.
	 * (ex. from drop notifications, or when previous calls to validate_ethertype failed)
	 */
	if (!proto)
		proto = ctx_get_protocol(ctx);

	/* Check whether the packet comes from a L3 device (no ethernet). */
	if (ETH_HLEN == 0)
		flags |= CLS_FLAG_L3_DEV;

	/* Check if IPv6 packet. */
	if (proto == bpf_htons(ETH_P_IPV6))
		flags |= CLS_FLAG_IPV6;

	return flags;
}
