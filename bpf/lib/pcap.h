/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __LIB_PCAP_H_
#define __LIB_PCAP_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"

struct pcap_timeval {
	__u32 tv_sec;
	__u32 tv_usec;
};

struct pcap_timeoff {
	__u64 tv_boot;
};

struct pcap_pkthdr {
	union {
		/* User space needs to perform inline conversion from
		 * boot offset to time of day before writing out to
		 * an external file.
		 */
		struct pcap_timeval ts;
		struct pcap_timeoff to;
	};
	__u32 caplen;
	__u32 len;
};

struct capture_msg {
	/* The hash is reserved and always zero for allowing different
	 * header extensions in future.
	 */
	NOTIFY_COMMON_HDR
	/* The pcap hdr must be the last member so that the placement
	 * inside the perf RB is linear: pcap hdr + packet payload.
	 */
	struct pcap_pkthdr hdr;
};

static __always_inline void cilium_capture(struct __ctx_buff *ctx,
					   const __u8 subtype,
					   const __u16 rule_id,
					   const __u64 tstamp)
{
	__u64 ctx_len = ctx_full_len(ctx);
	/* rule_id is the demuxer for the target pcap file when there are
	 * multiple capturing rules present.
	 */
	struct capture_msg msg = {
		.type    = CILIUM_NOTIFY_CAPTURE,
		.subtype = subtype,
		.source  = rule_id,
		.hdr     = {
			.to	= {
				.tv_boot = tstamp,
			},
			.caplen	= ctx_len,
			.len	= ctx_len,
		},
	};

	ctx_event_output(ctx, &EVENTS_MAP, (ctx_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void cilium_capture_in(struct __ctx_buff *ctx)
{
	/* For later pcap file generation, we export boot time to the RB
	 * such that user space can later reconstruct a real time of day
	 * timestamp in-place.
	 */
	cilium_capture(ctx, CAPTURE_INGRESS, 0, bpf_ktime_cache_set(boot_ns));
}

static __always_inline void cilium_capture_out(struct __ctx_buff *ctx)
{
	cilium_capture(ctx, CAPTURE_EGRESS, 0, bpf_ktime_cache_get());
}

#endif /* __LIB_PCAP_H_ */
