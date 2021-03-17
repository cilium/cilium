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

static __always_inline void __cilium_capture_in(struct __ctx_buff *ctx,
						__u16 rule_id)
{
	/* For later pcap file generation, we export boot time to the RB
	 * such that user space can later reconstruct a real time of day
	 * timestamp in-place.
	 */
	cilium_capture(ctx, CAPTURE_INGRESS, rule_id,
		       bpf_ktime_cache_set(boot_ns));
}

static __always_inline void __cilium_capture_out(struct __ctx_buff *ctx,
						 __u16 rule_id)
{
	cilium_capture(ctx, CAPTURE_EGRESS, rule_id,
		       bpf_ktime_cache_get());
}

/* The capture_enabled integer ({0,1}) is enabled/disabled via BPF based ELF
 * templating. Meaning, when disabled, the verifier's dead code elimination
 * will ensure that there is no overhead when the facility is not used. The
 * below is a fallback definition for when the templating var is not defined.
 */
#ifndef capture_enabled
# define capture_enabled (__ctx_is == __ctx_xdp)
#endif /* capture_enabled */

struct capture_cache {
	bool  rule_seen;
	__u16 rule_id;
};

struct bpf_elf_map __section_maps cilium_capture_cache = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct capture_cache),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

static __always_inline bool
cilium_capture_candidate(struct __ctx_buff *ctx __maybe_unused,
			 __u16 *rule_id __maybe_unused)
{
	if (capture_enabled) {
		struct capture_cache *c;
		__u32 zero = 0;

		c = map_lookup_elem(&cilium_capture_cache, &zero);
		if (always_succeeds(c)) {
			/* TBD */
			c->rule_seen = true;
			c->rule_id = 0;
			return true;
		}
	}
	return false;
}

static __always_inline bool
cilium_capture_cached(struct __ctx_buff *ctx __maybe_unused,
		      __u16 *rule_id __maybe_unused)
{
	if (capture_enabled) {
		struct capture_cache *c;
		__u32 zero = 0;

		/* Avoid full classification a 2nd time due to i) overhead but
		 * also since ii) we might have pushed an encap header in front
		 * where we don't want to dissect everything again.
		 */
		c = map_lookup_elem(&cilium_capture_cache, &zero);
		if (always_succeeds(c) && c->rule_seen) {
			*rule_id = c->rule_id;
			return true;
		}
	}
	return false;
}

static __always_inline void
cilium_capture_in(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_CAPTURE
	__u16 rule_id;

	if (cilium_capture_candidate(ctx, &rule_id))
		__cilium_capture_in(ctx, rule_id);
#endif /* ENABLE_CAPTURE */
}

static __always_inline void
cilium_capture_out(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_CAPTURE
	__u16 rule_id;

	/* cilium_capture_out() is always paired with cilium_capture_in(), so
	 * we can rely on previous cached result on whether to push the pkt
	 * to the RB or not.
	 */
	if (cilium_capture_cached(ctx, &rule_id))
		__cilium_capture_out(ctx, rule_id);
#endif /* ENABLE_CAPTURE */
}

#endif /* __LIB_PCAP_H_ */
