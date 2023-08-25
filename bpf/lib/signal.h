/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_SIGNAL_H_
#define __LIB_SIGNAL_H_

#include <bpf/api.h>
#include <lib/common.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, __NR_CPUS__);
} SIGNAL_MAP __section_maps_btf;

enum {
	SIGNAL_NAT_FILL_UP = 0,
	SIGNAL_CT_FILL_UP,
	SIGNAL_AUTH_REQUIRED,
};

enum {
	SIGNAL_PROTO_V4 = 0,
	SIGNAL_PROTO_V6,
};

struct signal_msg {
	__u32 signal_nr;
	union {
		struct {
			__u32 proto;
		};
		struct auth_key auth;
	};
};

/**
 * SEND_SIGNAL sets a single union MEMBER to VALUE and only includes that
 * member (and signal_nr) in message size. Used to avoid referencing
 * uninitialized memory if trying to send the whole msg.
 */
#define SEND_SIGNAL(CTX, SIGNAL, MEMBER, VALUE)				\
  {									\
	struct signal_msg msg = {					\
		.signal_nr	= (SIGNAL),				\
		.MEMBER		= (VALUE),				\
	};								\
	ctx_event_output((CTX), &SIGNAL_MAP, BPF_F_CURRENT_CPU, &msg,	\
			 sizeof(msg.signal_nr) + sizeof(msg.MEMBER));	\
  }

static __always_inline void send_signal_nat_fill_up(struct __ctx_buff *ctx,
						    __u32 proto)
{
	SEND_SIGNAL(ctx, SIGNAL_NAT_FILL_UP, proto, proto);
}

static __always_inline void send_signal_ct_fill_up(struct __ctx_buff *ctx,
						   __u32 proto)
{
	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
}

static __always_inline void send_signal_auth_required(struct __ctx_buff *ctx,
						      const struct auth_key *auth)
{
	SEND_SIGNAL(ctx, SIGNAL_AUTH_REQUIRED, auth, *auth);
}

#endif /* __LIB_SIGNAL_H_ */
