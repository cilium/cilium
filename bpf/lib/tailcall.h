/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "drop_reasons.h"
#include "config.h"

#include "bpf/compiler.h"

#define __eval(x, ...) x ## __VA_ARGS__

#define __and_00 0
#define __and_01 0
#define __and_10 0
#define __and_11 1
#define __and_0(y)  __eval(__and_0, y)
#define __and_1(y)  __eval(__and_1, y)
#define __and(x, y) __eval(__and_, x)(y)

#define __or_00 0
#define __or_01 1
#define __or_10 1
#define __or_11 1
#define __or_0(y)  __eval(__or_0, y)
#define __or_1(y)  __eval(__or_1, y)
#define __or(x, y) __eval(__or_, x)(y)

#define __or3_1(y, z)  1
#define __or3_0(y, z)  __or(y, z)
#define __or3(x, y, z) __eval(__or3_, x)(y, z)

#define __or4_1(x, y, z) 1
#define __or4_0(x, y, z) __eval(__or3_, x)(y, z)
#define __or4(w, x, y, z) __eval(__or4_, w)(x, y, z)

#define __not_0 1
#define __not_1 0
#define __not(x) __eval(__not_, x)

#define CILIUM_CALL_DROP_NOTIFY			1
#define CILIUM_CALL_ERROR_NOTIFY		2
/*
 * A gap in the macro numbering sequence was created by #24921.
 * It can be reused for a new macro in the future, but caution is needed when
 * backporting changes as it may conflict with older versions of the code.
 */
#define CILIUM_CALL_HANDLE_ICMP6_NS			4
#define CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED		5
#define CILIUM_CALL_ARP					6
#define CILIUM_CALL_IPV4_FROM_LXC			7
#define CILIUM_CALL_IPV4_FROM_NETDEV			CILIUM_CALL_IPV4_FROM_LXC
#define CILIUM_CALL_IPV4_FROM_OVERLAY			CILIUM_CALL_IPV4_FROM_LXC
#define CILIUM_CALL_IPV4_FROM_WIREGUARD			CILIUM_CALL_IPV4_FROM_LXC
#define CILIUM_CALL_IPV46_RFC6052			8
#define CILIUM_CALL_IPV64_RFC6052			9
#define CILIUM_CALL_IPV6_FROM_LXC			10
#define CILIUM_CALL_IPV6_FROM_NETDEV			CILIUM_CALL_IPV6_FROM_LXC
#define CILIUM_CALL_IPV6_FROM_OVERLAY			CILIUM_CALL_IPV6_FROM_LXC
#define CILIUM_CALL_IPV6_FROM_WIREGUARD			CILIUM_CALL_IPV6_FROM_LXC
#define CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY		11
#define CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY		CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY
#define CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY		12
#define CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY		CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY
#define CILIUM_CALL_IPV4_TO_ENDPOINT			13
#define CILIUM_CALL_IPV6_TO_ENDPOINT			14
#define CILIUM_CALL_IPV4_NODEPORT_NAT_EGRESS		15
#define CILIUM_CALL_IPV6_NODEPORT_NAT_EGRESS		16
#define CILIUM_CALL_IPV4_NODEPORT_REVNAT		17
#define CILIUM_CALL_IPV6_NODEPORT_REVNAT_INGRESS	18
#define CILIUM_CALL_IPV6_NODEPORT_REVNAT_EGRESS		19
#define CILIUM_CALL_IPV4_NODEPORT_NAT_FWD		20
#define CILIUM_CALL_IPV4_NODEPORT_DSR			21
#define CILIUM_CALL_IPV6_NODEPORT_DSR			22
#define CILIUM_CALL_IPV4_FROM_HOST			23
#define CILIUM_CALL_IPV6_FROM_HOST			24
#define CILIUM_CALL_IPV6_NODEPORT_NAT_FWD		25
#define CILIUM_CALL_IPV4_FROM_LXC_CONT			26
#define CILIUM_CALL_IPV6_FROM_LXC_CONT			27
#define CILIUM_CALL_IPV4_CT_INGRESS			28
#define CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY		29
#define CILIUM_CALL_IPV4_CT_EGRESS			30
#define CILIUM_CALL_IPV6_CT_INGRESS			31
#define CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY		32
#define CILIUM_CALL_IPV6_CT_EGRESS			33
#define CILIUM_CALL_SRV6_ENCAP				34
#define CILIUM_CALL_SRV6_DECAP				35
#define CILIUM_CALL_IPV4_NODEPORT_NAT_INGRESS		36
#define CILIUM_CALL_IPV6_NODEPORT_NAT_INGRESS		37
#define CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD		38
#define CILIUM_CALL_IPV6_NODEPORT_SNAT_FWD		39
#define CILIUM_CALL_IPV4_INTER_CLUSTER_REVSNAT		40
#define CILIUM_CALL_IPV4_CONT_FROM_HOST			41
#define CILIUM_CALL_IPV4_CONT_FROM_NETDEV		42
#define CILIUM_CALL_IPV6_CONT_FROM_HOST			43
#define CILIUM_CALL_IPV6_CONT_FROM_NETDEV		44
#define CILIUM_CALL_IPV4_NO_SERVICE			45
#define CILIUM_CALL_IPV6_NO_SERVICE			46
#define CILIUM_CALL_MULTICAST_EP_DELIVERY		47
#define CILIUM_CALL_SIZE				48

/* Private per-EP map for internal tail calls. Its bpffs pin is replaced every
 * time the BPF object is loaded. An existing pinned map is never reused.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, CILIUM_CALL_SIZE);
	__uint(pinning, CILIUM_PIN_REPLACE);
	__array(values, int ());
} cilium_calls __section_maps_btf;

/* Annotate a function with this attribute to insert it into cilium_calls at
 * the given index. index must be a compile-time constant and must be unique.
 * Do not use for tail call mocks in bpf tests, use __section_entry instead.
 *
 * The agent will automatically insert the tail call into cilium_calls when
 * the object is loaded. This annotation marks the function for elimination
 * when it's never called by tail_call_static.
 */
#if !defined(PROG_TYPE)
	#error "Include bpf/ctx/skb.h or bpf/ctx/xdp.h before tailcall.h!"
#endif
#define __declare_tail(index) \
	__section(PROG_TYPE "/tail") \
	__attribute__((btf_decl_tag("tail:cilium_calls/" __stringify(index))))

static __always_inline __must_check int
tail_call_internal(struct __ctx_buff *ctx, const __u32 index, __s8 *ext_err)
{
	tail_call_static(ctx, cilium_calls, index);

	if (ext_err)
		*ext_err = (__s8)index;
	return DROP_MISSED_TAIL_CALL;
}

/* invoke_tailcall_if() is a helper which based on COND either selects to emit
 * a tail call for the underlying function when true or emits it as inlined
 * when false. COND can be selected by one or multiple compile time flags.
 *
 * [...]
 * invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
 *                    CILIUM_CALL_FOO, foo_fn);
 * [...]
 *
 * The loader will only load tail calls if they are invoked at least once.
 */

#define __invoke_tailcall_if_0(NAME, FUNC, EXT_ERR)			\
	FUNC(ctx)
#define __invoke_tailcall_if_1(NAME, FUNC, EXT_ERR)			\
	({								\
		tail_call_internal(ctx, NAME, EXT_ERR);			\
	})
#define invoke_tailcall_if(COND, NAME, FUNC, EXT_ERR)			\
	__eval(__invoke_tailcall_if_, COND)(NAME, FUNC, EXT_ERR)

#define __invoke_traced_tailcall_if_0(NAME, FUNC, TRACE, EXT_ERR)	\
	FUNC(ctx, TRACE, EXT_ERR)
#define __invoke_traced_tailcall_if_1(NAME, FUNC, TRACE, EXT_ERR)	\
	({								\
		tail_call_internal(ctx, NAME, EXT_ERR);			\
	})
#define invoke_traced_tailcall_if(COND, NAME, FUNC, TRACE, EXT_ERR)	\
	__eval(__invoke_traced_tailcall_if_, COND)(NAME, FUNC, TRACE,	\
						   EXT_ERR)
