// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2020 Authors of Cilium */

/* Ensure declaration of notification event types */
#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY
#define POLICY_VERDICT_NOTIFY
#define ENABLE_EGRESS_GATEWAY
#undef ENABLE_ARP_RESPONDER

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/ipv4.h"
#define SKIP_UNDEF_LPM_LOOKUP_FN
#include "lib/maps.h"
#include "lib/nat.h"
#include "lib/trace.h"
#include "lib/policy_log.h"
#include "lib/pcap.h"
#include "sockops/bpf_sockops.h"

/* DECLARE declares a unique usage of the union or struct 'x' on the stack.
 *
 * To prevent compiler from optimizing away the var, we pass a reference
 * to the var to a BPF helper function which accepts a reference as
 * an argument.
 */
#define DECLARE(datatype, x, iter)		\
{						\
	datatype x s ## iter = {};		\
	trace_printk("%p", 1, &s ## iter);	\
	iter++;					\
}

/* This function is a placeholder for C struct definitions shared with Go,
 * it is never executed.
 */
int main(void)
{
	int iter = 0;

	DECLARE(struct, ipv4_ct_tuple, iter);
	DECLARE(struct, ipv6_ct_tuple, iter);
	DECLARE(struct, ct_entry, iter);
	DECLARE(struct, ipcache_key, iter);
	DECLARE(struct, remote_endpoint_info, iter);
	DECLARE(struct, lb4_key, iter);
	DECLARE(struct, lb4_service, iter);
	DECLARE(struct, lb4_backend, iter);
	DECLARE(struct, lb6_key, iter);
	DECLARE(struct, lb6_service, iter);
	DECLARE(struct, lb6_backend, iter);
	DECLARE(struct, endpoint_key, iter);
	DECLARE(struct, endpoint_info, iter);
	DECLARE(struct, metrics_key, iter);
	DECLARE(struct, metrics_value, iter);
	DECLARE(struct, sock_key, iter);
	DECLARE(struct, policy_key, iter);
	DECLARE(struct, policy_entry, iter);
	DECLARE(struct, ipv4_nat_entry, iter);
	DECLARE(struct, ipv6_nat_entry, iter);
	DECLARE(struct, trace_notify, iter);
	DECLARE(struct, drop_notify, iter);
	DECLARE(struct, policy_verdict_notify, iter);
	DECLARE(struct, debug_msg, iter);
	DECLARE(struct, debug_capture_msg, iter);
	DECLARE(struct, ipv4_revnat_tuple, iter);
	DECLARE(struct, ipv4_revnat_entry, iter);
	DECLARE(struct, ipv6_revnat_tuple, iter);
	DECLARE(struct, ipv6_revnat_entry, iter);
	DECLARE(struct, ipv4_frag_id, iter);
	DECLARE(struct, ipv4_frag_l4ports, iter);
	DECLARE(union, macaddr, iter);
	DECLARE(struct, lb4_affinity_key, iter);
	DECLARE(struct, lb6_affinity_key, iter);
	DECLARE(struct, lb_affinity_val, iter);
	DECLARE(struct, lb_affinity_match, iter);
	DECLARE(struct, lb4_src_range_key, iter);
	DECLARE(struct, lb6_src_range_key, iter);
	DECLARE(struct, edt_id, iter);
	DECLARE(struct, edt_info, iter);
	DECLARE(struct, egress_gw_policy_key, iter);
	DECLARE(struct, egress_gw_policy_entry, iter);
	DECLARE(struct, capture4_wcard, iter);
	DECLARE(struct, capture6_wcard, iter);
	DECLARE(struct, capture_rule, iter);

	return 0;
}
