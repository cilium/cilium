// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Ensure declaration of notification event types */
#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY
#define POLICY_VERDICT_NOTIFY
#define ENABLE_VTEP
#define ENABLE_CAPTURE
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
#define DECLARE(type)			\
{					\
	type s = {};			\
	trace_printk("%p", 1, &s);	\
}

/* This function is a placeholder for C struct definitions shared with Go,
 * it is never executed.
 */
int main(void)
{
	DECLARE(struct ipv4_ct_tuple);
	DECLARE(struct ipv6_ct_tuple);
	DECLARE(struct ct_entry);
	DECLARE(struct ipcache_key);
	DECLARE(struct remote_endpoint_info);
	DECLARE(struct lb4_key);
	DECLARE(struct lb4_service);
	DECLARE(struct lb4_backend);
	DECLARE(struct lb6_key);
	DECLARE(struct lb6_service);
	DECLARE(struct lb6_backend);
	DECLARE(struct endpoint_key);
	DECLARE(struct endpoint_info);
	DECLARE(struct metrics_key);
	DECLARE(struct metrics_value);
	DECLARE(struct sock_key);
	DECLARE(struct policy_key);
	DECLARE(struct policy_entry);
	DECLARE(struct ipv4_nat_entry);
	DECLARE(struct ipv6_nat_entry);
	DECLARE(struct trace_notify);
	DECLARE(struct drop_notify);
	DECLARE(struct policy_verdict_notify);
	DECLARE(struct debug_msg);
	DECLARE(struct debug_capture_msg);
	DECLARE(struct ipv4_revnat_tuple);
	DECLARE(struct ipv4_revnat_entry);
	DECLARE(struct ipv6_revnat_tuple);
	DECLARE(struct ipv6_revnat_entry);
	DECLARE(struct ipv4_frag_id);
	DECLARE(struct ipv4_frag_l4ports);
	DECLARE(union macaddr);
	DECLARE(struct lb4_affinity_key);
	DECLARE(struct lb6_affinity_key);
	DECLARE(struct lb_affinity_val);
	DECLARE(struct lb_affinity_match);
	DECLARE(struct lb4_src_range_key);
	DECLARE(struct lb6_src_range_key);
	DECLARE(struct edt_id);
	DECLARE(struct edt_info);
	DECLARE(struct egress_gw_policy_key);
	DECLARE(struct egress_gw_policy_entry);
	DECLARE(struct vtep_key);
	DECLARE(struct vtep_value);
	DECLARE(struct capture4_wcard);
	DECLARE(struct capture6_wcard);
	DECLARE(struct capture_rule);
	DECLARE(struct srv6_vrf_key4);
	DECLARE(struct srv6_vrf_key6);
	DECLARE(struct srv6_policy_key4);
	DECLARE(struct srv6_policy_key6);

	return 0;
}
