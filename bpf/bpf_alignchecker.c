// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#include "lib/common.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/trace.h"
#include "lib/policy_log.h"
#include "lib/pcap.h"
#include "lib/trace_sock.h"
#include "lib/mcast.h"
#include "lib/vtep.h"

/*
 * The __COUNTER__ macro expands to an integer value which is increasing every
 * time the macro is used.  Extra macros are required so that the __COUNTER__
 * value is actually expanded before concatenation with the _ prefix.  Thus,
 * the first occurrence of add_type(TYPE) will expand to "TYPE _0", the second
 * to "TYPE _1", etc.
 */
#define __add_type(TYPE, N) TYPE _ ## N
#define __expand(TYPE, N) __add_type(TYPE, N)
#define add_type(TYPE) __expand(TYPE, __COUNTER__)

add_type(struct ipv4_ct_tuple);
add_type(struct ipv6_ct_tuple);
add_type(struct ct_entry);
add_type(struct ipcache_key);
add_type(struct remote_endpoint_info);
add_type(struct lb4_key);
add_type(struct lb4_service);
add_type(struct lb4_backend);
add_type(struct lb6_key);
add_type(struct lb6_service);
add_type(struct lb6_backend);
add_type(struct endpoint_key);
add_type(struct endpoint_info);
add_type(struct metrics_key);
add_type(struct metrics_value);
add_type(struct policy_key);
add_type(struct policy_entry);
add_type(struct ipv4_nat_entry);
add_type(struct ipv6_nat_entry);
add_type(struct trace_notify);
add_type(struct drop_notify);
add_type(struct policy_verdict_notify);
add_type(struct debug_msg);
add_type(struct debug_capture_msg);
add_type(struct ipv4_revnat_tuple);
add_type(struct ipv4_revnat_entry);
add_type(struct ipv6_revnat_tuple);
add_type(struct ipv6_revnat_entry);
add_type(struct ipv4_frag_id);
add_type(struct ipv4_frag_l4ports);
add_type(struct ipv6_frag_id);
add_type(struct ipv6_frag_l4ports);
add_type(union macaddr);
add_type(struct lb4_affinity_key);
add_type(struct lb6_affinity_key);
add_type(struct lb_affinity_val);
add_type(struct lb_affinity_match);
add_type(struct lb4_src_range_key);
add_type(struct lb6_src_range_key);
add_type(struct edt_id);
add_type(struct edt_info);
add_type(struct egress_gw_policy_key);
add_type(struct egress_gw_policy_entry);
add_type(struct egress_gw_policy_key6);
add_type(struct egress_gw_policy_entry6);
add_type(struct vtep_key);
add_type(struct vtep_value);
add_type(struct capture4_wcard);
add_type(struct capture6_wcard);
add_type(struct capture_rule);
add_type(struct srv6_vrf_key4);
add_type(struct srv6_vrf_key6);
add_type(struct srv6_policy_key4);
add_type(struct srv6_policy_key6);
add_type(struct trace_sock_notify);
add_type(struct auth_key);
add_type(struct auth_info);
add_type(struct encrypt_config);
add_type(struct mcast_subscriber_v4);
add_type(struct node_key);
add_type(struct node_value);
add_type(struct skip_lb4_key);
add_type(struct skip_lb6_key);
