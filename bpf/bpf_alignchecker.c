// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY
#define POLICY_VERDICT_NOTIFY
#define ENABLE_CAPTURE
#define TRACE_SOCK_NOTIFY

#include <bpf/ctx/unspec.h>

#include "node_config.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "sockops/bpf_sockops.h"
#include "lib/nat.h"
#include "lib/trace.h"
#include "lib/policy_log.h"
#include "lib/pcap.h"
#include "lib/trace_sock.h"

struct ipv4_ct_tuple _1;
struct ipv6_ct_tuple _2;
struct ct_entry _3;
struct ipcache_key _4;
struct remote_endpoint_info _5;
struct lb4_key st6;
struct lb4_service _7;
struct lb4_backend _8;
struct lb6_key _9;
struct lb6_service _10;
struct lb6_backend _11;
struct endpoint_key _12;
struct endpoint_info _13;
struct metrics_key _14;
struct metrics_value _15;
struct sock_key _16;
struct policy_key _17;
struct policy_entry _18;
struct ipv4_nat_entry _19;
struct ipv6_nat_entry _20;
struct trace_notify _21;
struct drop_notify _22;
struct policy_verdict_notify _23;
struct debug_msg _24;
struct debug_capture_msg _25;
struct ipv4_revnat_tuple _26;
struct ipv4_revnat_entry _27;
struct ipv6_revnat_tuple _28;
struct ipv6_revnat_entry _29;
struct ipv4_frag_id _30;
struct ipv4_frag_l4ports _31;
union macaddr _32;
struct lb4_affinity_key _33;
struct lb6_affinity_key _34;
struct lb_affinity_val _35;
struct lb_affinity_match _36;
struct lb4_src_range_key _37;
struct lb6_src_range_key _38;
struct edt_id _39;
struct edt_info _40;
struct egress_gw_policy_key _41;
struct egress_gw_policy_entry _42;
struct vtep_key _43;
struct vtep_value _44;
struct capture4_wcard _45;
struct capture6_wcard _46;
struct capture_rule _47;
struct srv6_vrf_key4 _48;
struct srv6_vrf_key6 _49;
struct srv6_policy_key4 _50;
struct srv6_policy_key6 _51;
struct trace_sock_notify _52;
struct tunnel_key _53;
struct tunnel_value _54;
struct auth_key _55;
struct auth_info _56;
