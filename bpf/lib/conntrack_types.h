#pragma once

#include "common.h"
#include "ipfrag.h"

struct ct_entry {
	union {
		/* For CT_EGRESS entry: */
		union v6addr nat_addr;
		/* For CT_SERVICE entry: */
		struct {
			__u64 reserved0;	/* unused since v1.16 */
			__u64 backend_id;
		};
	};
	__u64 packets;
	__u64 bytes;
	__u32 lifetime;
	__u16 rx_closing:1,
	      tx_closing:1,
	      reserved1:1,	/* unused since v1.12 */
	      lb_loopback:1,
	      seen_non_syn:1,
	      node_port:1,
	      proxy_redirect:1,	/* Connection is redirected to a proxy */
	      dsr_internal:1,	/* DSR is k8s service related, cluster internal */
	      from_l7lb:1,	/* Connection is originated from an L7 LB proxy */
	      reserved2:1,	/* unused since v1.14 */
	      from_tunnel:1,	/* Connection is over tunnel */
	      reserved3:5;
	__u16 rev_nat_index;
	__be16 nat_port;	/* For CT_EGRESS entry. */

	/* *x_flags_seen represents the OR of all TCP flags seen for the
	 * transmit/receive direction of this entry.
	 */
	__u8  tx_flags_seen;
	__u8  rx_flags_seen;

	__u32 src_sec_id; /* Used from userspace proxies, do not change offset! */

	/* last_*x_report is a timestamp of the last time a monitor
	 * notification was sent for the transmit/receive direction.
	 */
	__u32 last_tx_report;
	__u32 last_rx_report;
};

struct ct_state {
	union v6addr nat_addr;
	__be16 nat_port;
	__u16 rev_nat_index;
	__u16 loopback:1,
	      node_port:1,
	      dsr_internal:1,   /* DSR is k8s service related, cluster internal */
	      syn:1,
	      proxy_redirect:1,	/* Connection is redirected to a proxy */
	      from_l7lb:1,	/* Connection is originated from an L7 LB proxy */
	      reserved1:1,	/* Was auth_required, not used in production anywhere */
	      from_tunnel:1,	/* Connection is from tunnel */
		  closing:1,
	      reserved:7;
	__u32 src_sec_id;
	__u32 backend_id;	/* Backend ID in lb4_backends */
};

struct ct_buffer4 {
	struct ipv4_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
	int l4_off;
};

struct ct_buffer6 {
	struct ipv6_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
	int l4_off;
	fraginfo_t fraginfo;
};
