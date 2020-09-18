/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_COMMON_H_
#define __LIB_COMMON_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

#include "endian.h"
#include "mono.h"

/* FIXME: GH-3239 LRU logic is not handling timeouts gracefully enough
 * #ifndef HAVE_LRU_HASH_MAP_TYPE
 * #define NEEDS_TIMEOUT 1
 * #endif
 */
#define NEEDS_TIMEOUT 1

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#define PORT_UDP_VXLAN 4789
#define PORT_UDP_GENEVE 6081
#define PORT_UDP_VXLAN_LINUX 8472

#ifdef PREALLOCATE_MAPS
#define CONDITIONAL_PREALLOC 0
#else
#define CONDITIONAL_PREALLOC BPF_F_NO_PREALLOC
#endif

/* TODO: ipsec v6 tunnel datapath still needs separate fixing */
#ifndef ENABLE_IPSEC
# ifdef ENABLE_IPV6
#  define ENABLE_ENCAP_HOST_REMAP 1
# endif
#endif

/* XDP to SKB transferred meta data. */
#define XFER_PKT_NO_SVC		1 /* Skip upper service handling. */

/* These are shared with test/bpf/check-complexity.sh, when modifying any of
 * the below, that script should also be updated.
 */
#define CILIUM_CALL_DROP_NOTIFY			1
#define CILIUM_CALL_ERROR_NOTIFY		2
#define CILIUM_CALL_SEND_ICMP6_ECHO_REPLY	3
#define CILIUM_CALL_HANDLE_ICMP6_NS		4
#define CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED	5
#define CILIUM_CALL_ARP				6
#define CILIUM_CALL_IPV4_FROM_LXC		7
#define CILIUM_CALL_NAT64			8
#define CILIUM_CALL_NAT46			9
#define CILIUM_CALL_IPV6_FROM_LXC		10
#define CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY	11
#define CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY	12
#define CILIUM_CALL_IPV4_TO_ENDPOINT		13
#define CILIUM_CALL_IPV6_TO_ENDPOINT		14
#define CILIUM_CALL_IPV4_NODEPORT_NAT		15
#define CILIUM_CALL_IPV6_NODEPORT_NAT		16
#define CILIUM_CALL_IPV4_NODEPORT_REVNAT	17
#define CILIUM_CALL_IPV6_NODEPORT_REVNAT	18
#define CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT	19
#define CILIUM_CALL_IPV4_NODEPORT_DSR		20
#define CILIUM_CALL_IPV6_NODEPORT_DSR		21
#define CILIUM_CALL_IPV4_FROM_HOST		22
#define CILIUM_CALL_IPV6_FROM_HOST		23
#define CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT	24
#define CILIUM_CALL_SIZE			25

typedef __u64 mac_t;

union v6addr {
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	struct {
		__u64 d1;
		__u64 d2;
	};
	__u8 addr[16];
} __packed;

static __always_inline bool validate_ethertype(struct __ctx_buff *ctx,
					       __u16 *proto)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = data;

	if (data + ETH_HLEN > data_end)
		return false;
	*proto = eth->h_proto;
	if (bpf_ntohs(*proto) < ETH_P_802_3_MIN)
		return false; /* non-Ethernet II unsupported */
	return true;
}

static __always_inline __maybe_unused bool
__revalidate_data_pull(struct __ctx_buff *ctx, void **data_, void **data_end_,
		       void **l3, const __u32 l3_len, const bool pull)
{
	const __u32 tot_len = ETH_HLEN + l3_len;
	void *data_end;
	void *data;

	/* Verifier workaround, do this unconditionally: invalid size of register spill. */
	if (pull)
		ctx_pull_data(ctx, tot_len);
	data_end = ctx_data_end(ctx);
	data = ctx_data(ctx);
	if (data + tot_len > data_end)
		return false;

	/* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
	*data_ = data;
	*data_end_ = data_end;

	*l3 = data + ETH_HLEN;
	return true;
}

/* revalidate_data_pull() initializes the provided pointers from the ctx and
 * ensures that the data is pulled in for access. Should be used the first
 * time that the ctx data is accessed, subsequent calls can be made to
 * revalidate_data() which is cheaper.
 * Returns true if 'ctx' is long enough for an IP header of the provided type,
 * false otherwise.
 */
#define revalidate_data_pull(ctx, data, data_end, ip)			\
	__revalidate_data_pull(ctx, data, data_end, (void **)ip, sizeof(**ip), true)

/* revalidate_data_maybe_pull() does the same as revalidate_data_maybe_pull()
 * except that the skb data pull is controlled by the "pull" argument.
 */
#define revalidate_data_maybe_pull(ctx, data, data_end, ip, pull)	\
	__revalidate_data_pull(ctx, data, data_end, (void **)ip, sizeof(**ip), pull)


/* revalidate_data() initializes the provided pointers from the ctx.
 * Returns true if 'ctx' is long enough for an IP header of the provided type,
 * false otherwise.
 */
#define revalidate_data(ctx, data, data_end, ip)			\
	__revalidate_data_pull(ctx, data, data_end, (void **)ip, sizeof(**ip), false)

/* Macros for working with L3 cilium defined IPV6 addresses */
#define BPF_V6(dst, ...)	BPF_V6_1(dst, fetch_ipv6(__VA_ARGS__))
#define BPF_V6_1(dst, ...)	BPF_V6_4(dst, __VA_ARGS__)
#define BPF_V6_4(dst, a1, a2, a3, a4)		\
	({					\
		dst.p1 = a1;			\
		dst.p2 = a2;			\
		dst.p3 = a3;			\
		dst.p4 = a4;			\
	})

#define ENDPOINT_KEY_IPV4 1
#define ENDPOINT_KEY_IPV6 2

/* Structure representing an IPv4 or IPv6 address, being used for:
 *  - key as endpoints map
 *  - key for tunnel endpoint map
 *  - value for tunnel endpoint map
 */
struct endpoint_key {
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
	__u8 family;
	__u8 key;
	__u16 pad5;
} __packed;

#define ENDPOINT_F_HOST		1 /* Special endpoint representing local host */

/* Value of endpoint map */
struct endpoint_info {
	__u32		ifindex;
	__u16		unused; /* used to be sec_label, no longer used */
	__u16           lxc_id;
	__u32		flags;
	mac_t		mac;
	mac_t		node_mac;
	__u32		pad[4];
};

struct edt_id {
	__u64		id;
};

struct edt_info {
	__u64		bps;
	__u64		t_last;
	__u64		t_horizon_drop;
	__u64		pad[4];
};

struct remote_endpoint_info {
	__u32		sec_label;
	__u32		tunnel_endpoint;
	__u8		key;
};

struct policy_key {
	__u32		sec_label;
	__u16		dport;
	__u8		protocol;
	__u8		egress:1,
			pad:7;
};

struct policy_entry {
	__be16		proxy_port;
	__u16		pad0;
	__u16		pad1;
	__u16		pad2;
	__u64		packets;
	__u64		bytes;
};

struct metrics_key {
	__u8      reason;	/* 0: forwarded, >0 dropped */
	__u8      dir:2,	/* 1: ingress 2: egress */
		  pad:6;
	__u16     reserved[3];	/* reserved for future extension */
};


struct metrics_value {
	__u64	count;
	__u64	bytes;
};

enum {
	POLICY_INGRESS = 1,
	POLICY_EGRESS = 2,
};


enum {
	POLICY_MATCH_NONE = 0,
	POLICY_MATCH_L3_ONLY = 1,
	POLICY_MATCH_L3_L4 = 2,
	POLICY_MATCH_L4_ONLY = 3,
	POLICY_MATCH_ALL = 4,
};

enum {
	CILIUM_NOTIFY_UNSPEC,
	CILIUM_NOTIFY_DROP,
	CILIUM_NOTIFY_DBG_MSG,
	CILIUM_NOTIFY_DBG_CAPTURE,
	CILIUM_NOTIFY_TRACE,
	CILIUM_NOTIFY_POLICY_VERDICT,
};

#define NOTIFY_COMMON_HDR \
	__u8		type;		\
	__u8		subtype;	\
	__u16		source;		\
	__u32		hash;

#define NOTIFY_CAPTURE_HDR \
	NOTIFY_COMMON_HDR						\
	__u32		len_orig;	/* Length of original packet */	\
	__u16		len_cap;	/* Length of captured bytes */	\
	__u16		version;	/* Capture header version */

#define __notify_common_hdr(t, s)	\
	.type		= (t),		\
	.subtype	= (s),		\
	.source		= EVENT_SOURCE,	\
	.hash		= get_hash_recalc(ctx)

#define __notify_pktcap_hdr(o, c)	\
	.len_orig	= (o),		\
	.len_cap	= (c),		\
	.version	= NOTIFY_CAPTURE_VER

/* Capture notifications version. Must be incremented when format changes. */
#define NOTIFY_CAPTURE_VER 1

#ifndef TRACE_PAYLOAD_LEN
#define TRACE_PAYLOAD_LEN 128ULL
#endif

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define IS_ERR(x) (unlikely((x < 0) || (x == CTX_ACT_DROP)))

/* Cilium IPSec code to indicate packet needs to be handled
 * by IPSec stack. Maps to CTX_ACT_OK.
 */
#define IPSEC_ENDPOINT CTX_ACT_OK

/* Return value to indicate that proxy redirection is required */
#define POLICY_ACT_PROXY_REDIRECT (1 << 16)

/* Cilium error codes, must NOT overlap with TC return codes.
 * These also serve as drop reasons for metrics,
 * where reason > 0 corresponds to -(DROP_*)
 */
#define DROP_UNUSED1		-130 /* unused */
#define DROP_UNUSED2		-131 /* unused */
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_UNUSED3		-136 /* unused */
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_UNUSED4		-138 /* unused */
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_UNUSED5		-148 /* unused */
#define DROP_UNUSED6		-149 /* unused */
#define DROP_UNKNOWN_TARGET	-150
#define DROP_UNROUTABLE		-151
#define DROP_UNUSED7		-152 /* unused */
#define DROP_CSUM_L3		-153
#define DROP_CSUM_L4		-154
#define DROP_CT_CREATE_FAILED	-155
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157
#define DROP_NO_SERVICE		-158
#define DROP_UNUSED8		-159 /* unused */
#define DROP_NO_TUNNEL_ENDPOINT -160
#define DROP_UNUSED9		-161 /* unused */
#define DROP_EDT_HORIZON	-162
#define DROP_UNKNOWN_CT		-163
#define DROP_HOST_UNREACHABLE	-164
#define DROP_NO_CONFIG		-165
#define DROP_UNSUPPORTED_L2	-166
#define DROP_NAT_NO_MAPPING	-167
#define DROP_NAT_UNSUPP_PROTO	-168
#define DROP_NO_FIB		-169
#define DROP_ENCAP_PROHIBITED	-170
#define DROP_INVALID_IDENTITY	-171
#define DROP_UNKNOWN_SENDER	-172
#define DROP_NAT_NOT_NEEDED	-173 /* Mapped as drop code, though drop not necessary. */
#define DROP_IS_CLUSTER_IP	-174
#define DROP_FRAG_NOT_FOUND	-175
#define DROP_FORBIDDEN_ICMP6	-176
#define DROP_NOT_IN_SRC_RANGE	-177
#define DROP_PROXY_LOOKUP_FAILED	-178
#define DROP_PROXY_SET_FAILED	-179
#define DROP_PROXY_UNKNOWN_PROTO	-180

#define NAT_PUNT_TO_STACK	DROP_NAT_NOT_NEEDED

/* Cilium metrics reasons for forwarding packets and other stats.
 * If reason is larger than below then this is a drop reason and
 * value corresponds to -(DROP_*), see above.
 */
#define REASON_FORWARDED		0
#define REASON_PLAINTEXT		3
#define REASON_DECRYPT			4
#define REASON_LB_NO_BACKEND_SLOT	5
#define REASON_LB_NO_BACKEND		6
#define REASON_LB_REVNAT_UPDATE		7
#define REASON_LB_REVNAT_STALE		8

/* Lookup scope for externalTrafficPolicy=Local */
#define LB_LOOKUP_SCOPE_EXT	0
#define LB_LOOKUP_SCOPE_INT	1

/* Cilium metrics direction for dropping/forwarding packet */
#define METRIC_INGRESS  1
#define METRIC_EGRESS   2

/* Magic ctx->mark identifies packets origination and encryption status.
 *
 * The upper 16 bits plus lower 8 bits (e.g. mask 0XFFFF00FF) contain the
 * packets security identity. The lower/upper halves are swapped to recover
 * the identity.
 *
 * The 4 bits at 0X0F00 provide
 *  - the magic marker values which indicate whether the packet is coming from
 *    an ingress or egress proxy, a local process and its current encryption
 *    status.
 *
 * The 4 bits at 0xF000 provide
 *  - the key index to use for encryption when multiple keys are in-flight.
 *    In the IPsec case this becomes the SPI on the wire.
 */
#define MARK_MAGIC_HOST_MASK		0x0F00
#define MARK_MAGIC_PROXY_INGRESS	0x0A00
#define MARK_MAGIC_PROXY_EGRESS		0x0B00
#define MARK_MAGIC_HOST			0x0C00
#define MARK_MAGIC_DECRYPT		0x0D00
#define MARK_MAGIC_ENCRYPT		0x0E00
#define MARK_MAGIC_IDENTITY		0x0F00 /* mark carries identity */
#define MARK_MAGIC_TO_PROXY		0x0200

#define MARK_MAGIC_KEY_ID		0xF000
#define MARK_MAGIC_KEY_MASK		0xFF00

/* IPSec cannot be configured with NodePort BPF today, hence non-conflicting
 * overlap with MARK_MAGIC_KEY_ID.
 */
#define MARK_MAGIC_SNAT_DONE		0x1500

/* IPv4 option used to carry service addr and port for DSR. Lower 16bits set to
 * zero so that they can be OR'd with service port.
 *
 * Copy = 1 (option is copied to each fragment)
 * Class = 0 (control option)
 * Number = 26 (not used according to [1])
 * Len = 8 (option type (1) + option len (1) + addr (4) + port (2))
 *
 * [1]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
 */
#define DSR_IPV4_OPT_32		0x9a080000
#define DSR_IPV4_OPT_MASK	0xffff0000
#define DSR_IPV4_DPORT_MASK	0x0000ffff

/* IPv6 option type of Destination Option used to carry service IPv6 addr and
 * port for DSR.
 *
 * 0b00		- "skip over this option and continue processing the header"
 *     0	- "Option Data does not change en-route"
 *      11011   - Unassigned [1]
 *
 * [1]:  https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
 */
#define DSR_IPV6_OPT_TYPE	0x1B
#define DSR_IPV6_OPT_LEN	0x14	/* to store ipv6 addr + port */
#define DSR_IPV6_EXT_LEN	0x2	/* = (sizeof(dsr_opt_v6) - 8) / 8 */

/* We cap key index at 4 bits because mark value is used to map ctx to key */
#define MAX_KEY_INDEX 15

/* encrypt_key is the index into the encrypt map */
struct encrypt_key {
	__u32 ctx;
} __packed;

/* encrypt_config is the current encryption context on the node */
struct encrypt_config {
	__u8 encrypt_key;
} __packed;

/**
 * or_encrypt_key - mask and shift key into encryption format
 */
static __always_inline __u32 or_encrypt_key(__u8 key)
{
	return (((__u32)key & 0x0F) << 12) | MARK_MAGIC_ENCRYPT;
}

/*
 * ctx->tc_index uses
 *
 * cilium_host @egress
 *   bpf_host -> bpf_lxc
 */
#define TC_INDEX_F_SKIP_INGRESS_PROXY	1
#define TC_INDEX_F_SKIP_EGRESS_PROXY	2
#define TC_INDEX_F_SKIP_NODEPORT	4
#define TC_INDEX_F_SKIP_RECIRCULATION	8
#define TC_INDEX_F_SKIP_HOST_FIREWALL	16

/* ctx_{load,store}_meta() usage: */
enum {
	CB_SRC_LABEL,
#define	CB_SVC_PORT		CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_PROXY_MAGIC		CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_ENCRYPT_MAGIC	CB_SRC_LABEL	/* Alias, non-overlapping */
	CB_IFINDEX,
#define	CB_SVC_ADDR_V4		CB_IFINDEX	/* Alias, non-overlapping */
#define	CB_SVC_ADDR_V6_1	CB_IFINDEX	/* Alias, non-overlapping */
#define	CB_ENCRYPT_IDENTITY	CB_IFINDEX	/* Alias, non-overlapping */
#define	CB_IPCACHE_SRC_LABEL	CB_IFINDEX	/* Alias, non-overlapping */
	CB_POLICY,
#define	CB_SVC_ADDR_V6_2	CB_POLICY	/* Alias, non-overlapping */
	CB_NAT46_STATE,
#define CB_NAT			CB_NAT46_STATE	/* Alias, non-overlapping */
#define	CB_SVC_ADDR_V6_3	CB_NAT46_STATE	/* Alias, non-overlapping */
#define	CB_FROM_HOST		CB_NAT46_STATE	/* Alias, non-overlapping */
	CB_CT_STATE,
#define	CB_SVC_ADDR_V6_4	CB_CT_STATE	/* Alias, non-overlapping */
#define	CB_ENCRYPT_DST		CB_CT_STATE	/* Alias, non-overlapping,
						 * Not used by xfrm.
						 */
};

/* State values for NAT46 */
enum {
	NAT46_CLEAR,
	NAT64,
	NAT46,
};

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */
#define TUPLE_F_SERVICE		4	/* Flow represents packets to service */

#define CT_EGRESS 0
#define CT_INGRESS 1
#define CT_SERVICE 2

#ifdef ENABLE_NODEPORT
#define NAT_MIN_EGRESS		NODEPORT_PORT_MIN_NAT
#else
#define NAT_MIN_EGRESS		EPHEMERAL_MIN
#endif

enum {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
};

/* Service flags (lb{4,6}_service->flags) */
enum {
	SVC_FLAG_EXTERNAL_IP  = (1 << 0),  /* External IPs */
	SVC_FLAG_NODEPORT     = (1 << 1),  /* NodePort service */
	SVC_FLAG_LOCAL_SCOPE  = (1 << 2),  /* externalTrafficPolicy=Local */
	SVC_FLAG_HOSTPORT     = (1 << 3),  /* hostPort forwarding */
	SVC_FLAG_AFFINITY     = (1 << 4),  /* sessionAffinity=clientIP */
	SVC_FLAG_LOADBALANCER = (1 << 5),  /* LoadBalancer service */
	SVC_FLAG_ROUTABLE     = (1 << 6),  /* Not a surrogate/ClusterIP entry */
	SVC_FLAG_SOURCE_RANGE = (1 << 7),  /* Check LoadBalancer source range */
};

struct ipv6_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	union v6addr	daddr;
	union v6addr	saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

struct ct_entry {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u32 lifetime;
	__u16 rx_closing:1,
	      tx_closing:1,
	      nat46:1,
	      lb_loopback:1,
	      seen_non_syn:1,
	      node_port:1,
	      proxy_redirect:1, /* Connection is redirected to a proxy */
	      dsr:1,
	      reserved:8;
	__u16 rev_nat_index;
	/* In the kernel ifindex is u32, so we need to check in cilium-agent
	 * that ifindex of a NodePort device is <= MAX(u16).
	 */
	__u16 ifindex;

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

struct lb6_key {
	union v6addr address;	/* Service virtual IPv6 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 backend_slot;	/* Backend iterator, 0 indicates the svc frontend */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 scope;		/* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
	__u8 pad[2];
};

/* See lb4_service comments */
struct lb6_service {
	union {
		__u32 backend_id;	/* Backend ID in lb6_backends */
		__u32 affinity_timeout;	/* In seconds, only for svc frontend */
	};
	__u16 count;
	__u16 rev_nat_index;
	__u8 flags;
	__u8 pad[3];
};

/* See lb4_backend comments */
struct lb6_backend {
	union v6addr address;
	__be16 port;
	__u8 proto;
	__u8 pad;
};

struct lb6_reverse_nat {
	union v6addr address;
	__be16 port;
} __packed;

struct ipv6_revnat_tuple {
	__u64 cookie;
	union v6addr address;
	__be16 port;
	__u16 pad;
};

struct ipv6_revnat_entry {
	union v6addr address;
	__be16 port;
	__u16 rev_nat_index;
};

struct lb4_key {
	__be32 address;		/* Service virtual IPv4 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 backend_slot;	/* Backend iterator, 0 indicates the svc frontend */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 scope;		/* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
	__u8 pad[2];
};

struct lb4_service {
	union {
		__u32 backend_id;		/* Backend ID in lb4_backends */
		__u32 affinity_timeout;		/* In seconds, only for svc frontend */
	};
	/* For the service frontend, count denotes number of service backend
	 * slots (otherwise zero).
	 */
	__u16 count;
	__u16 rev_nat_index;	/* Reverse NAT ID in lb4_reverse_nat */
	__u8 flags;
	__u8 pad[3];
};

struct lb4_backend {
	__be32 address;		/* Service endpoint IPv4 address */
	__be16 port;		/* L4 port filter */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 pad;
};

struct lb4_reverse_nat {
	__be32 address;
	__be16 port;
} __packed;

struct ipv4_revnat_tuple {
	__u64 cookie;
	__be32 address;
	__be16 port;
	__u16 pad;
};

struct ipv4_revnat_entry {
	__be32 address;
	__be16 port;
	__u16 rev_nat_index;
};

union lb4_affinity_client_id {
	__u32 client_ip;
	__u64 client_cookie; /* netns cookie */
} __packed;

struct lb4_affinity_key {
	union lb4_affinity_client_id client_id;
	__u16 rev_nat_id;
	__u8 netns_cookie:1,
	     reserved:7;
	__u8 pad1;
	__u32 pad2;
} __packed;

union lb6_affinity_client_id {
	union v6addr client_ip;
	__u64 client_cookie; /* netns cookie */
} __packed;

struct lb6_affinity_key {
	union lb6_affinity_client_id client_id;
	__u16 rev_nat_id;
	__u8 netns_cookie:1,
	     reserved:7;
	__u8 pad1;
	__u32 pad2;
} __packed;

struct lb_affinity_val {
	__u64 last_used;
	__u32 backend_id;
	__u32 pad;
} __packed;

struct lb_affinity_match {
	__u32 backend_id;
	__u16 rev_nat_id;
	__u16 pad;
} __packed;

struct ct_state {
	__u16 rev_nat_index;
	__u16 loopback:1,
	      node_port:1,
	      proxy_redirect:1, /* Connection is redirected to a proxy */
	      dsr:1,
	      reserved:12;
	__be32 addr;
	__be32 svc_addr;
	__u32 src_sec_id;
	__u16 ifindex;
	__u16 backend_id;	/* Backend ID in lb4_backends */
};

#define SRC_RANGE_STATIC_PREFIX(STRUCT)		\
	(8 * (sizeof(STRUCT) - sizeof(struct bpf_lpm_trie_key)))

struct lb4_src_range_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 rev_nat_id;
	__u16 pad;
	__u32 addr;
};

struct lb6_src_range_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 rev_nat_id;
	__u16 pad;
	union v6addr addr;
};

static __always_inline int redirect_peer(int ifindex __maybe_unused,
					 __u32 flags __maybe_unused)
{
	/* If our datapath has proper redirect support, we make use
	 * of it here, otherwise we terminate tc processing by letting
	 * stack handle forwarding e.g. in ipvlan case.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return redirect(ifindex, flags);
#else
	return CTX_ACT_OK;
#endif /* ENABLE_HOST_REDIRECT */
}

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct lpm_v6_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[16];
};

struct lpm_val {
	/* Just dummy for now. */
	__u8 flags;
};

#include "overloadable.h"

#endif /* __LIB_COMMON_H_ */
