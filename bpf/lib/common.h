/*
 *  Copyright (C) 2016-2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_COMMON_H_
#define __LIB_COMMON_H_

#include <bpf_features.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <stdint.h>
#include <stdbool.h>

// FIXME: GH-3239 LRU logic is not handling timeouts gracefully enough
// #ifndef HAVE_LRU_MAP_TYPE
// #define NEEDS_TIMEOUT 1
// #endif
#define NEEDS_TIMEOUT 1

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#ifdef PREALLOCATE_MAPS
#define CONDITIONAL_PREALLOC 0
#else
#define CONDITIONAL_PREALLOC BPF_F_NO_PREALLOC
#endif

#define __inline__ __attribute__((always_inline))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* These are shared with test/bpf/check-complexity.sh, when modifying any of
 * the below, that script should also be updated. */
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
#define CILIUM_CALL_IPV4_TO_LXC			11
#define CILIUM_CALL_IPV6_TO_LXC			12
#define CILIUM_CALL_SIZE			13

typedef __u64 mac_t;

union v6addr {
        struct {
                __u32 p1;
                __u32 p2;
                __u32 p3;
                __u32 p4;
        };
        __u8 addr[16];
};

static inline bool __revalidate_data(struct __sk_buff *skb, void **data_,
				     void **data_end_, void **l3,
				     size_t l3_len)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	if (data + ETH_HLEN + l3_len > data_end)
		return false;

	*data_ = data;
	*data_end_ = data_end;
	*l3 = data + ETH_HLEN;
	return true;
}

/* revalidate_data() initializes the provided pointers from the skb.
 * Returns true if 'skb' is long enough for an IP header of the provided type,
 * false otherwise. */
#define revalidate_data(skb, data, data_end, ip)	\
	__revalidate_data(skb, data, data_end, (void **)ip, sizeof(**ip))

/* Macros for working with L3 cilium defined IPV6 addresses */
#define BPF_V6(dst, ...)	BPF_V6_16(dst, __VA_ARGS__)
#define BPF_V6_16(dst, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) \
	({										\
		dst.p1 = bpf_htonl( (a1) << 24 |  (a2) << 16 |  (a3) << 8 |  (a4));	\
		dst.p2 = bpf_htonl( (a5) << 24 |  (a6) << 16 |  (a7) << 8 |  (a8));	\
		dst.p3 = bpf_htonl( (a9) << 24 | (a10) << 16 | (a11) << 8 | (a12));	\
		dst.p4 = bpf_htonl((a13) << 24 | (a14) << 16 | (a15) << 8 | (a16));	\
	})

/* Macros for building proxy port/nexthdr maps */
#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0 (EVAL0 (EVAL0 (__VA_ARGS__)))
#define EVAL2(...) EVAL1 (EVAL1 (EVAL1 (__VA_ARGS__)))
#define EVAL(...)  EVAL2 (EVAL2 (EVAL2 (__VA_ARGS__)))

#define BPF_L4_MAP_OUT
#define BPF_L4_MAP_END(...)
#define BPF_L4_MAP_GET_END() 0, BPF_L4_MAP_END
#define BPF_L4_MAP_NEXT0(dst, port, hdr, index, map, next, ...) next BPF_L4_MAP_OUT
#define BPF_L4_MAP_NEXT1(dst, port, hdr, index, map, next) BPF_L4_MAP_NEXT0(dst, port, hdr, index, map, next, 0)
#define BPF_L4_MAP_NEXT(dst, port, hdr, index, map, next) BPF_L4_MAP_NEXT1 (dst, port, hdr, index, BPF_L4_MAP_GET_END map, next)

#define F(dst, port, hdr, index, map0, map1, map2)				\
	({									\
		dst = (dst > -1 ? dst : ((map0 && map0 == port) ?		\
			((map2 && map2 == hdr) ? map1 : DROP_POLICY_L4) :	\
			DROP_POLICY_L4));					\
	});

#define BPF_L4_MAP0(dst, port, hdr, index, map0, map1, map2, next, ...) \
	F(dst, port, hdr, index, map0, map1, map2) BPF_L4_MAP_NEXT(dst, port, hdr, index, next, BPF_L4_MAP1)(dst, port, hdr, next, __VA_ARGS__)
#define BPF_L4_MAP1(dst, port, hdr, index, map0, map1, map2, next, ...) \
	F(dst, port, hdr, index, map0, map1, map2) BPF_L4_MAP_NEXT(dst, port, hdr, index, next, BPF_L4_MAP0)(dst, port, hdr, next, __VA_ARGS__)

#define BPF_L4_MAP(dst, port, hdr, ...)				\
	({							\
		EVAL (BPF_L4_MAP1(dst, port, hdr, __VA_ARGS__))	\
	})

/* Examples to illustrate how to use BPF_L4_MAP and BPF_V6_16
 *
 * BPF_L4_MAP(my_map, 0, 80, 8080, 0, 1, 80, 8080, 0, (), 0)
 * BPF_V6_16(my_dst, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
 */

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
	__u8 pad4;
	__u16 pad5;
} __attribute__((packed));

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

struct remote_endpoint_info {
	__u32		sec_label;
	__u32		tunnel_endpoint;
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
	__u16		pad[3];
	__u64		packets;
	__u64		bytes;
};

struct metrics_key {
    __u8      reason;     //0: forwarded, >0 dropped
    __u8      dir:2,      //1: ingress 2: egress
              pad:6;
    __u16     reserved[3]; // reserved for future extension
};


struct metrics_value {
     __u64	count;
     __u64	bytes;
};


enum {
	CILIUM_NOTIFY_UNSPEC,
	CILIUM_NOTIFY_DROP,
	CILIUM_NOTIFY_DBG_MSG,
	CILIUM_NOTIFY_DBG_CAPTURE,
	CILIUM_NOTIFY_TRACE,
};

#define NOTIFY_COMMON_HDR \
	__u8		type; \
	__u8		subtype; \
	__u16		source; \
	__u32		hash;

#ifndef TRACE_PAYLOAD_LEN
#define TRACE_PAYLOAD_LEN 128ULL
#endif

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define IS_ERR(x) (unlikely((x < 0) || (x == TC_ACT_SHOT)))

/* Cilium IPSec code to indicate packet needs to be handled
 * by IPSec stack. Maps to TC_ACT_OK.
 */
#define IPSEC_ENDPOINT TC_ACT_OK

/* Cilium error codes, must NOT overlap with TC return codes.
 * These also serve as drop reasons for metrics,
 * where reason > 0 corresponds to -(DROP_*)
 */
#define DROP_INVALID_SMAC	-130
#define DROP_INVALID_DMAC	-131
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_CT_MISSING_ACK	-136
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_PROXY_INVALID	-138
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_NO_TUNNEL_OPT	-148 /* unused */
#define DROP_INVALID_GENEVE	-149 /* unused */
#define DROP_UNKNOWN_TARGET	-150
#define DROP_NON_LOCAL		-151
#define DROP_NO_LXC		-152
#define DROP_CSUM_L3		-153
#define DROP_CSUM_L4		-154
#define DROP_CT_CREATE_FAILED	-155
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157
#define DROP_NO_SERVICE		-158
#define DROP_POLICY_L4		-159
#define DROP_NO_TUNNEL_ENDPOINT -160
#define DROP_PROXYMAP_CREATE_FAILED_	-161 /* unused */
#define DROP_POLICY_CIDR		-162
#define DROP_UNKNOWN_CT			-163
#define DROP_HOST_UNREACHABLE		-164
#define DROP_NO_CONFIG		-165

/* Cilium metrics reason for forwarding packet.
 * If reason > 0 then this is a drop reason and value corresponds to -(DROP_*)
 */
#define REASON_FORWARDED  0

/* Cilium metrics direction for dropping/forwarding packet */
#define METRIC_INGRESS  1
#define METRIC_EGRESS   2

/* Magic skb->mark identifies packets origination and encryption status.
 *
 * The upper 16 bits plus lower 8 bits (e.g. mask 0XFFFF00FF) contain the
 * packets security identity. The lower/upper halves are swapped to recover
 * the identity.
 *
 * The 4 bits at 0XF00 provide
 *  - the magic marker values which indicate whether the packet is coming from
 *    an ingress or egress proxy, a local process and its current encryption
 *    status.
 */
#define MARK_MAGIC_HOST_MASK		0xF00
#define MARK_MAGIC_PROXY_INGRESS	0xA00
#define MARK_MAGIC_PROXY_EGRESS		0xB00
#define MARK_MAGIC_HOST			0xC00
#define MARK_MAGIC_DECRYPT		0xD00
#define MARK_MAGIC_ENCRYPT		0xE00
#define MARK_MAGIC_TO_PROXY		0x200

/**
 * get_identity - returns source identity from the mark field
 */
static inline int __inline__ get_identity(struct __sk_buff *skb)
{
	return ((skb->mark & 0xFF) << 16) | skb->mark >> 16;
}

/**
 * set_identity - pushes 24 bit identity into skb mark value.
 */
static inline void __inline__ set_identity(struct __sk_buff *skb, __u32 identity)
{
	skb->mark = skb->mark & MARK_MAGIC_HOST_MASK;
	skb->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);
}

/*
 * skb->tc_index uses
 *
 * cilium_host @egress
 *   bpf_host -> bpf_lxc
 */
#define TC_INDEX_F_SKIP_PROXY		1

/* skb->cb[] usage: */
enum {
	CB_SRC_LABEL,
	CB_IFINDEX,
	CB_POLICY,
	CB_NAT46_STATE,
	CB_CT_STATE,
};

/* State values for NAT46 */
enum {
	NAT46_CLEAR,
	NAT64,
	NAT46,
};

#define CT_EGRESS 0
#define CT_INGRESS 1
#define CT_SERVICE 2

enum {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
};

struct ipv6_ct_tuple {
	union v6addr	daddr;
	union v6addr	saddr;
	/* The order of dport+sport must not be changed */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

static inline union v6addr *
ipv6_ct_tuple_get_daddr(struct ipv6_ct_tuple *tuple)
{
#ifdef CONNTRACK
	/* For outgoing connections, lib/conntrack.h swaps the src/dst. */
	return &tuple->saddr;
#else
	return &tuple->daddr;
#endif
}

struct ipv4_ct_tuple {
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

static inline __be32
ipv4_ct_tuple_get_daddr(struct ipv4_ct_tuple *tuple)
{
#ifdef CONNTRACK
	/* For outgoing connections, lib/conntrack.h swaps the src/dst. */
	return tuple->saddr;
#else
	return tuple->daddr;
#endif
}

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
	      reserve:11;
	__u16 rev_nat_index;
	__u16 slave;

	/* *x_flags_seen represents the OR of all TCP flags seen for the
	 * transmit/receive direction of this entry. */
	__u8  tx_flags_seen;
	__u8  rx_flags_seen;

	__u32 src_sec_id; /* Used from userspace proxies, do not change offset! */

	/* last_*x_report is a timestamp of the last time a monitor
	 * notification was sent for the transmit/receive direction. */
	__u32 last_tx_report;
	__u32 last_rx_report;
};

struct lb6_key {
        union v6addr address;
        __be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
} __attribute__((packed));

struct lb6_service {
	union v6addr target;
	__be16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
} __attribute__((packed));

struct lb6_reverse_nat {
	union v6addr address;
	__be16 port;
} __attribute__((packed));

struct lb4_key {
	__be32 address;
        __be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
} __attribute__((packed));

struct lb4_service {
	__be32 target;
	__be16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
} __attribute__((packed));

struct lb4_reverse_nat {
	__be32 address;
	__be16 port;
} __attribute__((packed));

// LB_RR_MAX_SEQ generated by daemon in node_config.h
struct lb_sequence {
	__u16 count;
	__u16 idx[LB_RR_MAX_SEQ];
};

struct ct_state {
	__u16 rev_nat_index;
	__u16 loopback:1,
	      reserved:15;
	__be16 orig_dport;
	__be32 addr;
	__be32 svc_addr;
	__u32 src_sec_id;
	__u16 slave;
};

/* ep_config corresponds to the EndpointConfig object in pkg/maps/configmap. */
struct ep_config {
	__u32 flags; /* enum ep_cfg_flag */
	__be32 ipv4Addr;
	union v6addr ipv6Addr;
	mac_t node_mac;
	__u16 lxc_id;
	__be16 lxc_id_nb;
	__u32 identity;
	__be32 identity_nb;
	__u32 pad;
} __attribute__((packed));

/**
 * relax_verifier is a dummy helper call to introduce a pruning checkpoing to
 * help relax the verifier to avoid reaching complexity limits on older
 * kernels.
 */
static inline void relax_verifier(void)
{
	int foo = 0;
	csum_diff(0, 0, &foo, 1, 0);
}

static inline int redirect_self(struct __sk_buff *skb)
{
	/* Looping back the packet into the originating netns. In
	 * case of veth, it's xmit'ing into the hosts' veth device
	 * such that we end up on ingress in the peer. For ipvlan
	 * slave it's redirect to ingress as we are attached on the
	 * slave in netns already.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return redirect(skb->ifindex, 0);
#else
	return redirect(skb->ifindex, BPF_F_INGRESS);
#endif
}

static inline int redirect_peer(int ifindex, uint32_t flags)
{
	/* If our datapath has proper redirect support, we make use
	 * of it here, otherwise we terminate tc processing by letting
	 * stack handle forwarding e.g. in ipvlan case.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return redirect(ifindex, flags);
#else
	return TC_ACT_OK;
#endif /* ENABLE_HOST_REDIRECT */
}

#endif
