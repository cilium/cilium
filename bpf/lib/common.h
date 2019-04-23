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
#ifndef __always_inline
#define __always_inline inline __inline__
#endif

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
#define CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY	11
#define CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY	12
#define CILIUM_CALL_IPV4_TO_ENDPOINT		13
#define CILIUM_CALL_IPV6_TO_ENDPOINT		14
#define CILIUM_CALL_SIZE			15

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

static inline bool validate_ethertype(struct __sk_buff *skb, __u16 *proto)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	if (data + ETH_HLEN > data_end)
		return false;

	struct ethhdr *eth = data;
	*proto = eth->h_proto;

	if (bpf_ntohs(*proto) < ETH_P_802_3_MIN)
		return false; // non-Ethernet II unsupported

	return true;
}

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
#define DROP_CT_CANT_CREATE_	-138 /* unused */
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_NO_TUNNEL_OPT_	-148 /* unused */
#define DROP_INVALID_GENEVE_	-149 /* unused */
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
#define DROP_UNSUPPORTED_L2		-166
#define DROP_NAT_NO_MAPPING	-167
#define DROP_NAT_UNSUPP_PROTO	-168

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
	skb->mark = skb->mark & MARK_MAGIC_KEY_MASK;
	skb->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);
}

/* We cap key index at 4 bits because mark value is used to map skb to key */
#define MAX_KEY_INDEX 15

/* encrypt_key is the index into the encrypt map */
struct encrypt_key {
	__u32 ctx;
} __attribute__((packed));

/* encrypt_config is the current encryption context on the node */
struct encrypt_config {
	__u8 encrypt_key;
} __attribute__((packed));

/**
 * or_encrypt_key - mask and shift key into encryption format
 */
static inline __u32 __inline__ or_encrypt_key(__u8 key)
{
	return (((__u32)key & 0x0F) << 12) | MARK_MAGIC_ENCRYPT;
}

/**
 * set_encrypt_key - pushes 8 bit key and encryption marker into skb mark value.
 */
static inline void __inline__ set_encrypt_key(struct __sk_buff *skb, __u8 key)
{
	skb->mark = or_encrypt_key(key);
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

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */
#define TUPLE_F_SERVICE		4	/* Flow represents service/slave map */

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
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic. */
	union v6addr	daddr;
	union v6addr	saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic. */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic. */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic. */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

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

struct lb6_key_v2 {
	union v6addr address;	/* Service virtual IPv6 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 pad[3];
};

/* See lb4_service_v2 comments */
struct lb6_service_v2 {
	__u32 backend_id;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
	__u16 pad;
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

struct lb4_key_v2 {
	__be32 address;		/* Service virtual IPv4 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
	__u8 proto;		/* L4 protocol, currently not used (set to 0) */
	__u8 pad[3];
};

struct lb4_service_v2 {
	__u32 backend_id;	/* Backend ID in lb4_backends */
	/* For the master service, count denotes number of service endpoints,
	 * while for any service endpoint, count contains a slave slot number
	 * in a corresponding legacy service which points to the same backend
	 * (used for the backward compatibility)
	 */
	__u16 count;
	__u16 rev_nat_index;	/* Reverse NAT ID in lb4_reverse_nat */
	__u16 weight;		/* Currently not used */
	__u16 pad;
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
	__u16 slave;		/* Slave slot number in a legacy service */
	__u16 backend_id;	/* Backend ID in lb4_backends */
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
