/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#include <linux/ipv6.h>
#include <linux/in.h>
#include <stdint.h>

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#define POLICY_MAP_SIZE	65536
#define RESERVED_POLICY_SIZE 128

#define __inline__ __attribute__((always_inline))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define CILIUM_CALL_DROP_NOTIFY			1
#define CILIUM_CALL_ERROR_NOTIFY		2
#define CILIUM_CALL_SEND_ICMP6_ECHO_REPLY	3
#define CILIUM_CALL_HANDLE_ICMP6_NS		4
#define CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED	5
#define CILIUM_CALL_ARP				6
#define CILIUM_CALL_IPV4			7
#define CILIUM_CALL_NAT64			8
#define CILIUM_CALL_NAT46			9
#define CILIUM_CALL_SIZE			10

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

#define PORTMAP_MAX 16

struct portmap {
	__u16 from;
	__u16 to;
};

struct lxc_info {
	__u32		ifindex;
	__u16		sec_label;
	__u16           lxc_id;
	mac_t		mac;
	mac_t		node_mac;
	union v6addr	ip;
	struct portmap  portmap[PORTMAP_MAX];
};

struct policy_entry {
	__u32		action;
	__u32		pad;
	__u64		packets;
	__u64		bytes;
};

enum {
	CILIUM_NOTIFY_UNSPEC,
	CILIUM_NOTIFY_DROP,
	CILIUM_NOTIFY_DBG_MSG,
	CILIUM_NOTIFY_DBG_CAPTURE,
};

#define NOTIFY_COMMON_HDR \
	__u8		type; \
	__u8		subtype; \
	__u16		source; \
	__u32		hash;

struct drop_notify {
	NOTIFY_COMMON_HDR
	__u32		len_orig;
	__u32		len_cap;
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		ifindex;
};

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define IS_ERR(x) (unlikely((x < 0) || (x == TC_ACT_SHOT)))

/* Cilium error codes, must NOT overlap with TC return codes */
#define DROP_INVALID_SMAC	-130
#define DROP_INVALID_DMAC	-131
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_CT_MISSING_ACK	-136
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_CT_CANT_CREATE	-138
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_NO_TUNNEL_OPT	-148
#define DROP_INVALID_GENEVE	-149
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

struct ipv6_ct_tuple {
#ifdef CONNTRACK_LOCAL
	union v6addr	addr;
#else
	union v6addr	daddr;
	union v6addr	saddr;
#endif
	/* The order of dport+sport must not be changed */
	__u16		dport;
	__u16		sport;
	__u8		nexthdr;
	__u8		flags;
};

struct ipv4_ct_tuple {
#ifdef CONNTRACK_LOCAL
	__be32		addr;
#else
	__be32		daddr;
	__be32		saddr;
#endif
	/* The order of dport+sport must not be changed */
	__u16		dport;
	__u16		sport;
	__u8		nexthdr;
	__u8		flags;
} __attribute__((packed));

struct ct_entry {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u16 lifetime;
	__u16 rx_closing:1,
	      tx_closing:1,
	      nat46:1,
	      lb_loopback:1,
	      reserve:12;
	__u16 rev_nat_index;
	__u16 proxy_port;
};

struct lb6_key {
        union v6addr address;
        __u16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
} __attribute__((packed));

struct lb6_service {
	union v6addr target;
	__u16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
} __attribute__((packed));

struct lb6_reverse_nat {
	union v6addr address;
	__u16 port;
} __attribute__((packed));

struct lb4_key {
	__be32 address;
        __u16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
} __attribute__((packed));

struct lb4_service {
	__be32 target;
	__u16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
} __attribute__((packed));

struct lb4_reverse_nat {
	__be32 address;
	__u16 port;
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
	__u16 orig_dport;
	__u16 proxy_port;
	__be32 addr;
};

struct proxy4_tbl_key {
	__be32 saddr;
	__u16 dport; /* dport must be in front of sport, loaded with 4 bytes read */
	__u16 sport;
	__u8 nexthdr;
} __attribute__((packed));

struct proxy4_tbl_value {
	__be32 orig_daddr;
	__u16 orig_dport;
	__u16 lifetime;
} __attribute__((packed));

#endif
