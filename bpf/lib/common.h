#ifndef __LIB_COMMON_H_
#define __LIB_COMMON_H_

#include <iproute2/bpf_api.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <stdint.h>

#define __inline__ __attribute__((always_inline))

enum {
	CILIUM_MAP_LOCAL_LXC,
	__CILIUM_MAP_ID_MAX,
#define CILIUM_MAP_ID_MAX __CILIUM_MAP_ID_MAX
};

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
	__u32		sec_label;
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

#define DROP_SAMPLE_LEN 64

enum {
	CILIUM_NOTIFY_UNSPEC,
	CILIUM_NOTIFY_DROP,
	CILIUM_NOTIFY_DBG_MSG,
	CILIUM_NOTIFY_DBG_CAPTURE,
};

#define NOTIFY_COMMON_HDR \
	__u8		type; \
	__u8		subtype; \
	__u16		flags;

struct drop_notify {
	NOTIFY_COMMON_HDR
	__u32		len;
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		ifindex;
	char		data[DROP_SAMPLE_LEN];
};

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

/* Cilium error codes, must NOT overlap with TC return codes */
#define REDIRECT_TO_LXC		-128
#define SEND_TIME_EXCEEDED	-129
#define DROP_INVALID_SMAC	-130
#define DROP_INVALID_DMAC	-131
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133

enum {
	CB_SRC_LABEL,
	CB_IFINDEX,
	CB_POLICY,
};

/* Indicates an ingress CT entry */
#define TUPLE_F_OUT		0
#define TUPLE_F_IN		1

enum {
	POLICY_UNSPEC,
	POLICY_SKIP,
	POLICY_DROP,
};

struct ipv6_ct_tuple {
	union v6addr	addr;
	__u16		sport;
	__u16		dport;
	__u8		nexthdr;
	__u8		flags;
};

struct ipv6_ct_entry {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u16 lifetime;
	__u16 rx_closing:1,
	      tx_closing:1,
	      reserve:14;
};

#endif
