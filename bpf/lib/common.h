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
};

#define COMMON_HDR \
	__u8		type; \
	__u8		subtype; \
	__u16		flags; \

struct drop_notify {
	COMMON_HDR
	__u32		len;
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		dst_ifindex;
	char		data[DROP_SAMPLE_LEN];
};

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

/* Cilium error codes, must NOT overlap with TC return codes */
#define REDIRECT_TO_LXC		-257
#define SEND_TIME_EXCEEDED	-258
#define IS_CILIUM_ERROR(x) (x <= REDIRECT_TO_LXC

enum {
	CB_SRC_LABEL,
	CB_IFINDEX,
};

#endif
