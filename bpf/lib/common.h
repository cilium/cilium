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
	int		ifindex;
	/* 4 bytes hole */
	__u64		mac;
	union v6addr	ip;
	struct portmap  portmap[PORTMAP_MAX];
};

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define LXC_REDIRECT -2

#endif
