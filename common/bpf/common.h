#ifndef __COMMON_H_
#define __COMMON_H_

#include <iproute2/bpf_api.h>
#include <linux/ipv6.h>
#include <stdint.h>

enum {
	CILIUM_MAP_LOCAL_LXC,
	__CILIUM_MAP_ID_MAX,
#define CILIUM_MAP_ID_MAX __CILIUM_MAP_ID_MAX
};

struct lxc_info {
	__u64		mac;
	int		ifindex;
};

#endif
