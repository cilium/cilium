#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"

#define CILIUM_MAP_LXC		0
#define CILIUM_MAP_POLICY	1
#define CILIUM_MAP_CALLS	2

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, CILIUM_MAP_LXC, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

/* Global map to jump into policy enforcement of receiving endpoint */
BPF_PROG_ARRAY(cilium_policy, CILIUM_MAP_POLICY, PIN_GLOBAL_NS, POLICY_MAP_SIZE);

/* Private map for internal tail calls */
BPF_PROG_ARRAY(cilium_calls, CILIUM_MAP_CALLS, PIN_OBJECT_NS, CILIUM_CALL_SIZE);

#endif
