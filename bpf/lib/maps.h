#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"

#define CILIUM_MAP_LXC		0
#define CILIUM_MAP_JMP		1
#define CILIUM_MAP_PROTO	2
#define CILIUM_MAP_CALLS	3

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, CILIUM_MAP_LXC, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);
BPF_PROG_ARRAY(cilium_jmp, CILIUM_MAP_JMP, PIN_GLOBAL_NS, 1024);
BPF_PROG_ARRAY(cilium_proto, CILIUM_MAP_PROTO, PIN_GLOBAL_NS, 8);
BPF_PROG_ARRAY(cilium_calls, CILIUM_MAP_CALLS, PIN_OBJECT_NS, CILIUM_CALL_SIZE);

#endif
