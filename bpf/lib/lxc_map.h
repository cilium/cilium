#ifndef __LIB_LXC_MAP_H_
#define __LIB_LXC_MAP_H_

#include "common.h"

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, 0, sizeof(__u16), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

#endif
