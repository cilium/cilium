// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_ROUTING

#define EXPECTED_DEST_MAC ({ \
	union macaddr expected_dest_mac = NODE_MAC; \
	&expected_dest_mac.addr; \
})

#include "ipsec_from_lxc_generic.h"
