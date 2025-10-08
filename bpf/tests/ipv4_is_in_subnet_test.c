// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "node_config.h"
#include "lib/ipv4.h"

CHECK("tc", "ipv4_is_in_subnet_prefix0")
int ipv4_is_in_subnet_prefix0(void)
{
test_init();
	__be32 addr = bpf_htonl(0x12345678);
	__be32 subnet = 0;

	/* Any address is in 0.0.0.0/0 */
	assert(ipv4_is_in_subnet(addr, subnet, 0));

	/* Non-zero subnet with /0 should not match */
	subnet = bpf_htonl(0x01000000);
	assert(!ipv4_is_in_subnet(addr, subnet, 0));

	test_finish();
}
