// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 Authors of Cilium

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <assert.h>
#include <stdlib.h>

#include "lib/utils.h"
#include "lib/common.h"

#include "node_config.h"

#define CONNTRACK

#define htonl bpf_htonl
#define ntohl bpf_ntohl

/* Declare before lib/conntrack.h or die! */
static __u64 __now = 0;

#define ktime_get_ns()	(__now * NSEC_PER_SEC)
#define jiffies64()	(__now)

#include "tests/conntrack_test.h"
#include "tests/builtin_test.h"
#include "tests/ipv6_test.h"

int main(int argc, char *argv[])
{
	srandom(0x61C88647);

	test_lpm_lookup();
	test_ipv6_addr_clear_suffix();

	test___ct_update_timeout();
	test___ct_lookup();

	test___builtin_memzero();
	test___builtin_memcpy();
	test___builtin_memcmp();
	test___builtin_memmove();

	return 0;
}
